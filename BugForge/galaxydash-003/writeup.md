# galaxydash-003 - BugForge Lab Walkthrough

**URL:** https://lab-1786634127397-4zzoqy.labs-app.bugforge.io/
**Difficulty:** Medium (platform-untagged, no vulnerability-class hint given)
**Vulnerability:** Broken Access Control / IDOR - an endpoint's cached-read code path is missing
the ownership check present on its own first-generation code path
**Flag:** not recovered - see "Flag Status" below. The vulnerability itself is confirmed, live,
and reproduced against two independent victim organizations.

---

## Flag Status

This instance was untagged, so a full attack-surface sweep was required rather than a narrowed
hunt. One fully reproducible, cross-tenant Broken Access Control bug was found and confirmed
(write-up below), but no `bug{...}` flag ever appeared in any response through any oracle tested.
The root blocker: booking IDs in this app are globally sequential across the whole container, and
this session's own very first booking got `id: 1` - meaning the bookings/invoices tables were
completely empty at container boot. The bug needs a victim who has already viewed their own
invoice once; with no pre-existing victim data in this container, there was nothing left over to
read. A side-channel (the registration endpoint's duplicate-username error) confirmed a seeded
account called `walt` exists in this container, matching a hint used on a different instance of
this same lab family, but no path from that username to actual reachable data was found.

The finding is submitted here without a flag, in the same spirit as prior sessions in this lab
family that confirmed a real, severe vulnerability but could not locate a flag-delivery mechanism
for that specific container.

## Summary

Galaxy Dash is a multi-tenant B2B "intergalactic delivery" booking SaaS (React SPA, Express
backend, SQLite, JWT auth). Organizations create bookings and can view a generated invoice for
each one. `GET /api/invoices/:bookingId` has two different code paths: the first-ever fetch for a
booking generates the invoice from scratch, joins in the booking and organization data, and
correctly checks that the booking belongs to the caller's organization. Every later fetch for the
same booking instead reads the now-cached row straight from the invoices table with no ownership
check at all. Any authenticated user on the platform, from any organization, can read any other
tenant's already-viewed invoice by iterating small sequential booking IDs.

## Tech Stack

- React SPA (Create React App, source maps exposed)
- Express.js (Node.js), SQLite
- JWT auth, RS256 (a difference from sibling instances of this app, which use HS256), payload
  `{id, username, organizationId, role, iat}`
- Multi-tenant: organizations, team members with role plus 5 boolean permissions, bookings,
  invoices stored as their own table (confirmed via a `generated_at` timestamp and a
  `GET /api/invoices` list endpoint that returns cached rows, not on-the-fly data)

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Accepts a wider set of profile fields than `PUT /api/organization` does, but no sensitive-field mass assignment succeeds |
| `/api/bookings` | GET/POST | JWT | Correctly scoped to the caller's organization |
| `/api/bookings/:id` | GET/PUT/DELETE | JWT | GET and DELETE are real and correctly scoped; PUT returns success but never actually persists any field |
| `/api/invoices` | GET | JWT | Lists the caller's own cached invoices, correctly scoped |
| `/api/invoices/:bookingId` | GET | JWT | Vulnerable. First generation checks ownership; every later read of the same ID does not |
| `/api/team`, `/api/team/:id` | GET/POST/PUT/DELETE | JWT | Correctly scoped in every method and role tested |
| `/api/organization` | GET/PUT | JWT | Always resolves to the caller's own organization from the JWT, no ID parameter exists |

## Discovery

1. Standard source-map audit found no client-side-only enforcement gaps.
2. Because the instance was untagged, worked through the full standard vulnerability checklist:
   SSRF, SQL injection, prototype pollution, mass assignment, broken function-level access
   control, stored XSS, server-side template injection, and JWT attacks were all tried and ruled
   out with concrete negative evidence.
3. While probing every ID-bearing endpoint for cross-tenant access using two independent test
   accounts, noticed `GET /api/invoices/:id` returns two different JSON shapes depending on
   whether the invoice for that booking had already been generated once. A first-time fetch
   returns a rich object (`organization`, `booking_details`, an array of `line_items`, `status`).
   A later fetch of the same booking ID returns a much flatter shape that looks like a raw
   database row (`id`, `booking_id`, `invoice_number`, `line_items` as a JSON-encoded string,
   `subtotal`, `tax`, `total`, `generated_at`). Two distinct response shapes for the same URL
   strongly suggested two separate code paths, so each was tested for authorization independently.

## Proof of Concept

Two independent organizations were used: account 1 (the victim, organization 4) and account 2
(the attacker, organization 5). A third organization was used later purely to confirm the bug
generalizes to any two unrelated tenants, not just the two accounts used for discovery.

### Step 1 - victim creates a booking with sensitive cargo information

```
POST /api/bookings HTTP/1.1
Authorization: Bearer <victim token>
Content-Type: application/json

{"origin_location_id":4,"destination_location_id":12,"cargo_size":"medium",
 "cargo_weight_kg":50,"cargo_description":"CONFIDENTIAL-CARGO-PoC","service_id":3,
 "total_price":77,"calculated_risk_percent":5,"estimated_delivery_minutes":30}
```

Response: `{"id":10,"message":"Booking created successfully",...}`

### Step 2 - attacker probes before the victim has viewed their own invoice

```
GET /api/invoices/10 HTTP/1.1
Authorization: Bearer <attacker token>
```

Response: `404 {"error":"Booking not found"}` - ownership is correctly enforced on the
first-generation path.

### Step 3 - victim (the real owner) views their invoice once

```
GET /api/invoices/10 HTTP/1.1
Authorization: Bearer <victim token>
```

Response: `200`, a full detailed invoice is generated and cached to the invoices table.

### Step 4 - attacker repeats the exact same request

```
GET /api/invoices/10 HTTP/1.1
Authorization: Bearer <attacker token>
```

Response:

```json
{"id":5,"booking_id":10,"invoice_number":"GD-2026-000010",
 "line_items":"[{\"description\":\"Standard Route: Atlanta Depot (Earth) to Amphibios 9 Swamp District (Amphibios 9)\",\"quantity\":1,\"unit_price\":77,\"total\":77},{\"description\":\"Cargo: medium (50kg) - CONFIDENTIAL-CARGO-PoC\",\"quantity\":1,\"unit_price\":0,\"total\":0}]",
 "subtotal":77,"tax":6.16,"total":83.16,"generated_at":"2026-08-13 15:42:11"}
```

`HTTP 200`. A completely unrelated organization now has full read access to the victim's invoice,
including the confidential cargo description, with zero ownership check performed. This response
was diffed byte-for-byte against the real owner's own repeat fetch of the same resource and was
identical, ruling out any conditional flag field being inserted for unauthorized requesters.

### Step 5 - confirmed against a genuine, unrelated third party

Using a third test organization with no relationship to either account above, the attacker
account was able to read that third organization's already-cached invoice using the same request
shape, proving this is a platform-wide authorization gap rather than something specific to the
two accounts used for discovery.

## Dead Ends

| Attempt | Result | Lesson |
|---|---|---|
| SSRF via the one URL-accepting feature in the app (a mocked "internal shipping tracker" endpoint), 18 bypass variants tried | Every deviation from one exact literal string fails identically with the same error | Not a real outbound fetch, an exact-match lookup table simulating an internal service for flavor text |
| Prototype pollution on the team-permission-update endpoint, the exact mechanism that solved a sibling instance of this app | Server explicitly coerces the field to a boolean, no merge vulnerability reachable | This build validates permission field types where a sibling instance did not |
| Stored XSS via a booking field known to be vulnerable in a sibling instance | Field accepts the payload raw server side, but is never rendered through an unsafe HTML sink anywhere in this build's frontend | The vulnerable sink from the sibling instance simply is not present here |
| Server-side template injection on organization and cargo fields, the mechanism that solved another sibling instance | Template syntax always reflected back completely literally | No template engine processes these fields in this build |
| JWT algorithm-confusion attacks (signature tampering, alg:none, RS256-to-HS256 confusion against common secrets, JWK header injection with a self-generated key, kid/jku manipulation) | All cleanly rejected | Solid, explicit-algorithm, explicit-key verification; no public key exposed anywhere to attempt a real-key confusion attack |
| Sweeping booking IDs 1 through 300 (twice) looking for a pre-existing victim invoice | Only self-generated invoices ever found | Bookings and invoices tables were empty at container boot; there is no natural victim for this exact bug in this container |
| Business logic price and risk trust on booking creation, and a service/location restriction bypass, both real and matching a sibling instance's confirmed finding | No distinguishable flag appeared in any response field checked | Confirmed real but not the flag oracle, matching that sibling instance's own conclusion |
| A deliberate race condition test, ten concurrent requests split across both accounts against a never-before-viewed booking | Clean split - blocked until the first successful generation, open immediately after | Not a timing bug, a straightforward missing authorization check |

## Root Cause

- `GET /api/invoices/:bookingId` has two independent implementations of "return this invoice":
  one for the first time it is requested, one for every time after that. The ownership check was
  only added to the first (presumably written earlier, or written more carefully because it also
  has to generate the object), and never carried over to the second (presumably written later, as
  a caching shortcut for performance).
- The cached-read path performs a raw, unfiltered lookup by booking ID against the invoices
  table, with no join back to the owning organization and no comparison against the caller's own
  organization at any point.
- The bug is invisible to casual testing because both code paths return `200` with a
  plausible-looking invoice - it only becomes visible when a second tenant is used to probe the
  exact same resource ID before and after the real owner has viewed it once.

## CWE / OWASP

- CWE-862: Missing Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key
- OWASP Top 10 2021: A01, Broken Access Control
- OWASP API Security Top 10: API1:2023, Broken Object Level Authorization
