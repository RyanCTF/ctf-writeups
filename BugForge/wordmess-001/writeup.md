# wordmess-001 - BugForge Lab Walkthrough

**Difficulty:** Medium (Weekly)
**Vulnerability:** Broken Function-Level Authorization via REST batch-endpoint array desync
**Flag:** `bug{qr4zC01k3IivT398Q1Dkp94zHaJYcSE0}`

---

## Summary

WordMess is a WordPress-flavored REST API app exposing `/wp-json/wp/v2/*` routes plus a
`/wp-json/batch/v1` batch endpoint that lets a client submit several sub-requests in one call.
The batch handler tracks per-item state (which route/handler each sub-request resolves to, and
whether its permission check passed) across parallel data structures keyed by list position. A
deliberately malformed sub-request desyncs that per-item state by one slot for everything after
it in the list, so a later item ends up executing under a different item's resolved route while
its own permission check (still correctly aligned) is what actually gets evaluated. Pairing a
low-privilege item's passing check with a high-privilege item's execution gives full,
unauthenticated access to admin-only endpoints.

---

## Tech Stack

- Express.js (Node.js), custom REST handler mimicking WordPress core's `/wp/v2/*` and
  `/batch/v1` conventions
- A proof-of-work based bot-detection gate in front of the whole app (scriptable, no browser
  required)
- No SQL database - in-memory/JSON-backed data only

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/wp-json/batch/v1` | POST | No | The vulnerable batch dispatcher |
| `/wp/v2/comments` | GET/POST | No | Genuinely public even without the bug |
| `/wp/v2/plugins` | GET/POST | Admin only (bypassed) | `{"slug", "status"}` body - flag on activation |
| `/wp/v2/settings` | GET | Admin only (bypassed) | Readable via the same technique |
| `/wp/v2/users` | GET | Admin only (bypassed) | Readable via the same technique |
| `/wp/v2/users` | POST | N/A | No route handler exists at all, even via the bypass |

---

## Discovery

Testing the batch endpoint with a mix of a deliberately malformed sub-request path and several
distinct, genuinely public routes showed clear cross-route response misdirection: one item's
response would come back containing a different item's data, confirmed by diffing full response
bodies rather than just status codes. That much was straightforward.

The harder part was that placing an admin-gated route as the batch's last real item always
produced a clean, consistent 403 regardless of that item's own path - a distinct internal
"out of bounds" behavior that looks exactly like proper authorization enforcement from the
outside. Only after adding one more public item after the target, so the target was no longer
the last item in the list, did the actual bypass appear.

---

## Proof of Concept

Fully unauthenticated - no account, no session cookie, no auth header of any kind:

```
POST /wp-json/batch/v1
Content-Type: application/json

{
  "requests": [
    {"method": "POST", "path": "///"},
    {"method": "POST", "path": "/wp/v2/plugins",
     "body": {"slug": "wm-smilies/wm-smilies.php", "status": "active"}},
    {"method": "GET", "path": "/wp/v2/pages"}
  ]
}
```

The middle response comes back as:

```json
{
  "plugin": "wm-smilies/wm-smilies.php",
  "installed": true,
  "status": "active",
  "hook": "",
  "flag": "bug{qr4zC01k3IivT398Q1Dkp94zHaJYcSE0}"
}
```

Either of the app's two seeded inactive plugins works identically for activation.

---

## Dead Ends

- Mass assignment on comment creation (status, comment_approved, role, meta fields, spoofed
  author fields) - comment status is always forced server-side regardless of request body.
- Creating a new user via the batch bypass - the route simply does not exist (404), not merely
  permission-blocked.
- Techniques that rely on smuggling a nested batch inside a sub-request body, or smuggling query
  parameters between an item route and a collection route - both are silent no-ops here; this
  app's own array-position desync is the mechanism that matters, not those specific tricks.
- No SQL injection surface exists anywhere in this app - there is no database to inject into.

---

## Root Cause

The batch handler's per-item bookkeeping (resolved handler, permission-check result) is built
across structures that fall out of index alignment once a malformed sub-request is present,
because the error branch for a bad sub-request does not keep every tracking structure's length
in sync with the request list. A later item is then dispatched using a different item's resolved
handler while its own permission-check result, still correctly aligned, is what gets enforced -
pairing a passing check with the wrong action. Items that fall past the end of the desynced
array are unconditionally denied regardless of their own path, which can make the endpoint look
fully secured if the target item is left as the batch's last element.

## CWE / OWASP

- CWE-841: Improper Enforcement of Behavioral Workflow
- CWE-863: Incorrect Authorization
- OWASP API1:2023 - Broken Object Level Authorization (function-level variant)
