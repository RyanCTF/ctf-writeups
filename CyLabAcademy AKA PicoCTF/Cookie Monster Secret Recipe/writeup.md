# Cookie Monster Secret Recipe

**Platform:** CyLab Security Academy (picoCTF), picoCTF 2025
**Category:** Web Exploitation
**Difficulty:** Easy
**Flag:** `picoCTF{c00k1e_m0nster_l0ves_c00kies_2C8040EF}`

## Summary

A PHP login form rejects any submitted credentials, but the rejection response itself sets a
cookie whose value is the flag, base64 encoded. No further authentication or manipulation is
needed once the cookie is inspected.

## Discovery

Submitting any username/password pair to `login.php` returns an "Access Denied" page, but the
response headers include:

```
Set-Cookie: secret_recipe=cGljb0NURntjMDBrMWVfbTBuc3Rlcl9sMHZlc19jMDBraWVzXzJDODA0MEVGfQ%3D%3D; expires=...; Max-Age=3600; path=/
```

with the body text:

```
Cookie Monster says: 'Me no need password. Me just need cookies!'
Hint: Have you checked your cookies lately?
```

which points straight at the cookie itself as the artifact of interest rather than the login
form.

## Proof of Concept

URL-decode the cookie value, then base64-decode it:

```
echo "cGljb0NURntjMDBrMWVfbTBuc3Rlcl9sMHZlc19jMDBraWVzXzJDODA0MEVGfQ==" | base64 -d
picoCTF{c00k1e_m0nster_l0ves_c00kies_2C8040EF}
```

## Root Cause

The application places the flag value directly into a client-visible cookie with only a trivial
encoding (base64, not encryption or signing) applied. Any value sent to the client that isn't
cryptographically protected should be treated as fully readable by the client, regardless of how
it is encoded.

## CWE / OWASP

- **CWE-312**: Cleartext Storage of Sensitive Information
- **CWE-315**: Cleartext Storage of Sensitive Information in a Cookie
- **OWASP A02:2021**: Cryptographic Failures
