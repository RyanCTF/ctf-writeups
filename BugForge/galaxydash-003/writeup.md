# galaxydash-003 - BugForge Lab Walkthrough

**URL:** https://lab-1786634127397-4zzoqy.labs-app.bugforge.io/
**Difficulty:** Medium (platform-untagged, no vulnerability-class hint given)
**Vulnerability:** Server-Side Request Forgery to an internal auth microservice that leaks its
RSA private key, used to forge an admin JWT and bypass authentication. The flag is delivered
through a response header rather than the response body.
**Flag:** `bug{EFu9Z9Zfj9XW6XdBI9aZ1xCChW1MdCMz}`

---

## Summary

Galaxy Dash is a multi-tenant B2B "intergalactic delivery" booking SaaS (React SPA, Express
backend, SQLite, JWT auth). A booking detail page periodically calls a server-side endpoint with
a fixed body pointing at what looks like an internal shipping-status service, purely for flavor
text. That endpoint turns out to be a real server-side URL-fetch proxy into an actual internal
microservice rather than a client-facing mock. The internal service has its own authentication
sub-router, and one of its paths returns the RSA private key this application uses to sign its
JWTs. With that key in hand, any JWT can be forged and will be accepted by the app as fully
legitimate, including one impersonating a pre-seeded organization administrator. Once
authenticated this way, every API response carries a flag in a custom response header.

## Tech Stack

- React SPA (Create React App, source maps exposed)
- Express.js (Node.js), SQLite
- JWT auth using RS256 - a genuine difference from sibling instances of this same app, which use
  HS256 - the private key for this exact algorithm is what ends up leaking
- A separate internal service reachable only through the application's own server-to-server proxy
  endpoint, never directly from the internet
- Multi-tenant: organizations, team members with role plus permissions, bookings, invoices

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| A POST endpoint accepting a `url` field | POST | JWT | Server-side URL-fetch proxy. The frontend only ever sends one hardcoded value, but the server does not restrict which path on the allowed internal host can be requested |
| Standard registration and login endpoints | POST | No | Nothing unusual |
| Organization, team, booking, and invoice endpoints | various | JWT | Ordinary multi-tenant CRUD - every response from any of these carries the flag in a response header once authenticated with a forged, key-signed token |

## Discovery

1. Standard recon (pulling the exposed source map, reading every component) turned up a booking
   detail page calling a server-side endpoint with a hardcoded body pointing at an
   internal-sounding hostname and path, used purely to render flavor text about shipment status.
2. Early testing tried roughly eighteen variants of that request: different resource-flavored
   paths, host confusion tricks, query strings, encoding games, all hunting for a classic
   allowlist bypass. Every variant except the one exact original path returned an identical
   generic "not found" style error, which at first looked like proof this was a purely
   client-side lookup table rather than a real request going anywhere.
3. The signal that had been missed: none of those first guesses tried an authentication-flavored
   path. Trying one produced a genuinely different error message than every other guess had -
   not the generic "not found," but something closer to "nothing registered at this exact spot."
   That distinction was the tell that a real sub-router existed there, just with nothing mounted
   at its own root.
4. A path one level deeper under that same prefix returned the internal service's full RSA
   private key directly in the response body.

## Proof of Concept

### Step 1 - reach the internal service through the proxy endpoint

A request through the server-side proxy pointed at the internal service's private-key path
returned the key directly:

```json
{"service":"Galaxy Dash Internal Auth Service","key_type":"private","private_key":"-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"}
```

### Step 2 - forge an RS256 JWT with the leaked key

```python
import jwt, time
priv = open('private_key.pem').read()
payload = {"id": 1, "username": "admin", "organizationId": 1, "role": "admin", "iat": int(time.time())}
token = jwt.encode(payload, priv, algorithm="RS256")
```

### Step 3 - the forged token authenticates as a real, pre-seeded organization admin

Requesting the current-user endpoint with the forged token returned a fully valid identity that
had never been registered during this session - a pre-seeded user belonging to a pre-seeded
organization. Enumerating a handful of low user IDs with the same key revealed a small roster of
pre-seeded users across three separate pre-seeded organizations, none of which had any bookings
or invoices - confirming that the flag was never stored in any booking or invoice data at all,
which had been a dead end pursued at length before this technique was found.

### Step 4 - the flag is in a response header, on any authenticated request

Every endpoint tried while authenticated with the forged token carried the same custom response
header containing the flag. The exact same requests made with a normal, legitimately registered
token did not carry that header at all, confirming the header is added specifically in response
to successful authentication with a forged, key-signed token rather than being present
unconditionally.

### Step 5 - submit

The flag was submitted through the platform and confirmed correct. The lab instance terminated
automatically immediately afterward.

## Secondary finding

While hunting for the intended bug, a separate, genuinely reproducible Broken Access Control
issue was found and is worth documenting even though it was not the flag path: the endpoint that
serves a booking's invoice has two different code paths. The very first time an invoice is
requested for a booking, it is generated fresh and correctly checks that the booking belongs to
the requester's own organization. Every later request for that same booking instead reads the
now-cached row with no ownership check at all - any authenticated user from any organization can
read any other tenant's already-viewed invoice, including its cargo description and pricing, once
the real owner has viewed it once. This was proven cleanly: an attacker account was blocked before
the victim ever viewed their own invoice, then given full access to it immediately after the
victim's first view, and this was reproduced against a completely unrelated third organization
too. It produced no flag on this particular container because booking IDs are allocated globally
and sequentially, and this session's own very first booking received the very first ID - meaning
there was no pre-existing victim booking anywhere in this container for that bug to leak.

## Dead Ends

| Attempt | Result | Lesson |
|---|---|---|
| Around eighteen variants of the internal-service request, all targeting the one already-known path or classic allowlist-bypass tricks | Every variant except the exact original path returned an identical generic error | Concluded too early that this was a client-side mock, because the one useful path was never among the guesses tried. When probing a suspected internal-service proxy, try infrastructure-flavored paths as well as resource-flavored ones, and pay close attention when exactly one guess returns a distinctly different error message than all the others - that is a strong signal something real exists there |
| Response bodies checked exhaustively across dozens of requests; response headers essentially never inspected beyond a couple of early checks | The flag was delivered exclusively through a header, never the body, on any endpoint | Always diff full response headers, not just bodies, between a baseline request and any escalated or forged one - a header-only side channel is invisible to body-only inspection |
| Cross-tenant IDOR, prototype pollution, stored XSS, server-side template injection, mass assignment, broken function-level access control, SQL injection across every parameter and field type, JWT attacks against the signature verification itself, business logic price trust | All confirmed genuinely dead or, in the invoice case, real but not the flag oracle | Standard checklist coverage was still worth doing and ruled out a large surface area cleanly, but the actual bug in this instance sat entirely outside that checklist, in a feature that looked like flavor text |

## Root Cause

- An internal authentication microservice, reachable only through the application's own
  server-to-server proxy, serves its own RSA private signing key over an endpoint with no
  authentication of its own - private key material should never be servable over any network
  interface, internal or external.
- The proxy endpoint itself places no restriction on which path of the allowed internal host can
  be requested, effectively giving any authenticated application user the same reach into the
  internal service mesh that the application server itself has.
- Because the leaked key is the application's actual signing key rather than a decoy, anyone who
  reaches it can forge arbitrary, fully valid, application-trusted tokens for any user or role -
  a complete authentication bypass, not merely an information disclosure.

## CWE / OWASP

- CWE-918: Server-Side Request Forgery
- CWE-321: Use of Hard-coded Cryptographic Key
- CWE-347: Improper Verification of Cryptographic Signature
- OWASP Top 10 2021: A10, Server-Side Request Forgery, chained into A07, Identification and
  Authentication Failures
- OWASP API Security Top 10: API7:2023, Server Side Request Forgery
