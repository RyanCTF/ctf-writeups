# dice-002 (DiceForge - Quantum Roll) - BugForge Lab Walkthrough

**URL:** https://lab-1783189252000-uka3cs.labs-app.bugforge.io/
**Difficulty:** Easy
**Vulnerability:** Paywall bypass via Googlebot User-Agent (server-side access-control flaw)
**Flag:** `bug{qlGpKlmVgmRHXc78IMZ8Aedv4aH7b5so}`

---

## Summary

DiceForge is a dice-rolling web app with a premium "Quantum Roll" feature (`/quantum` route) gated behind a subscriber paywall. The paywall check (`GET /api/subscriber-content`) grants access to any request whose `User-Agent` header matches a Googlebot crawler string, a real-world pattern some sites use to let search engines index paywalled content for SEO. The same crawler check is (mistakenly) also honored by the actual premium action endpoint (`POST /api/quantum`), so spoofing the User-Agent grants full functional access to the paid feature, not just the metadata check.

## Tech Stack

- React SPA (Create React App, MUI/Emotion), no login/auth system present
- Express.js backend, `X-Powered-By: Express`
- No cookies, sessions, or JWTs used anywhere in the app. Access state is derived per-request from headers

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|---|---|---|---|
| `/api/subscriber-content` | GET | None | Returns `{"access": true/false}`, used by the client to show/hide the paywall dialog |
| `/api/quantum` | POST | None | Actual premium dice-roll action; returns roll results plus flag when access is granted |
| `/api/roll` | POST | None | Free-tier dice roll (dice-001 territory, unrelated) |

## Attack Chain

1. Fetched the React bundle and its exposed source map (`main.<hash>.js.map`). The CRA build leaks full source.
2. Extracted `QuantumRoller.js`, which shows the paywall flow: on mount it calls `axios.get('/api/subscriber-content')`; if `access !== true` it shows a locked/blurred UI. The actual roll happens via `axios.post('/api/quantum', {dice})`.
3. Confirmed baseline: unauthenticated request returns `{"access": false}` and `/api/quantum` returns a premium-feature error message.
4. Tried the classic SEO-crawler paywall bypass: setting `User-Agent` to a Googlebot string.

```bash
curl -s "$TARGET/api/subscriber-content" \
  -H "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
# => {"access":true}
```

5. Confirmed the same header also unlocks the real action endpoint, not just the metadata check:

```bash
curl -s -X POST "$TARGET/api/quantum" \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" \
  -d '{"dice":[{"type":"d20","count":2}]}'
# => {"notation":"2d20","results":[...],"grandTotal":35,"timestamp":"...","flag":"bug{qlGpKlmVgmRHXc78IMZ8Aedv4aH7b5so}"}
```

Flag retrieved directly in the roll response.

## Discovery Notes

- Source map extraction from the bundle immediately revealed the two-endpoint paywall pattern: a cheap boolean check (`/api/subscriber-content`) plus a separate action endpoint (`/api/quantum`), a strong signal that access control might be duplicated or inconsistent between the two.
- Narrowed the search to real-world content-paywall bypass tricks: Googlebot UA, referrer spoofing (google.com, facebook.com, t.co), AMP view, print view, X-Forwarded-For. Googlebot UA was the one that worked.

## Dead Ends

| Attempt | Result | Lesson |
|---|---|---|
| `Referer: https://www.google.com/`, `facebook.com`, `t.co` | No effect, `access:false` | This app only checks User-Agent, not Referer |
| `X-Forwarded-For: 127.0.0.1` | No effect | Not an IP-allowlist bypass |
| `X-Subscription-Status: active` | No effect | No custom header trusted |
| `X-Original-URL` / `X-Rewrite-URL` override | No effect | No reverse-proxy path-based routing in play |

## Root Causes

- The backend implements a crawler allowlist (likely `req.headers['user-agent'].includes('Googlebot')` or similar) intended only to let search engines index/preview paywalled content for SEO.
- That same crawler-detection logic was reused (or fell through) to gate the actual paid feature endpoint (`/api/quantum`), not just a read-only preview/metadata endpoint.
- User-Agent is a fully client-controlled, unauthenticated string and must never be used as an access-control credential. It is not proof of identity for any principal, human or bot.

## CWE / OWASP

- CWE-290: Authentication Bypass by Spoofing (User-Agent trusted as an identity signal)
- CWE-863: Incorrect Authorization (crawler-allowlist logic incorrectly applied to a privileged action endpoint)
- OWASP A01:2021: Broken Access Control
