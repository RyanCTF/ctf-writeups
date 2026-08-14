# More Cookies

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{cO0ki3s_yum_c0ff3200}`

## Summary

The app "fixes" the previous cookie-tampering challenge by encrypting the `auth_name` cookie
with AES in CBC mode instead of storing it in plaintext. CBC provides confidentiality but no
integrity protection, so an attacker who can't read the plaintext can still predictably corrupt
it: flipping a single bit in one ciphertext block flips the corresponding bit of the *next*
block's plaintext once decrypted (while scrambling the block actually XORed, which the app
apparently doesn't otherwise validate). The privilege flag in the decrypted cookie is a single
bit, so a blind, no-key-required bit-flip recovers it.

## Discovery

A fresh visit sets a cookie:

```
Set-Cookie: auth_name=ekorbW9F...(base64, double-encoded)...=
```

Decoding it twice with base64 yields 96 raw bytes — a multiple of the AES block size (16),
consistent with CBC ciphertext. Requesting the same page repeatedly from fresh sessions produces
a *completely different* 96-byte blob every time (no repeated blocks across sessions), matching
CBC with a random IV rather than a deterministic scheme.

`POST /search` without a valid admin cookie returns:

```
Unauthenticated search.
```

confirming the app gates a real feature behind whatever privilege bit lives inside the encrypted
cookie, exactly like the plaintext `auth_name=admin` check in the earlier "Cookies" challenge —
just now unreadable and, seemingly, unmodifiable without the key.

## Proof of Concept

Since CBC has no authentication, the fix is only cosmetic: corrupting ciphertext still corrupts
plaintext in a structured, attacker-influenceable way. Rather than reverse the exact plaintext
layout, a full blind sweep — XOR every one of the 8 bits of every one of the 96 bytes, one flip
at a time, and check the server's response — finds the working flip directly:

```python
import requests, base64, concurrent.futures

s = requests.Session()
s.get(BASE + "/")
raw = bytearray(base64.b64decode(base64.b64decode(s.cookies.get('auth_name'))))

def try_flip(pos, bit):
    tampered = bytearray(raw)
    tampered[pos] ^= (1 << bit)
    ct = base64.b64encode(base64.b64encode(bytes(tampered))).decode()
    r = requests.post(BASE + "/search", cookies={"auth_name": ct})
    return pos, bit, r.status_code, r.text

# sweep all (position, bit) pairs, keep anything that isn't a crash (500) or
# the standard "Unauthenticated search." response
```

Out of all 768 single-bit flips, exactly one survives cleanly: flipping **bit 0 of byte offset
9** in the decrypted-would-be plaintext (applied to the ciphertext, one block earlier, per CBC
bit-flip mechanics) changes the server's response from the generic unauthenticated message to:

```html
<b>Flag</b>: <code>picoCTF{cO0ki3s_yum_c0ff3200}</code>
```

Every other single-bit flip either left the response unchanged (`Unauthenticated search.`,
meaning it landed in a byte outside the meaningful privilege field) or produced a 500 (crashed
padding/parsing, meaning it corrupted the wrong block entirely) — consistent with a single
low-order bit in a short numeric/boolean field (e.g. an `admin` flag encoded as `0`/`1`) being
the only thing checked.

## Root Cause

AES-CBC provides confidentiality only. Without a MAC (encrypt-then-MAC, or an AEAD mode like
AES-GCM), an attacker who cannot decrypt the cookie can still predictably manipulate its
plaintext by XOR-ing bits into the preceding ciphertext block, because CBC decryption is
`P_i = Decrypt(C_i) XOR C_{i-1}` — a chosen delta in `C_{i-1}` produces the identical delta in
`P_i`. Encrypting a privilege flag doesn't protect it if the resulting ciphertext isn't also
authenticated.

## CWE / OWASP

- **CWE-353**: Missing Support for Integrity Check (no MAC/AEAD on the encrypted cookie)
- **CWE-565**: Reliance on Cookies without Validation and Integrity Checking
- **OWASP A02:2021**: Cryptographic Failures
