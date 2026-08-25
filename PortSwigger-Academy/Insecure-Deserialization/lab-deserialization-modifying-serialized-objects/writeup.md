# Modifying serialized objects

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Apprentice
**Vulnerability:** Insecure Deserialization - unsigned PHP object in a session cookie

---

## Summary

The session cookie is a base64-encoded, unencrypted PHP-serialized object rather than an opaque token. Decoding it exposes the object's fields directly, including an admin boolean, which can be edited and re-encoded to grant administrator access.

---

## Discovery and Exploitation

### Step 1

Logged in with a low-privilege account and captured the session cookie.

### Step 2

URL-decoded then base64-decoded the cookie value, revealing a PHP serialized object: `O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}`.

### Step 3

Flipped the `admin` field from `b:0` (false) to `b:1` (true) - a same-length edit, so no other length prefixes in the object needed adjusting.

### Step 4

Re-serialized, base64-encoded, and URL-encoded the modified object, then sent it as the session cookie on a request to the admin panel - access was granted.

### Step 5

Used the now-accessible admin panel to delete another user's account, confirming full administrative control.


---

## Proof of Concept

```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}
```

---

## Root Cause

The application stores an unencrypted, unsigned serialized PHP object directly in the session cookie and trusts its contents on deserialization, allowing any client to edit authorization-relevant fields at will.

---

## CWE

- **CWE-502: Deserialization of Untrusted Data**
- **CWE-863: Incorrect Authorization**
