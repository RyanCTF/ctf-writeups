# Modifying serialized data types

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Practitioner
**Vulnerability:** Insecure Deserialization - PHP loose-comparison (type juggling) bypass

---

## Summary

Same unsigned PHP-serialized session cookie as the basic lab, but this object's access_token field is a random string checked against a server-side stored value rather than a simple boolean. Changing the field's type to a PHP boolean exploits a loose-comparison quirk: any non-empty string compared against boolean true evaluates as equal in PHP.

---

## Discovery and Exploitation

### Step 1

Decoded the session cookie and found an `access_token` field holding a random 32-character string rather than an obvious boolean.

### Step 2

A first attempt setting the field's type to boolean false (`b:0;`) produced a verbose 500 error that leaked the server-side check's shape: the code compares `$user->access_token` against a stored per-user token in an `$access_tokens` array and throws when they do not match.

### Step 3

Reasoned that PHP's loose `==` comparison treats boolean `true` as equal to any non-empty, non-"0" string. Changed the field's type to boolean true instead: `s:12:"access_token";b:1;`.

### Step 4

Sent the modified cookie to the admin panel - it was accepted, since the stored token string compared loosely equal to `true` regardless of its actual value.

### Step 5

Used the now-accessible admin panel to delete another user's account, confirming the bypass.


---

## Proof of Concept

```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";b:1;}
```

---

## Root Cause

The server compares the deserialized access_token value against a stored token using PHP's loose equality operator, which considers any truthy value equal to boolean true - an attacker who can control the serialized object's field types can bypass the check entirely without ever knowing the real token.

---

## CWE

- **CWE-502: Deserialization of Untrusted Data**
- **CWE-697: Incorrect Comparison**
