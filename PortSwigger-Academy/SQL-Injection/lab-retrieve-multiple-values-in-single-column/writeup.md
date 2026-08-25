# SQL injection UNION attack, retrieving multiple values in a single column

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Practitioner
**Vulnerability:** SQL Injection - UNION attack with only one text-compatible column

---

## Summary

This variant only has ONE column that accepts text (the other is a non-string type), so extracting both a username and a password required concatenating them together into that single column rather than spreading them across two.

---

## Discovery and Exploitation

### Step 1

Confirmed 2 columns via `ORDER BY`.

### Step 2

Tested each column position individually with a literal string; only column 2 accepted text (column 1 errored on any string value, confirming it's a non-text type).

### Step 3

Since only one column could carry data, concatenated username and password together with a separator using the DB's string concatenation operator: `username||'~'||password`.

### Step 4

Ran `' UNION SELECT NULL, username||'~'||password FROM users--` and the results listed every account as a single `username~password` string, including the administrator's, which was then used to log in.


---

## Proof of Concept

```
GET /filter?category=Gifts'+UNION+SELECT+NULL,username||'~'||password+FROM+users--+-
```

---

## Root Cause

Same underlying injection, demonstrating that a single vulnerable text column is still sufficient to exfiltrate arbitrarily many fields via string concatenation.

---

## CWE

- **CWE-89: SQL Injection**
- **CWE-522: Insufficiently Protected Credentials**
