# SQL injection vulnerability allowing login bypass

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Apprentice
**Vulnerability:** SQL Injection - authentication bypass via comment injection

---

## Summary

The login form builds its authentication query by concatenating the submitted username and password directly into a SQL statement. Commenting out the password check after a known username logs in without ever knowing the real password.

---

## Discovery and Exploitation

### Step 1

Inspected the login form and inferred the likely backend query shape: `SELECT * FROM users WHERE username = 'USERNAME' AND password = 'PASSWORD'`.

### Step 2

Submitted `administrator'--` as the username with an arbitrary password.

### Step 3

The injected `--` comments out everything after it, including the `AND password = '...'` clause, so the query effectively becomes `SELECT * FROM users WHERE username = 'administrator'--' AND password = '...'` with the password check never evaluated.

### Step 4

The application logged straight into the administrator account.


---

## Proof of Concept

```
username=administrator'--+-&password=anything
```

---

## Root Cause

The authentication query is built by string concatenation rather than parameterized queries, so a comment sequence in the username field can neutralize the password check entirely.

---

## CWE

- **CWE-89: SQL Injection**
- **CWE-287: Improper Authentication**
