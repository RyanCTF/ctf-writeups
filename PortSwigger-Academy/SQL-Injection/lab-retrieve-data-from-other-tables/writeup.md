# SQL injection UNION attack, retrieving data from other tables

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Practitioner
**Vulnerability:** SQL Injection - UNION attack, cross-table data extraction leading to account takeover

---

## Summary

With the column count and text-accepting column already known, the same UNION injection point was used to pull the entire `users` table (usernames and passwords) out through the product listing, then used to log in as the administrator.

---

## Discovery and Exploitation

### Step 1

Confirmed the query takes 2 columns via `ORDER BY`.

### Step 2

Guessed a standard table/column naming scheme (`users` table with `username`/`password` columns) and queried it directly: `' UNION SELECT username,password FROM users--`.

### Step 3

The response listed every account's username and password in plaintext, rendered as extra product rows.

### Step 4

Located the `administrator` row and its password, then logged in normally with those credentials to fully take over the admin account.


---

## Proof of Concept

```
GET /filter?category=Gifts'+UNION+SELECT+username,password+FROM+users--+-
```

---

## Root Cause

Unparameterized query concatenation lets an attacker UNION in a completely different table, and the application has no separation between what a product-filter query should be able to read versus the full database.

---

## CWE

- **CWE-89: SQL Injection**
- **CWE-522: Insufficiently Protected Credentials**
