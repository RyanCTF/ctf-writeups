# SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Apprentice
**Vulnerability:** SQL Injection - boolean bypass in a WHERE clause

---

## Summary

An e-commerce product listing filters items by category using a raw, unparameterized SQL query. The category value is concatenated directly into the query's WHERE clause, so a single quote breaks out of the string literal and lets an attacker rewrite the query's logic entirely.

---

## Discovery and Exploitation

### Step 1

Browsed the product catalog and noted the category filter used a query parameter: `/filter?category=Gifts`.

### Step 2

Submitted a single quote (`category=Gifts'`) and got a 500 error, confirming the value is concatenated directly into a SQL query rather than parameterized.

### Step 3

Reconstructed the likely underlying query as `SELECT * FROM products WHERE category = 'CATEGORY' AND released = 1` (the `released` flag hides unpublished items from the storefront).

### Step 4

Closed the string early and appended a tautology, commenting out the rest of the clause: `' OR 1=1-- -`. The trailing `-` after `--` is just a throwaway character some DB engines require after the comment marker so the query doesn't end with a dangling space.

### Step 5

The response returned every product in the catalog, including ones normally hidden by the `released = 1` filter, confirming the injection.


---

## Proof of Concept

```
GET /filter?category=Gifts'+OR+1=1--+-
```

---

## Root Cause

User input is concatenated directly into a SQL query string instead of being passed as a bound parameter, so any single quote in the input breaks out of the intended string literal and lets an attacker inject arbitrary SQL logic.

---

## CWE

- **CWE-89: SQL Injection**
