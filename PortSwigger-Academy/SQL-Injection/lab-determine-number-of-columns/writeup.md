# SQL injection UNION attack, determining the number of columns returned by the query

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Practitioner
**Vulnerability:** SQL Injection - UNION attack, column count discovery

---

## Summary

Before any UNION-based extraction is possible, the injected SELECT has to return exactly as many columns as the original query. This lab is purely about discovering that count reliably.

---

## Discovery and Exploitation

### Step 1

Confirmed the category parameter was injectable.

### Step 2

Used `ORDER BY n` with an incrementing `n`: `ORDER BY 1--`, `ORDER BY 2--`, `ORDER BY 3--` all returned normally, but `ORDER BY 4--` produced a 500 error - meaning the underlying query has exactly 3 columns.

### Step 3

Confirmed with a matching UNION: `' UNION SELECT NULL,NULL,NULL--` returned successfully with an extra all-NULL row rendered alongside the real products.


---

## Proof of Concept

```
GET /filter?category=Gifts'+ORDER+BY+3--+-  (then confirm with UNION SELECT NULL,NULL,NULL--)
```

---

## Root Cause

Same unparameterized query concatenation as the rest of this lab family; this specific lab is a methodology exercise in column-count discovery rather than a distinct root cause.

---

## CWE

- **CWE-89: SQL Injection**
