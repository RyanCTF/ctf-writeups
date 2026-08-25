# SQL injection attack, querying the database type and version on Oracle

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Practitioner
**Vulnerability:** SQL Injection - UNION-based database fingerprinting (Oracle)

---

## Summary

Same category-filter injection point as the basic WHERE-clause lab, but this time used to run a UNION SELECT that pulls the database's own version banner out of Oracle's system view, confirming the backend engine and giving a template for further UNION-based extraction.

---

## Discovery and Exploitation

### Step 1

Confirmed the category parameter was injectable via the same single-quote test as the basic lab.

### Step 2

Oracle requires every SELECT to reference a table (no bare `SELECT 1`), so the UNION had to target a real Oracle-specific view. `v$version` exposes the engine's version banner across several rows.

### Step 3

Because the surrounding query already returns a row set with two displayable columns, the UNION only needed to match that column count: `UNION SELECT BANNER, NULL FROM v$version--`.

### Step 4

The response rendered the Oracle version banner text mixed in with the normal product listing, confirming both the injection and the backend engine.


---

## Proof of Concept

```
GET /filter?category=Gifts'+UNION+SELECT+BANNER,NULL+FROM+v$version--+-
```

---

## Root Cause

Same unparameterized string concatenation as the basic WHERE-clause lab; the UNION technique itself just demonstrates how far that single flaw can be pushed once you know the column count and target engine.

---

## CWE

- **CWE-89: SQL Injection**
