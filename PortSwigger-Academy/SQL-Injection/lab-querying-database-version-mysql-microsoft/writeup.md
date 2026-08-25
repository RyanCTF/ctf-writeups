# SQL injection attack, querying the database type and version on MySQL and Microsoft

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Practitioner
**Vulnerability:** SQL Injection - UNION-based database fingerprinting (MySQL/MSSQL)

---

## Summary

Same injectable category filter, this time fingerprinted for MySQL/MSSQL specifically using the `@@version` global variable, which (unlike Oracle) both engines expose without needing a FROM clause.

---

## Discovery and Exploitation

### Step 1

Confirmed injectability with a single quote as usual.

### Step 2

MySQL and MSSQL both expose the engine version through the `@@version` global variable and, unlike Oracle, allow a bare `SELECT` with no `FROM` clause.

### Step 3

Submitted `' UNION SELECT @@version,NULL--` matching the existing 2-column result set.

### Step 4

The response reflected the exact version string (e.g. an Ubuntu-packaged MySQL 8.x build), confirming the engine and injection.


---

## Proof of Concept

```
GET /filter?category=Gifts'+UNION+SELECT+@@version,NULL--+-
```

---

## Root Cause

Same root cause as the other SQLi labs in this app: raw string concatenation into the query with no parameterization.

---

## CWE

- **CWE-89: SQL Injection**
