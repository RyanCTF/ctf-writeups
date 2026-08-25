# SQL injection UNION attack, finding a column containing text

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Practitioner
**Vulnerability:** SQL Injection - UNION attack, text-column discovery

---

## Summary

Not every column in a vulnerable query is a string type. This lab required discovering the exact column count and then testing each position individually to find one that would accept a string literal without erroring.

---

## Discovery and Exploitation

### Step 1

Determined the query has 3 columns via the `ORDER BY` technique.

### Step 2

Tried `UNION SELECT 'x','x','x'--` first - this errored, meaning at least one column is a non-string type incompatible with a string literal.

### Step 3

Tested each position individually with the others left `NULL`: `UNION SELECT 'x',NULL,NULL--` errored, `UNION SELECT NULL,'x',NULL--` succeeded and displayed the injected `x` string in the page.

### Step 4

Column 2 confirmed as the text-accepting column for later data extraction.


---

## Proof of Concept

```
GET /filter?category=Gifts'+UNION+SELECT+NULL,'x',NULL--+-
```

---

## Root Cause

Same root cause as the rest of the family; the lab demonstrates that UNION-based extraction requires matching not just column count but column type per position.

---

## CWE

- **CWE-89: SQL Injection**
