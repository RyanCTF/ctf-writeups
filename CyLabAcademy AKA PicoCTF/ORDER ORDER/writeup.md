# ORDER ORDER

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Hard
**Flag:** `picoCTF{s3c0nd_0rd3r_1t_1s_4611c226}`

## Summary

An expense-tracker app uses parameterized queries everywhere a user directly supplies data to a
form field checked against the database — login, signup, adding expenses all resist injection.
But the asynchronous CSV report feature rebuilds a query using the **stored** `username` value
read back out of the database, string-concatenated with no escaping. Because that value was
originally accepted (and stored) unsanitized at signup, a malicious username becomes a live SQL
injection the moment a report is generated — a classic second-order injection.

## Discovery

Registering and adding expenses works entirely through safe, parameterized calls: quotes and SQL
keywords in the login form and the expense form (`description`, `amount`, `date`) produce no
observable effect. Guessed sort/pagination parameters (`sort`, `order_by`, `page`, etc.) on
`/expenses` also went nowhere — the pagination `page` value is validated/defaulted safely.

The actual seam is the **"Generate Report"** button on `/expenses`, which POSTs to
`/generate_report`, queues an async job ("Check your inbox after 10 seconds!!!"), and later drops
a CSV into `/inbox`, downloadable via `/download_report/<id>`. The report's own filename echoes
the username completely unescaped:

```
./reports/report_sqltest' UNION SELECT 1,2,3--_1786834245.csv
```

That's a strong signal the report-generation code re-reads the username from the database and
concatenates it directly into a query, rather than using the same parameterized pattern as the
rest of the app.

## Proof of Concept

Register a new account whose **username** is the injection payload (signup itself doesn't need
to be injectable — it just needs to accept the string and store it verbatim):

```
username: sqltest' UNION SELECT 1,2,3--
```

Log in as that user, click **Generate Report**, wait ~10 seconds, then download the resulting
report from `/inbox`:

```
description,amount,date
1,2,3
```

The `1,2,3` row confirms the report query is exactly:

```sql
SELECT description, amount, date FROM expenses WHERE username = '<stored username>'
```

with the stored username spliced in raw, letting `UNION SELECT` return arbitrary rows into the
CSV. Enumerating the schema via `sqlite_master`:

```
username: sqltest' UNION SELECT name, type, sql FROM sqlite_master--
```

revealed the normal `users`/`expenses`/`inbox`/`reports` tables plus one oddly-named table,
`aDNyM19uMF9mMTRn` — a base64 string (`base64.b64decode` → `h3r3_n0_f14g`, a taunt) with schema
`(name TEXT PRIMARY KEY, value TEXT NOT NULL)`. Reading it directly:

```
username: sqltest' UNION SELECT name, value, '2026-01-01' FROM aDNyM19uMF9mMTRn--
```

```
description,amount,date
flag,picoCTF{s3c0nd_0rd3r_1t_1s_4611c226},2026-01-01
```

Each payload requires a fresh signup (usernames are unique and immutable post-registration), so
every query is its own throwaway account: signup → login → generate report → wait → download.

## Root Cause

Second-order SQL injection: input validation/parameterization was applied at the point of
**entry** (the signup form) but not at the point of **use** (the report-generation query that
re-reads the stored username later). Any value that survives storage unmodified is exactly as
dangerous at the point it's reused in a raw query as it would have been if concatenated directly
at intake — sanitizing "everywhere data comes in" isn't the same as sanitizing everywhere data
is used in a query.

## CWE / OWASP

- **CWE-89**: SQL Injection (second-order)
- **CWE-020**: Improper Input Validation (validated at intake, not at use)
- **OWASP A03:2021**: Injection
