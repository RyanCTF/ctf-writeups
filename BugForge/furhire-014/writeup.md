# FurHire-014 - BugForge Weekly Lab Walkthrough

**Difficulty:** Medium (Weekly Challenge)
**Vulnerability:** NoSQL/type-confusion operator injection -> blind boolean data exfiltration
**Flag:** `bug{eZ01fw6wmSIV130jCN33IZtyvJeFnj60}` (instance-specific value shown, re-extract on a fresh container)

---

## Summary

FurHire is a pet-job-board app (Express.js + SQLite, server-rendered EJS, JWT-in-localStorage
auth). Its account-recovery endpoint builds its DB query directly from the request body without
type-checking, so sending a MongoDB-style operator object (`{"$ne": null}`) instead of a string
turns an equality check into a real query condition. This gives a blind boolean oracle over the
`backup_code` column. One specific seeded account has the flag string sitting in its
`backup_code` column in place of a normal recovery code - extracting that column's real value
via the oracle is the solve. No login, session, or account takeover is needed at any point.

## Tech Stack

Express.js, server-rendered EJS pages plus a thin `app.js` client helper (not a React/SPA
bundle, no source maps), JWT auth (HS256, stored in localStorage), SQLite with a custom query
builder that partially implements Mongo-style operators, Socket.io for live notifications.

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/register` | none | `role: "recruiter"` is a legitimate, honored registration option |
| `POST /api/login` | none | Crashes the whole container if `password` is a non-string JSON value - real DoS bug, not the flag path |
| `POST /api/account/recover` | none | The vulnerable endpoint - `{email, backupCode}`, both fields pass through an operator-aware query builder |
| `GET /api/jobs`, `/api/jobs/:id/apply`, `/api/jobs/:id/applicants` | mixed | Properly scoped; filters (`search`/`location`/`job_type`) are literal-only, not operator-aware |
| `PUT /api/applications/:id/status` | recruiter, owner-checked | `:id` is a path integer, ownership enforced server-side against the JWT - no injection point |
| Socket.io (`io()`, no auth) | none | Secondary bug, see below |

## Attack Chain

1. **Discover the operator-injection primitive.** `POST /api/account/recover` normally takes
   `{"email":"<addr>","backupCode":"<code>"}` and returns `{"status":"invalid",...}` for a wrong
   code. Sending an object instead of a string for `backupCode` changes behavior:
   ```bash
   curl -s -X POST "$TARGET/api/account/recover" -H "Content-Type: application/json" \
     -d '{"email":"hr@whiskersco.com","backupCode":{"$ne":null}}'
   # {"status":"verified","username":"whiskers_hr","message":"Backup code accepted. ..."}
   ```
   `$ne`, `$gt`, `$gte`, `$lt`, `$exists` are all honored (`$regex`/`$where`/`$eq` throw a
   caught, non-fatal 500). This alone leaks whether an email is enrolled plus its username, and
   is the type-confusion bug (object where a string is expected).

2. **Enumerate enrolled accounts.** `email` is passed through the same builder, so it can be an
   operator too - lets you enumerate accounts without knowing their address up front via
   lexicographic bisection (`{"email":{"$lt":"hr@pawsitive.com"},"backupCode":{"$ne":null}}`).
   In practice the enrolled set is small and guessable: the two fixed recruiter addresses
   (`hr@pawsitive.com`, `hr@whiskersco.com`) plus a handful of job-seekers at
   `<firstname>@example.com`.

3. **Blind-extract each account's real `backup_code` value.** `$gte` lets you binary-search the
   literal stored string, one character at a time:
   ```
   full_candidate = known_prefix + test_char
   verified == True  <=>  stored_value >= full_candidate   (given the prefix matches exactly)
   ```
   Bisecting over the character alphabet for each position (about 6-7 requests per character)
   recovers the exact value with no crashes and no rate limiting.

   Gotcha: do not pad `full_candidate` to a fixed length with filler characters. A naturally
   terminated real string is always lexicographically less than `known + its real last char +
   any trailing filler`, even the lowest possible filler char, because a strict prefix always
   sorts below a longer string extending it. That silently undershoots the true last character
   by exactly one position. Comparing `known + test_char` with zero padding is correct and
   simpler.

4. **Read the result as data, not as a credential.** For one specific enrolled account, the
   extracted "backup code" decodes to `bug{...}` directly - that account's `backup_code` column
   holds the flag instead of a normal recovery code. The other enrolled accounts have normal
   `XXXXXX-XXXXXX-XXXXXX` codes.

## Discovery Notes

The natural first instinct is to treat "verified" as a stepping stone to a real account
takeover (find a reset endpoint, forge a session, bypass login). That instinct is reinforced by
the endpoint's own message text ("Backup code accepted. You can now reset your password.") and
by sibling FurHire labs' history of chained takeover paths. It turns out to be a dead end here:
the endpoint never performs a reset (verified with the literal correct code, not just the
operator bypass - identical response either way, no token/cookie issued). Once the reset path is
ruled out, the recover endpoint's real value is as a data oracle in its own right: since the
operator injection lets you read any comparable value in that column, it is worth checking
whether the column holds something more interesting than a normal recovery code for any of the
enrolled accounts, which is exactly the case here.

## Dead Ends

| Attempted | Why it failed | Lesson |
|---|---|---|
| `POST /api/login` with non-string `password` | Crashes the entire container (502 then permanent 404, platform status does not self-report as down) - a generic body-sanitizer/validator calls a string method on `password` unconditionally before any auth logic runs | Real secondary DoS bug via type confusion, confirmed multiple times, account-independent. Do not use as an oracle. |
| Real extracted backup code plus a `newPassword` field (several field-name variants) on recover | Silently ignored every time - endpoint is verify-only | The "reset your password" message is flavor text, not a real second step |
| Arrays instead of operator objects on `email`/`backupCode` | Always "invalid," even for known-good values wrapped in a 1-element array | This app's query builder understands Mongo-style operators only |
| Extra body keys on recover (`role`, etc.), as literals or operators | Silently ignored - only `email`+`backupCode` are read | No parameter-pollution pivot to other columns via this endpoint |
| Exhaustive endpoint fuzzing (multiple wordlists, multiple base paths) for a password-reset/2FA/mail-catcher endpoint | Zero new endpoints found | Confirms the escalation genuinely does not exist |
| `admin@furhire.com` under many operator/literal shapes on `backupCode` | Never matches | Backup codes live in a separate table joined to `users` - admin simply has no row there |
| `alg:none` JWT forgery, weak-secret HS256 crack | Rejected / no hit | Not the intended path at all |

## Root Causes

- No type validation before query construction. `email`/`backupCode` are passed directly into a
  query-builder layer that supports Mongo-style operator objects, with no check that the client
  sent a string.
- Sensitive data (a flag/secret) stored in a field that is reachable by an unauthenticated,
  unrestricted equality/comparison oracle - even without any reset/login capability, the
  operator injection alone is a full data-exfiltration primitive.
- Secondary, unrelated bug: `/api/login`'s body handling assumes `password` is always a string
  and crashes the whole process otherwise - no input validation, no try/catch around a string
  method call.
- Secondary, unrelated bug: Socket.io has no authentication and the server broadcasts
  `new_application`/`status_update` events to every connected client; authorization is enforced
  only client-side (`if (user.id === data.recruiterId)`), so any socket connection observes
  every tenant's live notification stream.

## CWE / OWASP

- CWE-943: Improper Neutralization of Special Elements in Data Query Logic (NoSQL Injection)
- CWE-843: Type Confusion
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- OWASP API3:2023 - Broken Object Property Level Authorization (secondary: Socket.io broadcast)
- CWE-248 / unhandled exception -> Denial of Service (secondary: `/api/login` crash)
