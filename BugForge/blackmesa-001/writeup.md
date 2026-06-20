# blackmesa-001 - BugForge

**Difficulty:** Hard
**Vulnerability:** SQL Injection (string concatenation) → credential leak → OTP bypass → flag
**Flag:** `bug{4M3WCdfAku2R2xk0sykglhPHcyg9L01V}`

---

## Summary

MesaNet Access Panel is a multi-user application with an OTP-gated developer console. A SQL injection in the Rail subsystem's message field (accessed via a gateway proxy) allows extraction of database credentials from the Rail config table. Those credentials unlock a database admin interface, which exposes a backup endpoint containing the OTP needed to access the developer console and retrieve the flag.

---

## App Structure

| Endpoint | Notes |
|----------|-------|
| `POST /login` | Form-based login (x-www-form-urlencoded) |
| `GET /` | Dashboard - logged in as `operator` (L3 clearance) |
| `GET /apps/nexus` | Document store - some entries locked at L3 |
| `GET /apps/mail` | Mail inbox |
| `GET /dev` | Developer console - OTP-gated (6-digit, 60s rotation) |
| `GET /dev/time-remaining` | OTP timer |
| `POST /gateway` | Proxy to internal subsystems: `{id, endpoint, data}` |
| `GET /health` | Status check |

Initial login with provided credentials gives access as `operator`. The `/dev` console requires a 6-digit OTP that rotates every 60 seconds. Brute force is not viable with limited attempts.

---

## Recon

**Directory fuzzing** surfaces two endpoints not linked from the UI:

```
/db        - database admin login
/db/backup - database backup download (requires auth)
```

**Gateway proxy** - the `POST /gateway` endpoint forwards requests to internal subsystems. The Rail subsystem (database/admin layer) is reachable via a nil UUID:

```json
{
  "id": "00000000-0000-0000-0000-000000000000",
  "endpoint": "/api/rail/create",
  "data": { ... }
}
```

---

## Exploitation - SQL Injection in Rail `message` Field

The `/api/rail/create` endpoint accepts a `message` field that is concatenated directly into a SQL query. String injection using the `||` concatenation operator (SQLite/PostgreSQL syntax) allows extracting data from the database:

```json
{
  "id": "00000000-0000-0000-0000-000000000000",
  "endpoint": "/api/rail/create",
  "data": {
    "message": "x' || (SELECT config_value FROM rail_config WHERE config_key='db_password') || '"
  }
}
```

Enumerate the `rail_config` table to extract database credentials. The response echoes the injected value back in an error or confirmation message, making this an error-based or in-band injection.

Extract both the username and password:

```json
"message": "x' || (SELECT config_value FROM rail_config WHERE config_key='db_user') || '"
"message": "x' || (SELECT config_value FROM rail_config WHERE config_key='db_password') || '"
```

---

## Database Admin Console

Use the extracted credentials to authenticate at `/db/login`. Once logged in, navigate to `/db/backup` and download the `portalDb` backup.

Open the backup and search for OTP-related configuration. The current OTP (or the seed/algorithm needed to derive it) is stored in the backup data.

---

## Flag

Submit the OTP at `GET /dev/verify` (or `POST /dev` with the OTP value). The developer console unlocks and returns the flag:

```
bug{4M3WCdfAku2R2xk0sykglhPHcyg9L01V}
```

---

## Key Takeaways

- String concatenation injection (`||` operator) is functionally equivalent to classic SQL injection but is worth testing separately since some WAFs only pattern-match on `UNION` and `--` style payloads
- Internal subsystems reachable through a proxy/gateway endpoint often have weaker input validation than the public-facing API - the gateway itself may be validated but the backend service trusts anything arriving from it
- When brute force is blocked by attempt limits, look for the secret in the application's own data stores - OTPs seeded from a config table or backup file are a common CTF pattern that also appears in real-world misconfigured applications
- Directory fuzzing should always include admin and database paths (`/db`, `/admin`, `/console`, `/backup`) not just common wordlists
