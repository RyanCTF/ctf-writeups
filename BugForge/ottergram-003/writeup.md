# ottergram-003 - BugForge Lab Walkthrough

**URL:** https://lab-1782173211817-m2jwo2.labs-app.bugforge.io/
**Difficulty:** Easy  
**Vulnerability:** Path Traversal / Local File Inclusion (LFI)
**Flag:** `bug{HOXg0L3oKMzzpS1hEA34BNUlOsePwxyO}`

---

## Summary

Ottergram is a React-based Instagram-like app. The backend serves post images via `/api/post/image?file=<path>`, where the `file` parameter is passed unsanitised to a file-read operation on disk. No path traversal prevention exists, allowing an attacker to read arbitrary server files including `/app/flag.txt`.

## Tech Stack

- Frontend: React (CRA), React Router, Axios
- Backend: Node.js / Express (x-powered-by: Express)
- Auth: JWT (Bearer token)
- Roles: user, admin, subscriber

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `GET /api/post/image?file=<path>` | None | Vulnerable - no path sanitisation |
| `GET /api/posts` | Yes | Returns posts with `image_url` field |
| `GET /api/admin` | Admin only | Admin panel access check |

## Attack Chain

1. **Source map discovery** - React app exposes `/static/js/main.e6d131e0.js.map`. Extracted all 93 source files.

2. **Sink identified in PostView.js** - source audit reveals:
   ```jsx
   src={`/api/post/image?file=${post.image_url}`}
   ```
   The `file` query parameter is passed directly to the image-serving endpoint.

3. **LFI confirmed** - unauthenticated request with path traversal:
   ```
   GET /api/post/image?file=../../../../../etc/passwd
   → "flag is somewhere else."
   ```
   Response confirms file read is working (server reads `/etc/passwd`, returns custom message).

4. **Flag retrieved** - probe `/app/flag.txt` (standard BugForge container path):
   ```
   GET /api/post/image?file=../../../../../app/flag.txt
   → bug{HOXg0L3oKMzzpS1hEA34BNUlOsePwxyO}
   ```

## Discovery Notes

Phase 2 source audit was the decisive step. The source map was exposed at `main.e6d131e0.js.map`. Grepping extracted files for `file` immediately surfaced the sink in `PostView.js`. The endpoint requires no authentication.

## Dead Ends

| What | Why failed | Lesson |
|---|---|---|
| `/etc/passwd` | Returns "flag is somewhere else." not actual file content | Server reads file but returns custom message when it recognises known system files |
| `/.env`, `/app/.env` | 404 | App doesn't use dotenv at root |

## Root Causes

- No sanitisation of the `file` query parameter before passing to `fs.readFile` or equivalent
- No path normalisation (e.g. `path.resolve` + prefix check) to restrict reads to the uploads directory
- Endpoint is unauthenticated - any visitor can trigger it
- Sensitive file (`/app/flag.txt`) stored in a path reachable from the app's working directory

## CWE / OWASP

- **CWE-22**: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
- **OWASP A01:2021**: Broken Access Control
