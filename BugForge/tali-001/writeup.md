# tali-001 - BugForge Lab Walkthrough

**URL:** https://lab-1789247580198-x72v50.labs-app.bugforge.io
**Difficulty:** Medium (Weekly)
**Vulnerability:** Broken token verification - signature check short-circuits when the signature segment is omitted
**Flag:** `bug{l6CO9JilPdEclDKgemIDVWQ0fM2YlahW}`

---

## Summary

Tali is a dice board game served as a static frontend over a single Apollo-style GraphQL
endpoint (`/graphql`). The game can be saved and resumed with a "save code" - a custom,
header-less JWT-like token of the form `base64url(payload).base64url(hmac)`. The payload carries
the full game state plus an `official` boolean, and only games flagged `official:true` that reach
a player-1 win produce a `certificate` (the flag).

The save-code verifier splits the token on `.` and only validates the HMAC **when a signature
segment is present**. Submitting a token with **no signature segment at all** (just the
base64url payload, no dot) makes the signature variable falsy, the guard short-circuits, and the
attacker-controlled payload is trusted wholesale. Forging `official:true` plus a finished
player-1 win in that unsigned payload makes `resumeGame` reconstruct a "verified official win"
and mint the certificate.

---

## Tech Stack

- Static HTML/JS frontend (`app.js`), single GraphQL endpoint `/graphql` (Apollo-style)
- No auth/accounts anywhere - fully stateless API
- Custom save/resume token: `base64url(JSON payload).base64url(HMAC-SHA256)` (header-less, 2-part)
- `certificate` is a `Game` field populated only for an official win

---

## Schema (relevant parts)

```
Query    { game(id), reachable(id, dieId) }
Mutation { newGame(mode), deploy(id,dieId,row,col), move(id,dieId,row,col),
           saveGame(id), resumeGame(code), dailyChallenge }
Game     { id mode phase size firstPlayer currentPlayer winner
           collected1 collected2 message certificate dice{...} }
```

- `dailyChallenge` returns a save code whose payload has `"official": true`.
- `saveGame(id)` returns a save code, but always with `"official": false` in its export
  (anti-laundering - you cannot legitimately export an official token).
- `resumeGame(code)` rebuilds a game from a save code and returns the full `Game`, including
  `certificate`.

---

## The save-code format

Decoding a `dailyChallenge` code:

```
<base64url payload>.<base64url 32-byte HMAC>      # 2 parts, NO header segment
```

```json
{
  "game": {
    "mode": "bot", "phase": "deploy", "firstPlayer": 1, "currentPlayer": 1,
    "winner": null, "collected1": 0, "collected2": 0,
    "dice": [ {"id":"p1-0","owner":1,"value":6,"row":null,"col":null,"deployed":false,"alive":true}, ... ]
  },
  "official": true
}
```

---

## Dead ends (what does NOT work)

This lab is a trap for the obvious crypto attacks. All of the following are properly defended:

- **Tamper payload, keep the original signature** -> rejected (HMAC is actually verified).
- **Forge a signature** via weak/leaked secret - rockyou (14.3M) + SecLists xato (5.2M),
  both message-encodings -> no match. The secret is a real random key.
- **Hash length-extension** (naive `sha256(secret||msg)`) - tested with hashpumpy across key
  lengths 0-64, both encodings -> all rejected. It is a genuine keyed HMAC.
- **Empty / zero / null signature with the dot still present** (`payload.`, `payload.null`,
  `payload.<zeros>`) -> all rejected.
- **Winning a real official game legitimately** (`dailyChallenge` -> `resumeGame` -> play to a
  flawless win) -> `certificate` stays `null`, because `saveGame`/`resumeGame` never surface the
  official flag back into a game you played move-by-move.
- Race conditions (per-game mutations are mutex-locked), GraphQL batching/aliasing (a separate,
  real rate-limit-bypass bug but not the flag), mode fuzzing, hidden fields - all refuted.

The one thing none of that covers: **removing the signature segment entirely.**

---

## The bug

The verifier is equivalent to:

```js
const [payloadPart, sig] = code.split('.');
if (sig && !verifyHMAC(payloadPart, sig)) {
  throw new Error('That save code is invalid or corrupt');
}
const payload = JSON.parse(b64url(payloadPart));   // trusted
// ... rebuild game; if payload.official && winner===1 && phase==='over' -> mint certificate
```

When the code is a bare payload with **no `.`**, `code.split('.')` yields `sig === undefined`.
The `sig && ...` guard short-circuits to false, verification is skipped, and the forged payload
is trusted. This is a cousin of the JWT `alg:none` bug, but the trigger is the *absence of the
dot*, not a header claim.

The crucial nuance: a token that still contains a `.` re-enters the verify branch and is
rejected. `payload.` (empty sig, dot present) is **rejected**; bare `payload` (no dot) is
**accepted**. A one-character difference is the whole vulnerability, which is why the obvious
empty/zero/null-signature variations all fail while dropping the segment outright succeeds.

---

## Exploit

1. Call `dailyChallenge` to get a real official code; decode its payload.
2. Edit the payload in place: `official:true` (already), `game.phase:"over"`, `game.winner:1`,
   `game.collected1:3`, `game.collected2:0` (a flawless player-1 win).
3. Re-encode **only the payload** as base64url. Do **not** append a `.` or any signature.
4. `resumeGame(code = base64url(payload))` -> the returned `Game.certificate` is the flag.

```graphql
mutation($c:String!){ resumeGame(code:$c){ winner phase collected1 collected2 certificate } }
```

Live result:

```
winner=1 phase=over c1=3 c2=0 CERT='bug{l6CO9JilPdEclDKgemIDVWQ0fM2YlahW}'
```

Submitted: `{"correct": true, "pointsAwarded": 50}`.

See `sig_bypass.py` for the full automated proof-of-concept (forges the payload and tries a
matrix of signature-omission variants; only the dot-less one returns a certificate).

---

## Impact

Any client can mint a "verified official win" certificate without playing - or winning - a
single game, by stripping the signature from a save code and trusting their own forged state.
The integrity control (HMAC over the save payload) is completely bypassable because verification
is conditional on the attacker-supplied signature's own presence.

## Fix

Verify unconditionally. Require the token to have exactly the expected number of segments and a
non-empty signature, and reject anything that does not before parsing the payload:

```js
const parts = code.split('.');
if (parts.length !== 2 || !parts[1]) throw new Error('invalid');
if (!verifyHMAC(parts[0], parts[1])) throw new Error('invalid');
```

Never gate a signature check on the presence of the signature itself.
