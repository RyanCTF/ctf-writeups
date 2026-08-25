# Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Practitioner
**Vulnerability:** Stored XSS - HTML-entity bypass of correct JavaScript-string escaping

---

## Summary

A comment's 'website' field lands inside an onclick handler as a quoted JavaScript string. The application does real, correct JS-string escaping (it doubles backslashes and escapes quotes), defeating the classic backslash-smuggling trick - but it never encodes ampersands, so an HTML entity for a quote sails through the escaping layer untouched and gets decoded back into a real quote by the browser right before the JS engine runs it.

---

## Discovery and Exploitation

### Step 1

Submitted a comment with the website field set to a payload using a raw backslash to try to neutralize the app's own escaping backslash (the classic trick against naive `'` -> `\'` replacement): `\'-alert(document.domain)-\'`.

### Step 2

Read the resulting `onclick` attribute back from the DOM and counted the backslashes preceding the surviving quote character programmatically - found 3 backslashes, an odd number, meaning the quote was still escaped. This confirmed the app doubles pre-existing backslashes before escaping quotes, i.e. it does correct JS-string escaping, not the naive kind the classic trick defeats.

### Step 3

Reconsidered the lab's own stated defenses: angle brackets HTML-encoded, double quotes HTML-encoded, single quotes and backslashes JS-escaped - notably, ampersand is not on that list.

### Step 4

Since the onclick attribute value is still an HTML attribute, decoded by the browser before the JS engine ever sees it, used an HTML entity for the quote instead of a literal one: `&#39;`. The app's JS-escaping only scans for literal `'`/`\` characters (an entity isn't one), and the app never encodes `&`, so the entity survives untouched all the way to the browser, which decodes it back into a real quote immediately before executing the onclick handler.

### Step 5

Verified via the DOM (`getAttribute('onclick')`, which reflects the browser's own decoded value) that the entities had become real quote characters, then clicked the element and the alert fired.


---

## Proof of Concept

```
https://example.com&#39;-alert(document.domain)-&#39;
```

---

## Root Cause

The application correctly escapes single quotes and backslashes in JavaScript-string context, but never HTML-encodes ampersands, allowing an HTML entity to smuggle a literal quote character past the JS-escaping layer since the browser only decodes the entity after that layer has already run.

---

## CWE

- **CWE-79: Cross-site Scripting**
- **CWE-116: Improper Encoding or Escaping of Output**
