# Reflected XSS into a JavaScript string with angle brackets HTML encoded

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Apprentice
**Vulnerability:** Reflected XSS - JavaScript string context breakout

---

## Summary

The search term is reflected inside an inline script block as a quoted JavaScript string literal. Angle brackets are encoded so no new tag can be opened, but since the injection point is already inside a script block, none is needed - breaking out of the string literal is enough.

---

## Discovery and Exploitation

### Step 1

Confirmed the search term was reflected inside a `<script>` block as something like `var searchTerm = 'REFLECTED';`.

### Step 2

A tag-based payload was blocked by angle-bracket encoding, but since execution context was already inside a script block, no new tag was needed at all.

### Step 3

Closed the string literal early with a single quote, inserted the payload using `-` as a throwaway arithmetic operator to keep the surrounding expression syntactically valid, then reopened a string so any trailing code kept parsing cleanly: `x'-alert(document.domain)-'`.

### Step 4

Loading the URL executed the alert immediately, since the injected code runs as part of the page's normal script execution.


---

## Proof of Concept

```
?search=x'-alert(document.domain)-'
```

---

## Root Cause

Search input is embedded inside a JavaScript string literal in an inline script block with only HTML-entity encoding applied (which is irrelevant inside a script context) and no JavaScript-string escaping.

---

## CWE

- **CWE-79: Cross-site Scripting**
