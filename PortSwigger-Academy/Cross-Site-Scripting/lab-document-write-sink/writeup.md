# DOM XSS in document.write sink using source location.search

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Apprentice
**Vulnerability:** DOM-based XSS - document.write sink, location.search source

---

## Summary

Client-side JavaScript reads the `search` query parameter and writes it directly into the page via `document.write`, inside what's effectively an `<img>` tag's `src` attribute used for a tracking pixel.

---

## Discovery and Exploitation

### Step 1

Used the site's search box and noticed the search term appeared to be echoed into the page markup.

### Step 2

Reviewed the page's inline script and found a `document.write` call building an `<img>` tag whose `src` attribute embeds the raw `search` query parameter.

### Step 3

Broke out of the attribute with a double quote and closing angle bracket, then opened a fresh element with an `onload` handler: `"><svg onload=alert(document.domain)>`.

### Step 4

Loading the crafted URL fired the alert immediately on page load, confirming execution.


---

## Proof of Concept

```
?search="><svg onload=alert(document.domain)>
```

---

## Root Cause

User-controlled input from `location.search` is written into the DOM via `document.write` with no sanitization or encoding of the value before it lands inside an HTML attribute context.

---

## CWE

- **CWE-79: Cross-site Scripting**
