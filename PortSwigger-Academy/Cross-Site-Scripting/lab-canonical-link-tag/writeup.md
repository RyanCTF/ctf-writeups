# Reflected XSS in canonical link tag

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Practitioner
**Vulnerability:** Reflected XSS - single-quote attribute breakout + accesskey trigger

---

## Summary

The site reflects its own full query string into a canonical <link> tag's href attribute, which is wrapped in single quotes rather than the more common double quotes. Angle brackets and double quotes are encoded, but single quotes are not, and since a <link> element has no natural way to receive a click or focus, the injected attribute has to be a keyboard-triggered accesskey handler instead.

---

## Discovery and Exploitation

### Step 1

Appended an arbitrary marker query string to the homepage URL and observed it get reflected verbatim into a `<link rel="canonical" href='...'/>` tag - noting the attribute is wrapped in single quotes, not the more typical double quotes.

### Step 2

Tested a double-quote breakout first out of habit - it failed, since both angle brackets and double quotes were HTML-encoded in the output.

### Step 3

Tested a raw single quote - it passed through completely unescaped, confirming the real attribute boundary.

### Step 4

Since `<link>` elements aren't clickable or focusable through normal means, injected an `accesskey` attribute paired with an `onclick` handler instead of trying to open a new tag: `?'accesskey='x'onclick='alert(document.domain)`.

### Step 5

Loaded the crafted URL and triggered the injected accesskey shortcut (Alt+X on Linux/Windows Chrome), which fired the alert.


---

## Proof of Concept

```
?'accesskey='x'onclick='alert(document.domain)
```

---

## Root Cause

The application HTML-encodes angle brackets and double quotes when reflecting the query string into the canonical tag's href, but the attribute itself is delimited with single quotes, which are never encoded - leaving the real delimiter completely unprotected.

---

## CWE

- **CWE-79: Cross-site Scripting**
