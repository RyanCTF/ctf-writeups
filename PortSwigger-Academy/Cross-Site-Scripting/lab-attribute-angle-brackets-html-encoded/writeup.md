# Reflected XSS into attribute with angle brackets HTML-encoded

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Apprentice
**Vulnerability:** Reflected XSS - attribute breakout, angle brackets encoded

---

## Summary

The search term is reflected into an input field's `value` attribute. Angle brackets are HTML-encoded so a new tag cannot be opened, but the attribute itself can still be closed with an unencoded double quote, letting a new attribute be injected onto the same element.

---

## Discovery and Exploitation

### Step 1

Submitted a search term and confirmed it was reflected inside an `<input value="...">` element.

### Step 2

Tried a standard `<script>` breakout - the angle brackets came back HTML-encoded, ruling out opening a new tag.

### Step 3

Tested a bare double quote and confirmed it was NOT encoded, meaning the attribute itself could be closed.

### Step 4

Closed the value attribute and added a new one that both grabs focus and fires on it, since `autofocus` triggers without any user interaction: `" autofocus onfocus=alert(document.domain) x="`. The trailing `x="` mops up the real closing quote so the markup stays well-formed.

### Step 5

Loading the URL fired the alert immediately, since the injected element auto-focuses on page load.


---

## Proof of Concept

```
?search=" autofocus onfocus=alert(document.domain) x="
```

---

## Root Cause

Search input is HTML-encoded for angle brackets before being reflected into an attribute value, but double quotes are not encoded, so the attribute boundary itself remains breakable.

---

## CWE

- **CWE-79: Cross-site Scripting**
