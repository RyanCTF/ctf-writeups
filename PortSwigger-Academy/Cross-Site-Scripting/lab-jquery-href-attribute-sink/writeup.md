# DOM XSS in jQuery anchor href attribute sink using location.search source

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Apprentice
**Vulnerability:** DOM-based XSS - jQuery attr('href', ...) sink

---

## Summary

A 'Submit feedback' page reads a `returnPath` query parameter and uses jQuery's `.attr('href', ...)` to set a 'Back' link's destination, with no validation that the value is a safe relative path.

---

## Discovery and Exploitation

### Step 1

Located the feedback page and its 'Back' link, then traced the client-side script to a jQuery call reading `returnPath` from the query string and setting it directly as the link's `href`.

### Step 2

Since only the `href` attribute itself is controlled (not the surrounding HTML), used a `javascript:` URI as the value rather than trying to inject a new tag: `?returnPath=javascript:alert(document.domain)`.

### Step 3

Loaded the crafted URL and confirmed the 'Back' link's `href` had been set to the payload verbatim.

### Step 4

Clicked the link (the payload only executes on click, not on page load, since it's just an attribute value until then) and the alert fired.


---

## Proof of Concept

```
/feedback?returnPath=javascript:alert(document.domain)
```

---

## Root Cause

A URL-like query parameter is assigned directly to an anchor's `href` attribute via jQuery with no scheme validation, allowing a `javascript:` URI to be injected and executed on click.

---

## CWE

- **CWE-79: Cross-site Scripting**
