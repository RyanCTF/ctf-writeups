# Stored XSS into anchor href attribute with double quotes HTML-encoded

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Apprentice
**Vulnerability:** Stored XSS - href attribute injection via javascript: URI

---

## Summary

A blog comment form's 'website' field is rendered as an anchor's href attribute. Double quotes are HTML-encoded so the attribute can't be broken out of, but the entire value is used verbatim as the URL, so a javascript: scheme needs no escaping at all.

---

## Discovery and Exploitation

### Step 1

Submitted a comment with the website field set to `javascript:alert(document.domain)` and arbitrary values for the other required fields.

### Step 2

Revisited the post - the rendered comment included an anchor whose `href` was exactly the submitted value; double quotes elsewhere in the payload would have been encoded, but this payload needed none.

### Step 3

This class of payload does not execute on page load - the browser only evaluates a `javascript:` URI when the link is actually clicked - so located and clicked the resulting link.

### Step 4

The alert fired on click, confirming execution.


---

## Proof of Concept

```
javascript:alert(document.domain)
```

---

## Root Cause

A user-controlled 'website' field is placed directly into an anchor's href attribute with no scheme allowlist, so a javascript: URI is stored and later executed on click.

---

## CWE

- **CWE-79: Cross-site Scripting**
