# Stored XSS into HTML context with nothing encoded

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Apprentice
**Vulnerability:** Stored XSS - blog comment field with zero output encoding

---

## Summary

A blog's comment field stores and renders the comment body with no encoding at all, so a plain script tag executes for every visitor who views the post afterward.

---

## Discovery and Exploitation

### Step 1

Opened a blog post and located the comment form (comment body, name, email, website fields).

### Step 2

Submitted a comment with the payload `<script>alert(document.domain)</script>` as the comment body.

### Step 3

Revisited the post page - the script executed immediately on page load, and the alert dialog showed the lab's own domain, confirming same-origin execution.


---

## Proof of Concept

```
<script>alert(document.domain)</script>
```

---

## Root Cause

Comment content is stored and rendered back into the page verbatim, with no HTML entity encoding applied to angle brackets or any other special characters.

---

## CWE

- **CWE-79: Cross-site Scripting**
