# DOM XSS in innerHTML sink using source location.search

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Apprentice
**Vulnerability:** DOM-based XSS - innerHTML sink, location.search source

---

## Summary

Similar source (the search query parameter) to the document.write lab, but the sink here is `element.innerHTML`, which parses HTML but strips `<script>` tags on insertion - requiring an event-handler-based payload instead.

---

## Discovery and Exploitation

### Step 1

Confirmed the search term was being reflected into the page and traced the sink to an `innerHTML` assignment in the client-side JS.

### Step 2

A first attempt with a plain `<script>` payload had no effect, since browsers do not execute script tags inserted via `innerHTML`.

### Step 3

Switched to an event-handler payload that fires as soon as the element is parsed: `<img src=1 onerror=alert(document.domain)>`.

### Step 4

Loading the URL with this payload triggered the alert, confirming the sink accepts and executes injected markup with an inline handler.


---

## Proof of Concept

```
?search=<img src=1 onerror=alert(document.domain)>
```

---

## Root Cause

Search input is inserted into the page via `innerHTML` with no sanitization; while `innerHTML` blocks `<script>` execution by design, it happily parses and renders other elements whose event-handler attributes still execute.

---

## CWE

- **CWE-79: Cross-site Scripting**
