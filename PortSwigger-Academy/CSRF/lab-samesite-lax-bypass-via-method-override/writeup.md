# SameSite Lax bypass via method override

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Practitioner
**Vulnerability:** CSRF - SameSite=Lax cookie bypass combined with an HTTP method-override parameter

---

## Summary

No CSRF token is used at all here; the application relies purely on SameSite=Lax session cookies, which are excluded from cross-site POST requests but still sent on a top-level GET navigation. Combining that behavior with an undocumented `_method` override parameter (which lets a GET be processed as if it were a POST) defeats the protection entirely.

---

## Discovery and Exploitation

### Step 1

Confirmed the session cookie was set with no explicit SameSite attribute (defaulting to Lax in modern browsers) and that a direct cross-site POST to the email-change endpoint correctly excluded the cookie.

### Step 2

Tested whether the endpoint supported an HTTP method-override mechanism by sending a GET request with an added `_method=POST` parameter - it succeeded and changed the email, confirming the override.

### Step 3

Since SameSite=Lax still permits the cookie on a genuine top-level navigation (not a subresource load like an `<img>` tag), built the exploit-server payload as a real navigation using `document.location =` rather than an image tag.

### Step 4

Delivered the page to the simulated victim; the resulting top-level GET navigation carried their session cookie and was processed as the protected POST action via the override parameter.


---

## Proof of Concept

```
<script>document.location = "https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email?email=hacker@evil-user.net&_method=POST"</script>
```

---

## Root Cause

The application relies solely on SameSite=Lax cookie behavior for CSRF protection, but also implements an HTTP method-override feature that lets a GET request (which SameSite=Lax does not block on top-level navigation) be treated identically to a protected POST.

---

## CWE

- **CWE-352: Cross-Site Request Forgery**
