# Exploiting XSS to bypass CSRF defenses

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Practitioner
**Vulnerability:** Stored XSS used to defeat CSRF token protection

---

## Summary

An account's email-change endpoint is protected by a per-session CSRF token. Rather than trying to forge a cross-site request without knowing the token, stored XSS running same-origin in the victim's own session simply fetches a page containing a fresh valid token and uses it directly.

---

## Discovery and Exploitation

### Step 1

Confirmed the blog comment field allows raw HTML/script injection (same stored-XSS primitive used throughout this lab family).

### Step 2

Inspected the account page and confirmed the email-change form includes a hidden CSRF token that changes per request/session.

### Step 3

Rather than attempting a traditional cross-site CSRF forgery (which would fail against a valid per-session token it doesn't have), posted a comment containing a script that runs entirely same-origin: it fetches the account page, extracts the current session's own CSRF token from the response body with a regex, then immediately POSTs the email-change form using that freshly captured token.

### Step 4

The simulated administrator's browser rendered the comment on its own schedule; since the fetch happens in the admin's own authenticated context, no external delivery mechanism or collaborator listener was needed.

### Step 5

The lab flipped to solved almost immediately after the comment was posted, confirming the administrator's email had been changed.


---

## Proof of Concept

```
<script>fetch('/my-account').then(r=>r.text()).then(t=>{const token=t.match(/name="csrf" value="([^"]+)"/)[1];fetch('/my-account/change-email',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'csrf='+token+'&email=hacker@evil-user.net'})});</script>
```

---

## Root Cause

CSRF tokens defend against forged cross-origin requests, but do nothing against an attacker who already has same-origin script execution via XSS - the token can simply be read out of a normal same-origin request and reused.

---

## CWE

- **CWE-79: Cross-site Scripting**
- **CWE-352: Cross-Site Request Forgery**
