# CSRF where token is not tied to user session

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Practitioner
**Vulnerability:** CSRF - token validated for well-formedness but not bound to the requesting session

---

## Summary

The application checks that a submitted CSRF token is valid and well-formed, but never verifies it actually belongs to the session making the request. An attacker's own token, obtained from their own low-privilege account, works perfectly well when embedded in a forged request against a completely different victim.

---

## Discovery and Exploitation

### Step 1

Logged in with a personal low-privilege account and captured the current CSRF token from the account page.

### Step 2

Built an auto-submitting HTML form on the exploit server targeting the email-change endpoint, using the personally-captured token rather than trying to obtain the victim's own.

### Step 3

Delivered the page to the simulated victim (a different, higher-privileged session); their browser auto-submitted the form, sending their own session cookie alongside the attacker's own valid-but-mismatched token.

### Step 4

The request succeeded and the victim's email was changed, confirming the server never checks that the token belongs to the session presenting it.


---

## Proof of Concept

```
<html><body><form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email" method="POST"><input type="hidden" name="email" value="hacker@evil-user.net"><input type="hidden" name="csrf" value="YOUR-OWN-TOKEN"></form><script>document.forms[0].submit()</script></body></html>
```

---

## Root Cause

CSRF tokens are generated and validated as globally-valid values rather than being bound to and checked against the specific session that requested them, defeating the entire purpose of the defense.

---

## CWE

- **CWE-352: Cross-Site Request Forgery**
