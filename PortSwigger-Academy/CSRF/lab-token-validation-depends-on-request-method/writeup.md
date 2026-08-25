# CSRF where token validation depends on request method

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Practitioner
**Vulnerability:** CSRF - token validation only enforced on POST, endpoint also accepts GET

---

## Summary

The email-change endpoint correctly validates a CSRF token on POST requests, but the same endpoint also accepts GET requests, and the token check is only wired up for the POST code path. A GET request triggers the exact same state change with no token needed at all.

---

## Discovery and Exploitation

### Step 1

Confirmed the POST-based email-change request does require a valid CSRF token, and that a request with a missing or invalid token is correctly rejected.

### Step 2

Re-tested the exact same logical action but sent as a GET request with the target value in the query string instead of the POST body - it succeeded with no token check performed at all.

### Step 3

Built a minimal HTML page hosted on the exploit server containing nothing but an `<img>` tag pointing at the vulnerable GET URL - loading an image is enough to trigger any GET request cross-site, cookies included, with no user interaction needed.

### Step 4

Delivered the page to the simulated victim; their browser loaded the image, which silently issued the GET request and changed their email.


---

## Proof of Concept

```
<img src="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email?email=hacker@evil-user.net">
```

---

## Root Cause

CSRF token validation is implemented only for the POST handler of an endpoint that also accepts GET requests performing the identical state-changing action, so an attacker can simply switch verbs to bypass the protection entirely.

---

## CWE

- **CWE-352: Cross-Site Request Forgery**
