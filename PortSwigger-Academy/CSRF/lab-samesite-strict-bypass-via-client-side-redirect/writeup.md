# SameSite Strict bypass via client-side redirect

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Practitioner
**Vulnerability:** CSRF - SameSite=Strict bypass via a same-site client-side redirect gadget with a path-traversal parameter

---

## Summary

SameSite=Strict blocks the session cookie on any cross-site request at all, even a genuine top-level navigation, ruling out a direct link to the target. The bypass instead uses a page that IS on the target's own origin and performs a client-side JavaScript redirect based on unvalidated user input - once the browser is already same-site, a JS-triggered navigation from that page carries the cookie normally, and path traversal in the redirect's own input parameter repoints it anywhere on the target, including the protected endpoint.

---

## Discovery and Exploitation

### Step 1

Confirmed the session cookie is set with `SameSite=Strict` and that even a direct top-level navigation to the target from a cross-site page fails to carry it.

### Step 2

Posted an arbitrary blog comment and observed that submission redirects to a confirmation page at `/post/comment/confirmation?postId=X`, which after a few seconds performs its own client-side redirect back to the blog post.

### Step 3

Read the confirmation page's own imported JavaScript directly and found it builds the redirect target by concatenating the raw `postId` query parameter into a path with zero validation.

### Step 4

Tested path traversal in that parameter (`postId=1/../../my-account`) via a normal browser visit and confirmed the browser normalized the path and successfully landed on the account page - proving the redirect gadget could be steered to an arbitrary same-origin endpoint.

### Step 5

Built an exploit-server payload that performs a top-level navigation to the confirmation URL with a traversal payload pointing at the email-change endpoint, appending the required `submit=1` parameter (with the internal `&` URL-encoded so it stays inside the `postId` value rather than being read as a separate top-level parameter) and percent-encoding the literal `@` in the email address as `%40` (a literal `@` in this specific redirect chain silently prevented the attack from completing, discovered by comparing against the platform's own documented solution after an unencoded attempt failed).

### Step 6

Because the confirmation page's own redirect script executes on an origin that IS the target site, the resulting second-hop navigation is same-site from the browser's perspective and carried the Strict session cookie, changing the victim's email successfully.


---

## Proof of Concept

```
<script>document.location = "https://YOUR-LAB-ID.web-security-academy.net/post/comment/confirmation?postId=1/../../my-account/change-email?email=pwned%40evil-user.net%26submit=1"</script>
```

---

## Root Cause

A same-site page performs a client-side redirect using an unvalidated, path-traversal-vulnerable parameter, letting an attacker point that trusted, cookie-carrying navigation at an arbitrary sensitive endpoint - completely bypassing the SameSite=Strict protection, which only guards against cross-site-initiated requests, not same-site redirect gadgets.

---

## CWE

- **CWE-352: Cross-Site Request Forgery**
- **CWE-601: URL Redirection to Untrusted Site**
- **CWE-22: Path Traversal**
