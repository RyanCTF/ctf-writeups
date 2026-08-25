# DOM-based open redirection

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Practitioner
**Vulnerability:** DOM-based open redirection

---

## Summary

A blog post page's "Back to Blog" link computes its destination client-side by regex-matching the
page's own current URL for a `url=` parameter and setting `location.href` to whatever follows,
with no validation that the value is a relative path or points back at the same origin. Since the
source of the redirect target is the page's own address bar rather than a form field, the entire
attack is just a link - get a victim to visit a crafted URL and they end up redirected wherever the
attacker wants.

---

## Discovery and Exploitation

### Step 1

Found the vulnerable client-side logic attached to the "Back to Blog" link:

```js
var returnUrl = /url=(https?:\/\/.+)/.exec(location);
if (returnUrl) location.href = returnUrl[1];
else location.href = "/";
```

### Step 2

Noted the regex has no anchors and no origin check - it matches `url=` anywhere in the full
location string and captures everything after it up to the end, so any well-formed `http(s)://`
value is accepted and used directly as the redirect target.

### Step 3

Crafted a URL to the real blog post page with an extra `url` parameter pointing at an
attacker-controlled host:

```
https://YOUR-LAB-ID.web-security-academy.net/post?postId=4&url=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/
```

### Step 4

Visited the crafted URL directly, confirming the lab solved without needing to actually click
through the link or use the exploit server's delivery feature - the vulnerable condition is
satisfied purely by the URL/DOM state being reachable.

---

## Proof of Concept

```
https://YOUR-LAB-ID.web-security-academy.net/post?postId=4&url=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/
```

---

## Root Cause

The application derives a navigation target from an unvalidated, unanchored regex match against
the page's own current URL, then assigns it directly to `location.href`. Because the source is
attacker-controllable (a URL a victim can be persuaded to click) and the sink performs no
same-origin or allow-list check, an attacker fully controls where the victim is redirected.

---

## CWE

- **CWE-601: URL Redirection to Untrusted Site ('Open Redirect')**
