# Blind SQL injection with time delays

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Practitioner
**Vulnerability:** Blind SQL Injection - time-based detection via a tracking cookie

---

## Summary

The injection point here is a `TrackingId` cookie set on first visit and never reflected anywhere in the response, so there's no visible output or error to observe. The only signal available is how long the server takes to respond, confirmed with a PostgreSQL time-delay payload.

---

## Discovery and Exploitation

### Step 1

Made a clean request to capture the server-issued `TrackingId` cookie value.

### Step 2

Appended a PostgreSQL time-delay payload to the existing cookie value rather than replacing it outright, in case the backend validates the tracking ID's format before it reaches the vulnerable query: `<value>'||pg_sleep(8)--`.

### Step 3

Sent the request with the modified cookie and measured the response time - it took roughly 8 seconds longer than a baseline request, confirming the injection despite there being zero visible output difference.


---

## Proof of Concept

```
Cookie: TrackingId=<original-value>'||pg_sleep(8)--
```

---

## Root Cause

The tracking cookie value is concatenated into a backend SQL query with no output ever reflected to the client, meaning even a fully blind injection point is exploitable purely through response timing.

---

## CWE

- **CWE-89: SQL Injection**
