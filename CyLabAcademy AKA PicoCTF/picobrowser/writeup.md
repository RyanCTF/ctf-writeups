# picobrowser

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Easy
**Flag:** `picoCTF{p1c0_s3cr3t_ag3nt_fba5c48f}`

## Summary

The `/flag` page gates its content on the client-supplied `User-Agent` header, checking for the
literal string `picobrowser`. Since the `User-Agent` header is entirely attacker-controlled and
carries no authentication value, spoofing it is a one-line bypass.

## Discovery

Requesting `/flag` normally returns "You're not picobrowser!" along with the request's own
User-Agent string echoed back, confirming the check is a direct server-side comparison against
that header.

## Proof of Concept

```
curl -s -A "picobrowser" "http://TARGET/flag"
```

```html
<b>Flag</b>: <code>picoCTF{p1c0_s3cr3t_ag3nt_fba5c48f}</code>
```

## Root Cause

Using a client-supplied, trivially forgeable HTTP header (`User-Agent`) as an access control or
authentication mechanism. It identifies nothing about the requester and can be set to any value.

## CWE / OWASP

- **CWE-807**: Reliance on Untrusted Inputs in a Security Decision
- **OWASP A01:2021**: Broken Access Control
