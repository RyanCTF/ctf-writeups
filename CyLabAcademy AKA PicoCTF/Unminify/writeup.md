# Unminify

**Platform:** CyLab Security Academy (picoCTF), picoCTF 2024
**Category:** Web Exploitation
**Difficulty:** Easy
**Flag:** `picoCTF{pr3tty_c0d3_743d0f9b}`

## Summary

The page's HTML is minified into a single unbroken line, and nearly every tag carries a decoy
`class="picoctf{}"` attribute (empty, lowercase) to bury the one real flag, which sits in the
same visual position but with correct capitalization and actual content.

## Discovery

Fetching the raw HTML shows dozens of elements with an identical-looking but empty
`class="picoctf{}"` attribute scattered throughout, clearly placed to make a simple text search
for `picoctf{` return a wall of false positives. One element breaks the pattern:

```html
<p class="picoCTF{pr3tty_c0d3_743d0f9b}"></p>
```

Correct capitalization (`picoCTF`, matching the platform's real flag prefix) and actual content
inside the braces distinguish it from every decoy.

## Proof of Concept

```
curl -s http://TARGET/ | grep -o 'picoCTF{[^}]*}'
```

## Root Cause

Not a real vulnerability, a "read carefully" exercise: minifying/compressing markup doesn't hide
data from anyone willing to actually read the raw response, and the decoy attributes only work
against a careless case-insensitive grep rather than actual inspection.

## CWE / OWASP

- **CWE-200**: Exposure of Sensitive Information to an Unauthorized Actor
- **OWASP A05:2021**: Security Misconfiguration
