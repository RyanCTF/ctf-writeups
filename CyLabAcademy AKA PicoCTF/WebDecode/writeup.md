# WebDecode

**Platform:** CyLab Security Academy (picoCTF), picoCTF 2024
**Category:** Web Exploitation
**Difficulty:** Easy
**Flag:** `picoCTF{web_succ3ssfully_d3c0ded_df0da727}`

## Summary

A small multi page static site hides the flag inside a nonstandard HTML attribute on the About
page, base64 encoded. The homepage explicitly teases "Keep Navigating," pointing at exploring
the other pages rather than the landing page itself.

## Discovery

The homepage and Contact page contain only red herring text ("Keep Searching", "Don't give
up!!!") with nothing hidden. The About page's `<section>` tag carries a custom attribute that
isn't part of any standard HTML vocabulary and isn't referenced by the site's CSS or any script:

```html
<section class="about" notify_true="cGljb0NURnt3ZWJfc3VjYzNzc2Z1bGx5X2QzYzBkZWRfZGYwZGE3Mjd9">
  <h1>Try inspecting the page!! You might find it there</h1>
</section>
```

The heading text on that same page is a direct hint to open dev tools / view page source rather
than just reading the rendered output.

## Proof of Concept

```
curl -s http://TARGET/about.html | grep -o 'notify_true="[^"]*"'
echo "cGljb0NURnt3ZWJfc3VjYzNzc2Z1bGx5X2QzYzBkZWRfZGYwZGE3Mjd9" | base64 -d
```

## Root Cause

Not a real vulnerability class so much as a straightforward "read the source, not just the
rendered page" exercise: a value was stashed in a custom, non-semantic HTML attribute that is
invisible in the rendered page but plainly visible to anyone who views source or opens the
browser's element inspector.

## CWE / OWASP

- **CWE-200**: Exposure of Sensitive Information to an Unauthorized Actor
- **OWASP A05:2021**: Security Misconfiguration
