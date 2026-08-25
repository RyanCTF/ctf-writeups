# Clickjacking with form input data prefilled from a URL parameter

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Apprentice
**Vulnerability:** Clickjacking combined with a form-prefill parameter

---

## Summary

The account page's email field can be prefilled via a URL query parameter. Combined with an
unprotected iframe, this turns a single decoy click into an arbitrary, attacker-chosen value being
submitted on the victim's behalf - the attacker doesn't need the click to carry any information at
all, just the URL does the work, and the click itself is only needed to trigger the real submit.

---

## Discovery and Exploitation

### Step 1

Confirmed the email input on the account page reads its default value from a URL query parameter
(`?email=...`), and that the page has no framing protection.

### Step 2

Logged in and measured the "Update email" button's position at the same viewport size intended for
the iframe.

### Step 3

Built the iframe's `src` with the malicious email value already baked into the query string, so
the field is pre-populated with the attacker's address the moment the page loads inside the frame -
no attacker JavaScript involved, just the URL.

### Step 4

Positioned a decoy "Click me" div over the button's measured coordinates, pinning the iframe with
`position:absolute; top:0; left:0; border:none;` and a `body { margin:0; padding:0; }` reset on the
exploit page to avoid the browser's default body-margin/iframe-border offset shifting the overlay
away from the real button.

### Step 5

Delivered to the simulated victim. Their single click submitted the pre-filled form, changing their
account email to the attacker-controlled address without them ever seeing or typing it.

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
  div { position:absolute; z-index:1; top:490px; left:32px; width:132px; height:32px; }
</style>
<div>Click me</div>
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/my-account?email=hacker@evil-user.net"></iframe>
```

---

## Root Cause

The application has no clickjacking protection (no X-Frame-Options / frame-ancestors CSP, no
frame-busting) and additionally trusts a client-supplied URL parameter to prefill a sensitive form
field, letting an attacker fully determine the value a victim unknowingly submits with a single
click.

---

## CWE

- **CWE-1021: Improper Restriction of Rendered UI Layers or Frames**
