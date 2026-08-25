# Basic clickjacking with CSRF token protection

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Apprentice
**Vulnerability:** Clickjacking bypassing CSRF token protection

---

## Summary

The account deletion form is protected by a CSRF token, which normally prevents an attacker from
forging the request cross-site. Clickjacking sidesteps this entirely: rather than forging the
request, the attack tricks a real, authenticated visitor into submitting the genuine form
themselves inside an invisible iframe. Since it's a real click on the real page, the real token
goes along for the ride.

---

## Discovery and Exploitation

### Step 1

Confirmed the account page could be framed at all (no X-Frame-Options / frame-ancestors CSP, no
JavaScript frame-busting).

### Step 2

Logged in as the test account and measured the exact on-page position of the "Delete account"
button at the same viewport size intended for the iframe.

### Step 3

Built a single semi-transparent iframe of the account page, layered a "Click me" decoy `<div>`
exactly over the button's measured coordinates, and verified the visual alignment with a
temporarily raised opacity before dropping it back down for delivery.

### Step 4

Pinned the iframe with `position:absolute; top:0; left:0; border:none;` and reset
`body { margin:0; padding:0; }` on the exploit page rather than leaving the iframe in normal
document flow. The browser's own default body margin and default iframe border otherwise shift the
iframe's content away from the outer page's true viewport origin, which can throw off coordinates
measured from a plain, unwrapped page load by several pixels - a small but avoidable source of
misalignment.

### Step 5

Delivered the page to the simulated victim. Their click landed on the real, invisible "Delete
account" button, submitting the form (token included) and deleting the account, confirming the lab
solved.

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
  div { position:absolute; z-index:1; top:538px; left:16px; width:146px; height:32px; }
</style>
<div>Click me</div>
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>
```

---

## Root Cause

The application sends no X-Frame-Options or frame-ancestors CSP header and has no client-side
frame-busting protection, so it can be embedded in an attacker's iframe. A CSRF token alone does
not defend against clickjacking, since the forged interaction is a genuine click on the genuine
page rather than a cross-origin request forgery.

---

## CWE

- **CWE-1021: Improper Restriction of Rendered UI Layers or Frames**
