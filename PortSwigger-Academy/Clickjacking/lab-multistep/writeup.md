# Multistep clickjacking

**URL:** https://YOUR-LAB-ID.web-security-academy.net
**Difficulty:** Practitioner
**Vulnerability:** Clickjacking across a two-step confirmation flow

---

## Summary

The account deletion flow requires two separate real clicks: a "Delete account" button that
submits to a confirmation endpoint, followed by a "Yes" button on the resulting "Are you sure?"
page. A single unprotected iframe can still be used to jack both clicks, since the iframe's own
content changes to the confirmation page after the first click - two statically positioned decoy
elements layered over the same iframe are enough, no attacker-side JavaScript required.

---

## Discovery and Exploitation

### Step 1

Confirmed the account page could be framed (no X-Frame-Options / frame-busting) and walked the
real deletion flow manually: "Delete account" on `/my-account` submits a form to
`/my-account/delete`, which responds with an "Are you sure?" page containing "No, take me back"
and "Yes" options. "Yes" resubmits to the same endpoint with an additional `confirmed=true` field.

### Step 2

Measured the exact position of both buttons ("Delete account" on the account page, "Yes" on the
confirmation page) via their bounding boxes at the same viewport size as the planned iframe.

### Step 3

Built a single iframe pointing at `/my-account`, with two absolutely positioned decoy `<div>`s
layered above it at two different fixed coordinates - one over the initial "Delete account"
button's location, the other over where the "Yes" button appears once the iframe's content
changes following the first click. The victim is guided to click "Click me first" then "Click me
next"; both clicks land on the real, invisible target elements beneath.

### Step 4

Pinned the iframe with `position:absolute; top:0; left:0; border:none;` and reset `body{margin:0;
padding:0;}` on the exploit page, rather than relying on in-flow `position:relative` positioning.
Without this, the browser's default body margin (and default iframe border) shifts the iframe's
own content away from the outer page's true viewport origin, throwing off any coordinates that
were measured from a plain, unwrapped page load - the overlay divs then land a few pixels short of
the real buttons underneath, which is consistent with clicks failing to register even when the
overlay looks visually correct.

### Step 5

Verified alignment at a visible opacity by screenshotting both iframe states (before and after
simulating the first click) and confirming the decoys sat centered on each real button, then
dropped opacity to near-zero and delivered the page to the simulated victim. Solved on the first
delivery.

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
  div { position:absolute; z-index:1; }
  #decoy1 { top:490px; left:16px;  width:146px; height:32px; }
  #decoy2 { top:288px; left:183px; width:120px; height:32px; }
</style>
<div id="decoy1">Click me first</div>
<div id="decoy2">Click me next</div>
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>
```

---

## Root Cause

The application sends no X-Frame-Options or frame-ancestors CSP header and has no client-side
frame-busting on either the account page or its delete-confirmation page, so both steps of a
destructive, multi-click confirmation flow can be silently chained together behind a single
overlay using nothing but static CSS positioning.

---

## CWE

- **CWE-1021: Improper Restriction of Rendered UI Layers or Frames**
