# cafeclub-003 - BugForge Lab Writeup

**URL:** https://lab-1784802092811-obhyyt.labs-app.bugforge.io/
**Difficulty:** Easy
**Vulnerability:** Path Traversal / Local File Inclusion on the product image proxy endpoint
**Flag:** `bug{RjsoXpsmunbkYl3rBZ7u54dkjGFD2Cii}`

---

## Summary

CafeClub is a React SPA plus Express.js coffee shop app. Product images are not served as static files directly, they are proxied through a backend endpoint, `GET /api/product/image?file=<path>`, which reads the `file` query parameter and returns whatever it points to on disk. The parameter is not sanitized against directory traversal, so requesting `?file=../flag.txt` walks one directory up from the images folder and returns the flag file contents directly in the response body.

## Tech Stack

React SPA (CRA), Express.js (`x-powered-by: Express`), JWT auth (`Authorization: Bearer`).

## Key Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/register` / `POST /api/login` | none | Returns JWT and user object |
| `GET /api/products` | Bearer | Product listing, each item carries an `image_url` like `/images/brazilian-santos.png` |
| `GET /api/product/image?file=` | Bearer | Backend proxy that reads the `file` param off disk and streams it back |
| `GET /images/:name` | none | Static frontend asset path, served by the CRA build's catch-all router, always 200s to `index.html` for unrecognized paths |

## Attack Chain

1. Registered a normal account (`POST /api/register`) and obtained a JWT.
2. Pulled the product listing at `GET /api/products` and noted each product carries an `image_url` field such as `/images/brazilian-santos.png`.
3. First tried appending traversal sequences directly to the static `/images/` path (`/images/../flag.txt`, `/images/....//flag.txt`, URL-encoded variants). All of these returned HTTP 200 with the SPA's `index.html`, a dead end, since that path is the frontend's static catch-all router and not a real filesystem lookup.
4. Downloaded the main JS bundle (`/static/js/main.*.js`) and grepped for `image` references to find how the frontend actually requests product images. Found the real call site:
   ```js
   xo.get("/api/product/image?file=".concat(t), {responseType: "blob"})
   ```
   confirming a backend proxy endpoint, `GET /api/product/image`, takes the image path as a `file` query parameter rather than serving it as a plain static asset.
5. Confirmed the endpoint works normally with a legitimate value: `GET /api/product/image?file=/images/brazilian-santos.png` returns `200 image/png`.
6. Tested traversal against the real sink:
   ```
   GET /api/product/image?file=../flag.txt
   Authorization: Bearer <token>
   ```
   Response body:
   ```
   bug{RjsoXpsmunbkYl3rBZ7u54dkjGFD2Cii}
   ```
7. Deeper traversal (`../../flag.txt`, `../../../flag.txt`) returned `{"error":"File not found"}`, confirming the flag sits exactly one directory above wherever the images folder is rooted, and that the path is resolved relative to that images directory rather than an arbitrary base.

## Dead Ends

| Attempted | Result | Lesson |
|---|---|---|
| `/images/../flag.txt`, `/images/....//flag.txt`, URL-encoded traversal on the static `/images/` path | 200, returns `index.html` | This is the CRA static catch-all route, not a filesystem read, traversal here is meaningless |
| `../../flag.txt` and deeper on the real endpoint | 404 `File not found` | Confirms the flag is exactly one level up from the images directory, not further |
| `..%2fflag.txt`, `..\flag.txt` on the real endpoint | 400 | Encoded and backslash variants rejected outright, plain `../` was sufficient and required no bypass |

## Root Cause

The `/api/product/image` endpoint builds a filesystem path directly from a client supplied `file` query parameter with no normalization or containment check (no `path.resolve` plus prefix validation against the intended images directory). Any `../` sequence in the parameter is honored literally, allowing reads outside the intended directory.

## CWE / OWASP

CWE-22 (Path Traversal), maps to OWASP API8:2023 (Security Misconfiguration) / A01:2021 (Broken Access Control).
