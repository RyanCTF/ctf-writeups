# head-dump

**Platform:** CyLab Security Academy (picoCTF), picoCTF 2025
**Category:** Web Exploitation
**Difficulty:** Easy
**Flag:** `picoCTF{Pat!3nt_15_Th3_K3y_546786ba}`

## Summary

A Node.js/Express blog exposes a Swagger/OpenAPI specification at `/api-docs/` that documents
every backend route, including an undocumented-in-the-UI diagnostic endpoint, `/heapdump`, meant
for debugging server memory usage. Downloading it dumps the full V8 heap snapshot to the client,
and process memory happens to still contain the flag string in plaintext.

## Discovery

The homepage links to `/about`, `/services`, and `/api-docs`. The API docs page is a standard
Swagger UI, and its underlying spec is loaded from `/api-docs/swagger-ui-init.js` as an inline
JSON object rather than a separate `swagger.json` file. Reading that spec directly (rather than
relying on the rendered UI) shows every route including one tagged "Diagnosing":

```json
"/heapdump": {
  "get": {
    "tags": ["Diagnosing"],
    "summary": "Diagnosing the memory allocation.",
    "responses": { "200": { "description": "Returns a memory allocation status." } }
  }
}
```

## Proof of Concept

```
curl -s -o heap.dump http://TARGET/heapdump
strings heap.dump | grep 'picoCTF{'
```

The heap dump (an `application/octet-stream` V8 snapshot, ~11MB) contains the flag string in
plaintext among the live heap's retained strings.

## Root Cause

A Node.js memory-diagnostics endpoint (a `v8.writeHeapSnapshot()`-style route) was left enabled
and unauthenticated in what is otherwise a public production app. Heap snapshots capture whatever
strings and objects are currently resident in the process's memory, which can include secrets,
tokens, or in this case a flag value, with zero access control gating who can request one.

## CWE / OWASP

- **CWE-215**: Insertion of Sensitive Information Into Debugging Code
- **CWE-497**: Exposure of Sensitive System Information to an Unauthorized Control Sphere
- **OWASP A05:2021**: Security Misconfiguration
