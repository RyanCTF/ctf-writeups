# MatchTheRegex

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{succ3ssfully_matchtheregex_2375af79}`

## Summary

The `/flag` endpoint checks the `input` query parameter against a regular expression to decide
whether to return the flag. The regex itself is left sitting in a JavaScript comment on the
homepage, and its structure spells out the challenge's own prefix once decoded: 7 characters
starting with `p`, ending in `F`, matching the exact shape of the string `picoCTF`.

## Discovery

The homepage's inline script contains:

```javascript
// ^p.....F!?
fetch(`/flag?input=${val}`)
```

Reading that as a regex: `^p` (starts with `p`), `.....` (exactly five arbitrary characters),
`F` (literal), `!?` (an optional literal `!`, since `?` makes the preceding token optional).
Concatenating: `p` + any 5 characters + `F` matches exactly 7 characters shaped like `p????F`,
which is precisely how `picoCTF` is spelled (`p`-`icoCT`-`F`). No `$` end anchor is present, so
the match doesn't need to consume the whole string, but supplying `picoCTF` itself satisfies it
directly.

## Proof of Concept

```
curl -s "http://TARGET/flag?input=picoCTF"
```

```json
{"flag":"picoCTF{succ3ssfully_matchtheregex_2375af79}"}
```

## Root Cause

Not a traditional vulnerability, a literal read-the-source exercise: the validation regex was
left visible to the client instead of being enforced purely server side with the pattern itself
kept opaque, so satisfying it required no guessing at all once the comment was read.

## CWE / OWASP

- **CWE-200**: Exposure of Sensitive Information to an Unauthorized Actor
- **OWASP A05:2021**: Security Misconfiguration
