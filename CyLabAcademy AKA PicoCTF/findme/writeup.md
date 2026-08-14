# findme

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{proxies_all_the_way_be716d8e}`

## Summary

The login form's own on-page hint text is the actual credential, read literally rather than as
punctuation: the password is `test!` (with the exclamation mark), not `test`. Submitting the
wrong password (plain `test`) always returns an identical static-looking response regardless of
input, which is itself a decoy; the real password triggers a chain of redirects, first an HTTP
302 and then a client-side JavaScript redirect, each carrying one base64-encoded fragment of the
flag in a URL parameter named `id`.

## Discovery

The homepage reads: `Help us test this form` / `username:test and password:test.` and the
challenge description says the same. Submitting `username=test&password=test` (no `!`) always
returns the exact same byte-for-byte response (same `Content-Length`, same `ETag`) no matter what
is submitted, including deliberately wrong credentials, confirming it's a static fallback, not a
real authentication result.

A separate hidden page discovered via directory brute forcing (`/home`, case-insensitively
routed) is a themed decoy ("Our Bank," a dead client-side search box) referencing having been
"redirected here by a friend... couldn't find anything" — a hint that the real path involves a
redirect that dead-ends somewhere unhelpful if followed carelessly.

Re-reading the literal wording of the static hint response, `try username:test and
password:test!`, as the actual required password (the trailing `!` is the password's last
character, not sentence punctuation) and resubmitting with it produces real, different
behavior.

## Proof of Concept

```
curl -s -i -X POST http://TARGET/login \
  --data-urlencode "username=test" --data-urlencode "password=test!"
```

```
HTTP/1.1 302 Found
Location: /next-page/id=cGljb0NURntwcm94aWVzX2Fs
```

Following that redirect returns a page that, after a short client-side `setTimeout`, JavaScript-
navigates to a second `id=` URL carrying the next base64 fragment:

```html
<script>
  setTimeout(function () {
     window.location = "/next-page/id=bF90aGVfd2F5X2JlNzE2ZDhlfQ==";
  }, 0.5)
</script>
```

That page's own further redirect just leads to the `/home` decoy, ending the chain. Concatenating
both `id` fragments in order and base64-decoding the combined string reveals the flag:

```
echo -n "cGljb0NURntwcm94aWVzX2FsbF90aGVfd2F5X2JlNzE2ZDhlfQ==" | base64 -d
picoCTF{proxies_all_the_way_be716d8e}
```

## Root Cause

Sensitive data (the flag, split into pieces) is passed between pages entirely through
client-visible URL parameters across a chain of redirects, some server-side (HTTP 302) and some
client-side (JavaScript `window.location`). Anything placed in a redirect target URL is fully
exposed to the client regardless of how many hops it passes through or how it's encoded;
base64 provides no confidentiality, only a transport-safe encoding.

## CWE / OWASP

- **CWE-598**: Use of GET Request Method With Sensitive Query Strings
- **CWE-200**: Exposure of Sensitive Information to an Unauthorized Actor
- **OWASP A04:2021**: Insecure Design
