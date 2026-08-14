# Bookmarklet

**Platform:** CyLab Security Academy (picoCTF), picoCTF 2024
**Category:** Web Exploitation
**Difficulty:** Easy
**Flag:** `picoCTF{p@g3_turn3r_1d1ba7e0}`

## Summary

The page hands out a `javascript:` bookmarklet that, when actually run in a browser, decrypts
and alerts the flag. Rather than running the bookmarklet in a browser, the same decryption logic
can just be reimplemented directly against the encrypted string sitting in the page source.

## Discovery

The page body contains a read-only `<textarea>` with a bookmarklet:

```javascript
javascript:(function() {
    var encryptedFlag = "<encrypted bytes>";
    var key = "picoctf";
    var decryptedFlag = "";
    for (var i = 0; i < encryptedFlag.length; i++) {
        decryptedFlag += String.fromCharCode((encryptedFlag.charCodeAt(i) - key.charCodeAt(i % key.length) + 256) % 256);
    }
    alert(decryptedFlag);
})();
```

This is a simple repeating-key subtractive cipher: each character of the ciphertext has the
corresponding key character's code point subtracted (mod 256) to recover the plaintext byte.

## Proof of Concept

Reimplementing the same logic in Python against the raw page bytes (fetching with `curl` and
reading the file as UTF-8, since some ciphertext bytes fall in the C1 control range and get
silently mangled if copy-pasted through a terminal instead of read programmatically):

```python
import re
data = open('page.html', encoding='utf-8').read()
encrypted = re.search(r'var encryptedFlag = "(.*?)";', data).group(1)
key = "picoctf"
decrypted = "".join(
    chr((ord(ch) - ord(key[i % len(key)]) + 256) % 256)
    for i, ch in enumerate(encrypted)
)
print(decrypted)
```

```
picoCTF{p@g3_turn3r_1d1ba7e0}
```

## Root Cause

Not a server side vulnerability, a client side crypto exercise: the "encryption" is a trivial
repeating-key byte subtraction with a short, guessable key, and critically the entire decryption
algorithm ships to the client in plaintext JavaScript. Any cipher whose logic and key are both
visible to the party being kept out provides no real confidentiality.

## CWE / OWASP

- **CWE-321**: Use of Hard-coded Cryptographic Key
- **CWE-326**: Inadequate Encryption Strength
- **OWASP A02:2021**: Cryptographic Failures
