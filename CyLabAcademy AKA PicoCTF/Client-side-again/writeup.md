# Client-side-again

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Easy
**Flag:** `picoCTF{not_this_again_4daf93}`

## Summary

The entire "login" check runs client-side in obfuscated JavaScript: it never hashes or sends the
password anywhere, it just compares fixed-position substrings of the input directly against
hardcoded string fragments. De-obfuscating the string-array indirection recovers the exact
literal password (which is the flag) with no need to run anything against the server at all.

## Discovery

The page's `verify()` function uses a classic string-array obfuscator: an array of literals is
rotated at load time via a `push(shift())` loop, and every string reference in the code is
replaced with a lookup `_0x4b5b(index)` into that rotated array.

Reproducing the exact rotation in Node.js resolves every lookup:

```js
var arr = ["daf93}","_again_4","this","Password Verified","Incorrect password",
           "getElementById","value","substring","picoCTF{","not_this"];
(function(a, n) {
  var rotate = function(k) { while (--k) a.push(a.shift()); };
  rotate(++n);
})(arr, 0x1b3);
// arr is now: ["getElementById","value","substring","picoCTF{","not_this",
//              "daf93}","_again_4","this","Password Verified","Incorrect password"]
```

Substituting those back into `verify()` gives readable logic:

```js
function verify() {
  checkpass = document.getElementById('pass').value;
  split = 4;
  if (checkpass.substring(0, 8)   == 'picoCTF{') {
   if (checkpass.substring(7, 9)  == '{n') {
    if (checkpass.substring(8, 16) == 'not_this') {
     if (checkpass.substring(3, 6) == 'oCT') {
      if (checkpass.substring(24, 32) == 'daf93}') {
       if (checkpass.substring(6, 11) == 'F{not') {
        if (checkpass.substring(16, 24) == '_again_4') {
         if (checkpass.substring(12, 16) == 'this') {
          alert('Password Verified');
  } } } } } } } }
  else { alert('Incorrect password'); }
}
```

Every check is just a redundant cross-check on overlapping slices of four literal 8-character
chunks — `picoCTF{`, `not_this`, `_again_4`, `daf93}` — concatenated in order.

## Proof of Concept

```python
print('picoCTF{' + 'not_this' + '_again_4' + 'daf93}')
# picoCTF{not_this_again_4daf93}
```

No request to the server was ever required; the "password" is the flag itself, fully
reconstructable from the client-shipped JavaScript alone.

## Root Cause

Client-side-only authentication: the correct value is embedded directly in code the browser must
download and execute, so any obfuscation only delays, rather than prevents, static recovery of
the secret. Real authentication checks must happen server-side, where the client never receives
the material needed to derive the correct answer.

## CWE / OWASP

- **CWE-602**: Client-Side Enforcement of Server-Side Security
- **CWE-656**: Reliance on Security Through Obscurity
- **OWASP A08:2021**: Software and Data Integrity Failures
