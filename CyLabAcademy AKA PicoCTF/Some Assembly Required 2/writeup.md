# Some Assembly Required 2

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Reverse Engineering / Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{f80e708bb2a3b2e87cdfe4a9206adbaf}`

## Summary

A client-side flag checker validates input by copying each character into WebAssembly linear
memory (XOR-ing it with `0x08` along the way) and comparing the result against a fixed,
XOR-obfuscated string baked into the module's data section using a hand-rolled `strcmp`. Since
the comparison and the XOR key are both fully visible in the compiled WASM, the flag is
recovered by statically reading the target bytes out of the module and undoing the same XOR,
with no need to ever run the check against a guess.

## Discovery

`index.html` loads a single obfuscated JS file (`Y8splx37qY.js`). Beautifying/de-aliasing its
string-array obfuscation shows the actual logic:

```js
let wasm = await WebAssembly.instantiate(await (await fetch('./aD8SvhyVkb')).arrayBuffer());
exports = wasm.instance.exports;

function onButtonPress() {
  let input = document.getElementById('input').value;
  for (let i = 0; i < input.length; i++) exports.copy_char(input.charCodeAt(i), i);
  exports.copy_char(0, input.length);
  result.innerHTML = exports.check_flag() == 1 ? 'Correct!' : 'Incorrect!';
}
```

Fetching `./aD8SvhyVkb` directly (no extension, despite the `.wasm` MIME/format) retrieves an
864-byte WebAssembly module, disassembled with `wasm2wat`:

```
(func (;3;) (type 3) (param i32 i32)      ;; copy_char(char, index)
  ...
  block
    local.get $char
    i32.eqz
    br_if 0                               ;; skip XOR if char == 0 (null terminator)
    local.get $char
    i32.const 8
    i32.xor
    local.set $char
  end
  local.get $index
  local.get $char
  i32.store8 offset=1072                  ;; mem[1072 + index] = char (XORed with 8 unless it's 0)
```

```
(func (;2;) (type 2) (result i32)          ;; check_flag()
  ...
  i32.const 1072                           ;; user input buffer
  i32.const 1024                           ;; target buffer
  call 1                                   ;; strcmp(1024, 1072)
  ... i32.ne, i32.xor, i32.and ...         ;; returns 1 iff strcmp result == 0
```

```
(data (;0;) (i32.const 1024)
  "xakgK\5cNsn08m?80jj:i;j:m0?klnm<i1:8>iljinu\00\00")
```

So `check_flag()` returns `1` exactly when, for every character, `(input[i] XOR 8) ==
target[i]`, where `target` is the literal byte string embedded at memory offset `1024`. Solving
for the input just requires XOR-ing the target bytes with `8` (the operation is its own
inverse).

## Proof of Concept

```python
target = bytes([ord('x'),ord('a'),ord('k'),ord('g'),ord('K'),0x5c,ord('N'),ord('s'),ord('n'),
                 ord('0'),ord('8'),ord('m'),ord('?'),ord('8'),ord('0'),ord('j'),ord('j'),
                 ord(':'),ord('i'),ord(';'),ord('j'),ord(':'),ord('m'),ord('0'),ord('?'),
                 ord('k'),ord('l'),ord('n'),ord('m'),ord('<'),ord('i'),ord('1'),ord(':'),
                 ord('8'),ord('>'),ord('i'),ord('l'),ord('j'),ord('i'),ord('n'),ord('u')])
print(''.join(chr(b ^ 8) for b in target))
# picoCTF{f80e708bb2a3b2e87cdfe4a9206adbaf}
```

Verified directly against the real module (Node's built-in `WebAssembly` runtime) before
submitting, so the flag never had to be guessed through the browser UI:

```js
const { instance } = await WebAssembly.instantiate(fs.readFileSync('aD8SvhyVkb.wasm'));
const flag = "picoCTF{f80e708bb2a3b2e87cdfe4a9206adbaf}";
for (let i = 0; i < flag.length; i++) instance.exports.copy_char(flag.charCodeAt(i), i);
instance.exports.copy_char(0, flag.length);
console.log(instance.exports.check_flag()); // 1
```

## Root Cause

The flag validation logic and the reference value it checks against both ship to the client in
full. Wrapping the check in WebAssembly and XOR-obfuscating the string only adds friction to
static analysis, not an actual barrier: the XOR key and the encoded target bytes are both present
in the same 864-byte module, so recovering the flag is a direct, deterministic decode rather than
a brute-force or guessing exercise.

## CWE / OWASP

- **CWE-602**: Client-Side Enforcement of Server-Side Security (the entire validity check runs
  and is fully derivable in the browser)
- **CWE-656**: Reliance on Security Through Obscurity
- **OWASP A08:2021**: Software and Data Integrity Failures
