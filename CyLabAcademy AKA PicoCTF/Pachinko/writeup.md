# Pachinko

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{p4ch1nk0_f146_0n3_e947b9d7}`

## Summary

The server implements a fully custom CPU (a Verilog design synthesized to a gate-level netlist
and executed bit by bit through a Rust/WASM simulator). The `/check` endpoint lets a client submit
a "circuit," a list of NAND gate connections, which gets fed as data memory to a binary
(`nand_checker.bin`) that itself runs on that custom CPU to grade whether the submitted circuit
correctly inverts four random boolean inputs. Rather than reverse engineering the CPU's
instruction set or the checker binary directly, the exact wire numbering convention the checker
expects is fully exposed in the provided source's leftover frontend demo, which builds
`{input1, input2, output}` entries using a fixed ID scheme: output pins are IDs 1-4, and input
pins are IDs 5-8.

## Discovery

`server/index.js`'s `/check` handler generates 4 random boolean values (`0x0000` or `0xffff`)
as `inputState`, computes `outputState` as their logical inverse, serializes both into memory
alongside the attacker-supplied `circuit` array, and runs the whole thing through
`nand_checker.bin` on the custom CPU via `runCPU()`. Success is `memory[0x1000] == 0x1337`
after execution, meaning `nand_checker.bin` itself is the grader, not the Express server.

`server/utils.js`'s `serializeCircuit` shows each circuit entry is written as three raw 16-bit
values (`input1`, `input2`, `output`) with no documented meaning attached server side, and
`checkInt` only enforces `1 <= value <= 0xFFFF`, giving no clue what a *valid* address actually
is. However, `server/public/index.html` (an interactive NAND-gate builder UI, seemingly a
development/demo tool bundled with the same source) shows exactly how a valid circuit is meant
to be assembled:

```javascript
if (type === 'output') {
    node.dataset.nodeId = (outputNodes.length + 1).toString();  // outputs: 1-4
} else {
    node.dataset.nodeId = nextNodeId.toString();                 // everything else
    nextNodeId++;
}
```

`resetGame()` sets `nextNodeId = 5` after creating the 4 output nodes (IDs 1-4), then
immediately creates 4 input nodes, which take IDs 5-8. Any further "intermediate" (NAND gate)
nodes added afterward would start at ID 9. Each gate submitted to `/check` is
`{input1: <source node id>, input2: <source node id>, output: <this gate's own id, or 1-4 if it
feeds a circuit output>}`.

## Proof of Concept

Since the required transformation is a bitwise NOT of each input, and `NAND(x, x) == NOT x`,
four gates that each NAND an input pin with itself, writing directly to the matching output pin,
is a complete solution with no intermediate nodes needed:

```
curl -s -X POST http://TARGET/check \
  -H "Content-Type: application/json" \
  -d '{"circuit":[
    {"input1":5,"input2":5,"output":1},
    {"input1":6,"input2":6,"output":2},
    {"input1":7,"input2":7,"output":3},
    {"input1":8,"input2":8,"output":4}
  ]}'
```

```json
{"status":"success","flag":"picoCTF{p4ch1nk0_f146_0n3_e947b9d7}\n"}
```

## Root Cause

Not a traditional vulnerability so much as an information leak in the provided challenge
material: the backend's internal wire-addressing protocol has no documentation of its own, but
the same source bundle ships a frontend tool that implements the identical protocol in plain,
readable JavaScript, making the "hard" reverse-engineering problem (a custom CPU ISA and a
compiled checker binary) unnecessary to actually solve directly.

## CWE / OWASP

- **CWE-1295**: Debug Messages Revealing Unnecessary Information (bundled dev/demo tooling
  exposing an internal protocol)
- **OWASP A05:2021**: Security Misconfiguration
