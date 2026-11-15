# Portable numeric v1 (experimental)

`axial.portable-numeric.v1` executes actual words produced by the existing
Axial C compiler, not translated game rules. It is an additive, deliberately
narrow numeric profile. `portable-decision-v2`, the native VM, and the frozen
embedding ABI are unchanged.

## Build and use

```sh
node tools/portable-numeric-build.cjs tests/portable-numeric/add.axi /tmp/add.json
node --test tests/portable-numeric-differential.test.cjs
```

The build tool compiles the existing compiler core and a separate C exporter.
The exporter requires canonical source, type-checks it, generates and verifies
its contract, then checks this profile. It emits source, interface and body
hashes, the current checkout revision and the digest of compiler source files.
These are provenance fields, **not authenticated signatures**. A trusted host
must admit the actual bytes/digest from its own allowlist or signature policy.

In Node, require `runtime/portable-numeric-v1.js`; browsers receive
`globalThis.AxialPortableNumericV1`. Call:

```js
runtime.evaluate(program, {a: '9223372036854775807', b: '1'}, {fuel: 64});
// ok:true, outcome:'value', value:'-9223372036854775808', ...
```

## Semantics and bounds

- One pure cell, no capabilities, laws, errors, calls, effects, strings, floats,
  clock, RNG, allocation instructions or loops. Forward conditional branches
  are supported. Up to 16 named i64 inputs, 32 registers, 32 constants,
  128 instructions and 4,096 fuel. Return type is exactly i64 or bool.
- Inputs and i64 outputs use canonical signed decimal **strings**, never
  JavaScript Number. Inputs range from `-9223372036854775808` to
  `9223372036854775807`; no leading zeroes, plus signs or negative zero.
- i64 add/subtract/multiply **wrap modulo 2^64**, exactly like the native VM.
  Division truncates toward zero; `INT64_MIN / -1` wraps to `INT64_MIN`, and
  its remainder is zero. Division/remainder by zero trap `AXI-R003`.
- Compiler-emitted u64 constants 0/1 are admitted. Internal u64 arithmetic
  wraps unsigned; mixed numeric kinds trap. This supports internal compiler
  expressions without allowing u64 external parameters or results.
- Equality follows native kind/value equality; ordering requires matching
  numeric kinds. Conditions require bool. Uninitialized registers are UNIT,
  not numeric zero; malformed dynamic kinds trap rather than coerce.
- Cost is charged before each instruction: multiply costs 2, division/remainder
  cost 4, all other admitted instructions cost 1. An insufficient budget does
  not execute the instruction. The cell ceiling also applies.
- Results distinguish `value`, `trap`, and `refused`; there is no `allowed`
  flag. A computed bool is not an authorization to mutate world state.

This is **not checked fixed-point arithmetic**. It intentionally preserves
native modular semantics. The separate `games-numeric-v1.cjs` host helper
rejects overflow. Money/stock policies must explicitly guard ranges or use
checked host primitives and authoritative transactions. Do not silently switch
between the two semantics or claim fixed-point language integration.

## Security boundary and evidence

The structural validator rejects unknown fields/opcodes, out-of-range registers
and constants, backward/outside jumps and oversized arrays. Runtime checks
dynamic kinds and the declared return contract. Descriptors are inspected
without invoking getters. This does not isolate hostile Proxy objects or code
running in the same JavaScript realm; consume bounded serialized input from
outside that realm and apply host quotas. Fuel excludes JSON parsing, snapshot
validation, host scheduling and other surrounding work.

The differential gate compiles eleven source fixtures, then compares **16,500
evaluations** with `axi_vm_run_contract_cell_preverified_pure_scoped_diag` in
the real C VM. It compares values, success, fuel used/limit and exhaustion,
including signed endpoints, negative operands, zero divisors, overflow,
forward branches, internal unsigned expressions, and seeded full-width values.
Adversarial tests also cover malformed structures, types and fact encoding.

The oracle executable accepts two i64 fixture parameters over bounded stdin
lines. This is test infrastructure only, not a runtime admission service.
The comparisons establish evidence on the tested host/compiler/JS engine;
they are not an ARM/browser matrix, production deployment, signed-AXB loader,
general sandbox certification or complete anti-cheat solution.
