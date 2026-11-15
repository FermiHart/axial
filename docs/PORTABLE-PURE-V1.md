# Portable pure v1: bounded boolean policies for JavaScript hosts

This is an additional, deliberately narrow Axial execution profile. The
native C compiler still parses, checks and compiles the `.axi` source. A build
tool exports its actual register instruction words. A small JavaScript VM
executes those words in a browser or Node.js. Application policy is not copied
or translated into a second JavaScript implementation.

This profile does not replace or change the frozen embed-v1 ABI, AXB v7,
checker identity, or the language-only beta declaration. It provides no new
effect authority, signing claim, network protocol, or persistence guarantee.

## Exact admitted subset

* One `pure` cell, one `bool` result, zero laws, errors, capabilities, effects,
  builtins and calls. The application chooses to treat the boolean as policy.
* Zero to sixteen named `bool` parameters. Truthiness and coercion are refused.
* At most 32 registers, 32 constants and 128 instruction words.
* Constants are only `u64 0` and `u64 1`, used by the real compiler to construct
  boolean literals. No numeric policy arguments, arithmetic, strings or JSON.
* Real AXB opcode IDs: NOP=0, LDK=1, MOV=2, NOT=8, EQ=9, JMP=12, JF=13,
  RET=15, HALT=22. Every admitted opcode has native cost one.
* Forward in-range jumps only. Backward jumps, self-loops and calls are
  refused. Unused operand bytes must be zero. Register and constant indices
  are validated before execution.
* Declared fuel is 1..4096. Each invocation explicitly supplies integer fuel
  0..4096; the effective budget is its minimum with the declared ceiling.
  Fuel is charged before execution. The unaffordable instruction is not
  executed or charged. Zero fuel traps with zero consumption.

The coordinator runs the actual `axi check` gate; the C exporter also compares
the exact source snapshot with `axi_canon_render` before type checking and
compilation. The C exporter validates the full compiler contract and this subset.
The JavaScript runtime independently validates the exported shape and copies
all admitted fields before running. Accessor properties, malformed arrays,
unknown fields, unknown instructions, and noncanonical inputs are refused.
Output is always explicit: `allow`, `deny`, `trap`, or `refused`.

## Build and differential verification

Requirements: the existing C99/POSIX toolchain plus Node.js for this profile's
coordinator and tests. No Emscripten, WASM compiler, npm package or network
download is required.

```sh
node tools/portable-policy-build.cjs tests/portable-policy/access.axi build/access.json
node --test tests/portable-policy-differential.cjs
AXIAL_POLICY_SOURCE=/absolute/path/application.axi node --test tests/portable-policy-differential.cjs
```

The native oracle compiles the same source and runs the real C VM on the
verified compiler model. It compares every boolean combination for up to
eight parameters, every fuel budget from zero through the smaller of 256 and
the declared maximum, and 4096 to exercise the declared ceiling. Results,
allow/deny, consumption and exhaustion must agree exactly. The oracle uses an
internal pure VM function only for these locally compiled test models; it is
not a new artifact admission interface.

The built exporter is `build/portable-policy-export`. Its `export` subcommand
writes the JSON artifact; `oracle` emits JSONL comparison cases. Repeating an
export for identical source and core yields identical bytes.

## Host API and trust boundary

The browser global is `AxialPortablePureV1`; CommonJS exports the same API.

```js
const verdict = AxialPortablePureV1.evaluate(program, {
  identityKnown: true,
  resourceAllowed: true,
  available: true
}, {fuel: 64});
// Proceed only after the native owner checks verdict.ok && verdict.allowed.
```

`validate(program)` validates the bounded executable shape. `evaluate()`
returns `ok`, `allowed`, `outcome`, `code`, `fuelUsed`, `fuelLimit`, `profile`,
`sourceSha256`, `ifaceHash`, `bodyHash`, and `entry`. The program's format is
`axial.portable-pure.v1`; the same value appears as `verdict.profile`.

`sourceSha256`, `ifaceHash`, `bodyHash`, `compilerSourceRevision` and
`compilerSourceDigest` describe build provenance. The revision records the
original C core baseline; the digest records the current exact C/header bytes.
Its recipe is SHA-256 over `axial.portable-core.v1\n` followed, in sorted path
order, by `path + NUL + SHA256(file bytes) + LF` for every `.c` and `.h` file
under `src`, `include`, and `vendor`. It is source identity, not executable or
toolchain identity. The build refuses source changes while make is running.
**These fields are not runtime-verified signatures.** This JSON is
not signed AXB and is not a CHECKED certificate. The host must pin and deliver
the artifact and VM together through its existing trusted build/deployment
path. An altered program can change policy; merely keeping its declared hash
does not authenticate it. An authenticated transport or package digest has
its own trust assumptions and does not turn an editable client into authority.

The host supplies facts from its own authoritative state, validates that state
again when committing an operation, and owns identity, permission, reservation,
idempotency, persistence and effects. A client-side result cannot authorize
global money, ownership or supply. Errors and exhausted budgets deny the
requested operation. Fuel bounds these admitted instructions; it is not a
universal whole-process memory or wall-clock bound.

## Deliberately deferred work

Rich values, reason codes carried by policies, 64-bit checked monetary
arithmetic, call graphs, scheduling, signed admission, host capabilities and
WASM require separate profiles and validation. They must not be silently
enabled by accepting unknown fields or instructions in v1. The original C
VM and embed-v1 remain the larger language/runtime surfaces.
