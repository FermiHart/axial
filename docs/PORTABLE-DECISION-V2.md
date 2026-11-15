# Portable decision v2: native typed decisions in JavaScript hosts

`axial.portable-decision.v2` is a separate, bounded execution profile for a
pure policy that returns `ok` or a declared `err.Name`. The existing Axial C
compiler parses, checks and compiles the source. The exporter preserves its
actual instruction words and error constants. The JavaScript VM executes
those words and copies the returned error atom into the decision reason.
Application rules have one implementation, in the `.axi` source.

The original `axial.portable-pure.v1` runtime, exporter, artifact format and
boolean API remain unchanged. The native compiler, checker identity, AXB
format, embed-v1 ABI and language-only beta declaration are also unchanged.
This additional profile does not declare the full language portable.

## Language representation

This is real existing Axial syntax:

```axi
cell decide : fn(identityKnown: bool, resourceAllowed: bool, available: bool) -> ok | err.IdentityUnknown | err.ResourceDenied | err.Unavailable
  fuel 64
  pure
{
  if !identityKnown { ret err.IdentityUnknown }
  if !resourceAllowed { ret err.ResourceDenied }
  if !available { ret err.Unavailable }
  ret ok
}
```

The native manifest contains one regular return, `OK`, plus a separately
declared set of error atoms. In the C VM, `ok` is a `UNIT` value and
`err.Name` is an `ERR` value. Neither is a boolean, numeric enum or union
payload. No new language syntax or opcode was introduced for this profile.

A valid returned `ERR` is an ordinary typed policy denial. It is distinct
from a runtime trap such as exhausted fuel. The order of conditions in the
program determines the first denial reason when several facts are false;
the sorted manifest error list only declares the admitted names.

## Exact admitted subset

| Surface | Limit |
| --- | --- |
| Cells | Exactly one `pure` cell |
| Parameters | Zero to sixteen named `bool` parameters |
| Result | `ok` and one to sixteen declared `err.Name` alternatives |
| Names | One to 63 ASCII identifier bytes; `[A-Za-z_][A-Za-z0-9_]*` |
| Error declarations | Unique, sorted by ASCII byte order |
| Registers | One to 32; at least the parameter count |
| Constants | Up to 32; `u64 0`, `u64 1`, or a declared error atom |
| Instructions | One to 128 native 32-bit words |
| Source | At most 65,536 bytes, canonical form, no NUL, CR or tab |
| Declared fuel | Integer 1..4096 |
| Invocation fuel | Explicit integer 0..4096 |

Real opcode IDs are NOP=0, LDK=1, MOV=2, NOT=8, EQ=9, JMP=12, JF=13,
RET=15 and HALT=22. Each costs exactly one native unit. The exporter checks
these IDs and their native costs. Only forward, in-range jumps are admitted;
self-loops, backward jumps and unknown opcodes are refused. Register and
constant indices and unused operand bytes are checked before execution.

There are no laws, capabilities, effects, builtins, calls, strings, JSON,
numeric arguments, arithmetic, error payloads, tagged unions, tuple values
or collection values. Native `AXB_KERR` constants (wire tag 5) contain only
the exact error atom. Native `AXB_KU64` constants (wire tag 1) are limited to
zero and one because the compiler uses them to construct boolean literals.
A numeric zero returned by the program is not accepted as `ok`.

The compiler implements `ret ok` using an untouched register whose native
initial value is `UNIT`. The portable VM preserves that initialization;
it must not substitute boolean false or treat this register as a trap.
An actual RET of UNIT permits, and an actual RET of a declared ERR denies.
HALT, falling off the instruction list, wrong return kinds and invalid
payload shapes never create an affirmative result.

Fuel is charged immediately before each instruction. The effective budget
is the smaller of the requested budget and the declaration. An instruction
that cannot be afforded is neither executed nor charged. Zero fuel traps
with zero consumption. These bounds describe the admitted VM instructions,
not a universal memory or wall-clock budget for the JavaScript process.

## Artifact schema

The JSON object has exactly these fields:

```js
{
  format: 'axial.portable-decision.v2',
  compilerSourceRevision: '<40 lowercase hexadecimal characters>',
  compilerSourceDigest: '<64 lowercase hexadecimal characters>',
  sourceSha256: '<64 lowercase hexadecimal characters>',
  ifaceHash: '<64 lowercase hexadecimal characters>',
  bodyHash: '<64 lowercase hexadecimal characters>',
  entry: 'decide',
  fuelMax: 64,
  params: ['identityKnown', 'resourceAllowed', 'available'],
  returnType: {
    kind: 'result',
    ok: 'unit',
    errors: ['IdentityUnknown', 'ResourceDenied', 'Unavailable']
  },
  registers: 6,
  constants: [
    {kind: 'u64', value: 0},
    {kind: 'error', atom: 'IdentityUnknown'},
    {kind: 'error', atom: 'ResourceDenied'},
    {kind: 'error', atom: 'Unavailable'}
  ],
  code: [/* exact uint32 words produced by the native compiler */]
}
```

`returnType.kind` describes the exported decision contract; it does not add
a named `result` type to Axial syntax. Error atoms exclude the source
prefix `err.`. There is no error-number lookup table or implicit case
normalization. An unknown, misspelled or undeclared atom is refused.

Both nested schemas are closed: the only constant objects are
`{kind:'u64',value:0|1}` and `{kind:'error',atom:'DeclaredName'}`. A `payload`,
numeric tag, extra return field or alternative constant kind is refused,
including an empty payload field. Arrays must contain only their indexed
data properties and length. Accessors, missing elements, noncanonical
numbers, duplicate names and unknown program fields are refused.

The runtime takes bounded copies of the program, nested return declaration,
constants, instruction words and facts before execution. Property accessors
are not invoked. Array length is captured once from its descriptor to keep
mutable inputs from changing a validated bound. Host JavaScript Proxies may
execute their own traps during inspection; this is not a sandbox for
arbitrary hostile JavaScript already running in the same realm.

## Host API

Browser global: `AxialPortableDecisionV2`. CommonJS exports the same object.

```js
const verdict = AxialPortableDecisionV2.evaluate(program, {
  identityKnown: true,
  resourceAllowed: false,
  available: true
}, {fuel: 64});

// A normal policy denial, returned by the compiled program:
// verdict.ok === true
// verdict.allowed === false
// verdict.outcome === 'deny'
// verdict.code === 'AXP-DENY'
// verdict.decision === {kind: 'deny', reason: 'ResourceDenied'}
```

Every result is frozen and contains `ok`, `allowed`, `outcome`, `code`,
`fuelUsed`, `fuelLimit`, `profile`, `sourceSha256`, `ifaceHash`, `bodyHash`,
`entry` and `decision`. When present, the nested decision is also frozen.

| Outcome | `ok` | `allowed` | `decision` |
| --- | --- | --- | --- |
| `allow` | `true` | `true` | `{kind:'allow'}` |
| `deny` | `true` | `false` | `{kind:'deny',reason:'DeclaredName'}` |
| `trap` | `false` | `false` | `null` |
| `refused` | `false` | `false` | `null` |

`AXP-ALLOW` and `AXP-DENY` identify valid decisions. `AXI-R008` identifies
fuel exhaustion, `AXI-R001` a halt or falloff, `AXI-R004` a runtime operand
type error, and `AXI-R025` an invalid returned kind. Profile, fuel and
argument refusals use `AXP-P001`, `AXP-F001` and `AXP-A001`; a thrown
inspection failure uses `AXP-I001`. No trap or refusal invents a reason
that the policy did not emit.

`validate(program)` checks this executable shape and returns a boolean.
`profile` and `maxFuel` are also exported. The only execution option is
`{fuel}`; facts must have exactly the declared keys and boolean values.
No truthiness, coercion, default budget or unrecognized context fields are
accepted. Invocation identity, revisions and lifecycle belong to a separate
host context layer; they are not encoded as arbitrary extra VM options.

## Build and native differential verification

Requirements are the existing C99/POSIX toolchain and Node.js. No npm
dependencies, browser compiler, WASM toolchain or download is required.

```sh
node tools/portable-decision-build.cjs tests/portable-decision/access.axi build/decision.json
node --test tests/portable-decision-differential.cjs
AXIAL_DECISION_SOURCE=/absolute/path/application.axi node --test tests/portable-decision-differential.cjs
```

The builder runs the actual `axi check` gate. The C exporter also compares
its source snapshot with `axi_canon_render`, type-checks it, compiles the
native contract, verifies that contract and validates the portable subset.
`build/portable-decision-export export source.axi` emits the JSON artifact;
its `oracle` subcommand runs the actual C VM and emits JSONL test cases.
Identical source and compiler core produce identical artifact bytes.

The differential test covers every boolean combination for up to eight
parameters, every fuel budget from zero through the smaller of the declared
maximum and 256, and a request for 4096 to exercise the declared ceiling.
The actual returned decision and exact reason, success flag, fuel usage,
effective limit and exhaustion must match. A second compiled policy changes
condition order, uses boolean literals and returns unrelated reason names
to check that reasons come from executed error constants.

Additional tests exercise malformed schemas, payloads, return kinds,
instruction bounds, canonical source, mutable inputs and browser loading.
The v1 artifact regression pins the original generic fixture's exported
bytes. The unchanged v1 differential and adversarial suites remain separate
gates. When running suites that build their native exporters, sequence them
or use `node --test --test-concurrency=1` to avoid concurrent relinking of the
same binary. These tests use an internal pure VM function solely for
locally compiled, verified models, not as a new artifact admission API.

## Provenance, authority and compatibility

`compilerSourceRevision` identifies the original core baseline.
`compilerSourceDigest` records the exact C/header source bytes using the
existing `axial.portable-core.v1` digest recipe documented in
[PORTABLE-PURE-V1.md](PORTABLE-PURE-V1.md). Source, interface and body hashes
describe the source and native compiled contract.

**These fields are provenance, not runtime-verified signatures.** The JSON
artifact is not signed AXB, an embed-v1 admission object or a CHECKED
certificate. The runtime checks shape, not the truth of an editable hash
field. A changed instruction can change a decision while retaining a
declared hash. Hosts must pin the artifact, runtime and exporter through
their existing trusted build and deployment path.

The application supplies facts from authoritative state, checks the state
again at commit time, handles replay and stale requests, and performs all
effects. An allowed client-side policy cannot confer ownership, change
global supply, move money or authorize a multiplayer operation. A normal
typed denial can be translated for presentation without duplicating the
rule that produced it. Unknown reasons, traps and refusals must not grant
the requested operation.

Future numeric or richer result profiles require explicit new validation,
compiler/exporter support and native differential tests. V2 does not
silently enable such features in either v2 or v1, and no performance claim
for rendering, physics or hot gameplay loops follows from this policy
integration.
