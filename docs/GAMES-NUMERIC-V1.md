# Games numeric v1: checked host helper

`runtime/games-numeric-v1.cjs` is an additive Node/CommonJS helper for game
adapters. It is **not** a new Axial bytecode profile, compiler feature, native
ABI change, sandbox or proof that a client is honest. It does not change the
existing boolean portable VM or native numeric wrap semantics. Authoritative
facts and atomic world changes remain the responsibility of the server host.

## Contract

Inputs are primitive canonical decimal strings for signed 64-bit integers:
`-9223372036854775808` through `9223372036854775807`. No leading zeroes,
whitespace, exponent, plus sign, negative zero, Number or BigInt wire values
are accepted. Internal bounded BigInt arithmetic avoids Number precision loss.
Results are frozen `{ok:true,value:string}`; `compare` instead returns the
numeric ordering `-1`, `0` or `1`. Failures are frozen `{ok:false,code}` with
`AXN-INPUT`, `AXN-OVERFLOW`, `AXN-ZERO` or `AXN-PRECISION`.

- `add`, `sub`, `mul`, `div` check output i64 range. They never wrap or saturate.
- `div` truncates toward zero; zero divisor fails, including fixed division.
- Fixed-point amounts are scaled i64 integers, with an explicit integer scale
  from 0 to 9. Callers must use the same unit and scale; neither is inferred.
- `fixedMul(a,b,s)` computes `trunc(a*b/10^s)` with exact intermediates.
- `fixedDiv(a,b,s)` computes `trunc(a*10^s/b)` with exact intermediates.
- `rescale(a,from,to)` multiplies with overflow detection when raising precision,
  truncates toward zero when lowering it. Loss of precision is intentional here.
- `parseDecimal(text,s)` rejects excess fractional digits, even trailing zeroes;
  it does not silently round. Negative zero is invalid. `formatDecimal(a,s)`
  prints exactly `s` fractional digits. Formatting then parsing is lossless.

For monetary rules, choose a documented unit, use checked outcomes, and refuse
on error. Do not convert a failure to zero or permission. This module does not
choose a legally appropriate rounding rule or prevent stock/balance races.

## Resource bounds and tests

Integer strings are limited to 20 characters before regex/BigInt parsing;
decimal display strings to 30. No coercion hooks or caller-supplied callbacks
are invoked. Scale is capped before exponent lookup; operations have no loops
dependent on numeric magnitude. Arithmetic intermediates are bounded by two
i64 operands or one i64 and `10^9`. There are no collections or batch APIs.
This does not bound the number of evaluations a hostile caller requests: the
host must impose request, memory and tick budgets.

Run `node --test tests/games-numeric-v1.test.cjs`. It covers boundaries,
canonical input, hostile coercion, exact arithmetic, negative truncation,
all-scale roundtrips and a seeded 2,000-pair exact oracle corpus. It is not a
C/JS differential VM gate. A compiler-integrated quantitative profile still
needs independently specified opcodes, native implementation and cross-runtime
conformance tests before it can be claimed.

## Independent host arithmetic differential gate

`node --test tests/games-numeric-differential.test.cjs` compiles
`tools/games-numeric-oracle.c` with `CC` (default `cc`) and requires GCC/Clang
signed `__int128` support. It compares **11,362 cases** against the JavaScript
helper: add/subtract/multiply/divide, fixed multiply/divide and rescaling,
including i64 extremes, zero divisors, malformed integer strings, scale bounds,
overflow, negative truncation and a seeded 1,000-pair full-width i64 corpus.
The oracle uses independently implemented parsing and C arithmetic; its largest
arithmetic intermediate fits signed 128 bits. Temporary binaries are removed.
Compiler absence or lack of `__int128` fails the gate rather than silently
counting a skipped comparison as success.

This gate validates **checked host helper semantics only**. The C oracle is not
the Axial compiler or VM, and this test does not establish native/portable VM
parity, a new language profile, or determinism across all architectures.
