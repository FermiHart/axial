# Audit80 — source semantics and numeric implementation

Changes are confined to Axial. Frozen embed v1 layout and existing opcode
numbers/meanings are preserved. Source errors are named atoms without an
arbitrary payload; v7 returns them as the existing scalar error kind.

## W51 — error atoms are executable values

`err.Name` was accepted by the checker but rejected by source codegen.
Codegen now owns/deduplicates a separate KERR pool namespace, preserving
error identity through local bindings and branch returns. Error expressions
are validated against the same bounded manifest-name rule as declarations.
String constants containing the same bytes remain strings. No implicit
conversion between error, string, false, ok or trap is introduced.

Validation: `python3 tests/audit80/frontend.py build/axi errors` compiles signed
artifacts and runs direct/bound/dotted errors and string results through the
real v7 VM; undeclared and invalid atoms refuse without publishing an artifact.

## W52 — source option returns match the frozen v7 representation

The checker now annotates each return as plain, payload arm or ok arm.
Codegen uses this note to emit tagged options; named errors remain scalar
errors. The admitted payload type tags precede OK in the frozen manifest,
so source declaration order does not change arm identity. No new opcode is
needed and boolean false remains a payload, distinct from the ok arm.

Validation: `frontend.py build/axi returns` executes both arms for all seven
admitted payload types, both source declaration orders and bound values.

## W53 — explicit propagation of named errors

`?` now carries the callee's checked return shape into codegen. It compares
each possible source error atom and returns that exact scalar error before
evaluating subsequent expressions. This uses existing EQ/JF/RET semantics;
UCHK is deliberately not repurposed, because its bytecode union convention
does not represent v7 scalar errors. Error-only calls have no continuing
path and retain a defensive HALT. The new AST shape pointer borrows the
existing signature and allocates no extra object.

Validation: `frontend.py build/axi result` covers nested/reordered error sets,
multiple call operands, error propagation before a later division trap,
error-only calls and unhandled/undeclared/nonunion refusals.

## W54 — option propagation and composition

After named errors are handled, `?` inspects an option's canonical arm. A
payload is unwrapped in its owned temporary; ok returns the caller's checked
representation, including plain UNIT when the caller has no payload. This
supports different caller/callee payload types without guessing by kind.
No VM instruction or existing UCHK meaning changes.

Validation: `frontend.py build/axi options` covers options mixed with errors,
plain-ok callers, bool false in conditions, nested call arguments with live
bindings, recursion, short-circuit before a trap and undeclared ok refusal.

## W55 — text-string contract v1

The five escapes advertised by the lexer now have one semantic decoder:
`\n` is LF, `\t` is TAB, `\0` is NUL, `\\` is backslash, and `\"` is quote.
Unknown escapes and unrepresentable controls refuse instead of passing
through. Length-aware source codegen and AXS emission use the same byte
encoder, so LF/TAB/NUL survive assembly, signed v7 storage and disassembly.
The allocation-free length and decode-into APIs support the root compiler
budget without a global allocator context. Invalid inputs/capacity leave
caller outputs unchanged; embedded NUL is never treated as string length.

**Migration:** the earlier two-escape implementation interpreted `"\n"`,
`"\t"`, and `"\0"` as two literal bytes. To retain those old bytes, rewrite
them as `"\\n"`, `"\\t"`, and `"\\0"` before recompiling with text-string v1.
Existing binary string bytes are not rewritten. Source/AXS text meaning has
intentionally changed; the final checker identity and migration notes must
identify this revision rather than silently reusing the previous identity.

Validation: `frontend.py build/axi strings`; compile `frontend_strings.c`
with `axi_lex.c`, `axi_diag.c`, and `axi_alloc.c` for exact bytes, sentinel
preservation, insufficient capacity, invalid escapes and overlap refusal.

## W56 — canonical strings and complete source representation contract

Canonicalization now uses the shared byte escape mapping instead of copying
the raw lexeme. In particular raw TAB and `\t` have identical canonical text
and decoded bytes. This path validates without an intermediate allocation.
SPEC-GRAMMAR now explicitly defines error constructors, bounded names,
left-to-right early propagation and the v7 scalar/tagged return distinction.
Text-string v1 is a documented semantic revision, not an assertion that the
old implementation already decoded the five advertised escapes correctly.

Validation: `sh tests/audit80/frontend.sh build/axi` covers W51–W56 together,
UTF-8/control/quote/backslash canonical fixed points, exact binary results,
and all 16 propagated atoms. `make gate-fast` retains the original goldens.
The runner accepts CFLAGS for sanitizers and an explicitly built product
executable. No generic error payload syntax or new authority is added.

## W63 — exact decimal-to-binary64 core

`axi_numeric.c` introduces an original C99 integer-only conversion. It
compares an exact decimal rational against binary64 rounding boundaries,
searches the ordered positive bit patterns, and resolves a midpoint toward
the even significand. It never calls `strtod`, uses floating-point arithmetic,
consults locale/rounding mode, or allocates. A caller-owned workspace contains
all numeric arrays; `AXI_NUMERIC_SCRATCH_BYTES` exposes their simultaneous
size to the compiler quota. The input scan is linear; subsequent arithmetic
has a fixed bound independent of input length. Overflow is a distinct
refusal and does not overwrite output; gradual underflow includes positive
zero. Source sign handling remains a separate frontend operation.

The retained 800 significant digits are **not** an approximate precision
promise. Every nonnegative finite binary64 `M * 2^E` has an upper rounding
boundary `(2*M + 1) * 2^(E-1)`, including zero, the subnormal/normal transition
and the overflow boundary. A boundary's integer significand has at most
54 bits and its negative exponent has magnitude at most 1075. Its exact
decimal significand is therefore smaller than `2^54 * 5^1075 < 10^768`;
positive-exponent boundaries require at most 309 digits. A boundary cannot
lie strictly inside a bucket determined by 800 decimal significant digits.
The scan records whether any discarded digit is nonzero: that sticky bit
changes a boundary comparison only when the retained prefix equals the
boundary. Arbitrarily long zero prefixes/suffixes cannot change this proof.

For relevant magnitudes the retained decimal exponent is between -1123
and 308. Numerators require at most 2658 bits; a power-of-five denominator
times a 54-bit boundary requires fewer than 2664 bits. Each integer has
3072 bits of capacity; larger binary shifts are compared virtually. No
input-sized integer or buffer is constructed. Saturated decimal-position
counters cannot cancel later: before significance only leading fractional
zeroes decrease the position; significant integer digits only increase it.

Validation: compile `tests/audit80/numeric_driver.c` with `src/axi_numeric.c`
using `-std=c99 -Wall -Wextra -Werror -Wpedantic -O1`; run
`python3 tests/audit80/numeric.py build/numeric80-driver`. The 1,996 reader
fixtures include both midpoint parities, smallest subnormals, the normal
transition, overflow, 800/801/1,500-digit inputs and nonzero tails hundreds
of digits beyond exact midpoints. The independent Python oracle retains
the complete integer numerator/denominator and rounds a scaled quotient;
it does not use the production binary search, bounded prefix, `float()`,
libc conversion or a formatter round trip to obtain expected bits.

Numerical background: [Clinger, *How to Read Floating Point Numbers
Accurately*](https://scholarsbank.uoregon.edu/server/api/core/bitstreams/ba79372c-1283-483a-9915-24e45d1417dd/content),
[Burger and Dybvig, *Printing Floating-Point Numbers Quickly and
Accurately*](https://www.burgerrg.com/FP-Printing-PLDI96.pdf), and
[David Gay's original dtoa implementation](https://www.netlib.org/fp/dtoa.c)
explain why a correct reader and a correct printer must agree on rounding
boundaries. No code from those implementations was imported.

## W64 — the source lexer uses the exact reader

The lexer now loads the integer reader's exact bits with `memcpy`; no host
arithmetic rounds each fractional digit. Float integer parts may exceed
u64, so maximum finite binary64 values are expressible in the existing
plain-decimal grammar. Integer-token overflow remains AXI-L005. A decimal
that would round to infinity reports AXI-L006 and cannot publish a compiled
artifact; subnormal underflow rounds to zero. The source token consumes the
whole numeric spelling and preserves the separate trailing-junk diagnostic.
Build-time checks reject host `double` formats other than binary64; like
the existing VM, storage requires IEEE encoding in native integer byte order.

**Migration — decimal-f64 profile v1:** some previously accepted decimal
sources intentionally produce corrected bits. In particular the old digit
accumulator read `0.3` one ulp above its nearest binary64 value. Existing
binary constants are unchanged. To preserve an old artifact's bits during
recompilation, recover those bits and use the new bit-derived canonical
decimal spelling; simply retaining an old decimal lexeme is not evidence
of identical meaning. The checker identity must identify the new source
semantics. No exponent, NaN or infinity source syntax is added.

Validation: `sh tests/audit80/numeric.sh` runs the same 1,996 independent
reader expectations both directly and through the actual lexer. All lexer
standalone runners now link `axi_numeric.c`. The existing 67 golden tests
remain a separate gate; new tests compare bits, not libc diagnostic printing.

## W65 — unique shortest canonical decimal from bits

The numeric core now renders any finite binary64 bit pattern, including
negative zero, using only integers. It first derives the exact finite
decimal expansion of the dyadic value, then examines decimal grids with
1 through 17 significant digits. For each grid it checks the two adjacent
decimals against the target's exact lower and upper rounding boundaries.
The closest admitted candidate wins; an exact distance tie uses an even
scaled decimal coefficient. Trailing coefficient zeroes are then removed,
and the result is expanded into the existing grammar with a decimal point
and no exponent. The result depends only on bits, never on the old lexeme.

These are exhaustive decisions for each grid: an interval containing the
value can contain a grid point only if it contains one of the two adjacent
points. At a decimal decade boundary, any admitted candidate in a different
decade has the intervening power of ten closer to the value; that power is
already a one-digit candidate. At powers of two the lower and upper binary
gaps can differ, so the second decimal candidate is necessary. Seventeen
digits suffice: the nearest such decimal has relative error at most
`5 * 10^-17`, less than the smallest relative half-gap `2^-54` for finite
binary64; subnormal intervals are no narrower in relative terms.

The renderer returns a borrowed span in the same explicit workspace. It
has no nested reader invocation, extra output array, dynamic allocation,
libc float formatting or locale dependency. NaNs and infinities refuse
without publishing either output field; every finite bit pattern has a
source spelling. The frozen binary NaN/inf representations are not changed.

Validation: `numeric.py DRIVER format` compares 8,318 bit patterns with an
independent Python `Fraction` oracle that intersects decimal integer ranges
with exact rational rounding intervals. It does not call the production
reader or try the production formatter's two candidates. Fixtures cover
all normal exponent boundaries and their immediate neighbors, subnormal
powers, both zero signs, 2,000 deterministic random values, maximum finite
and nonfinite refusals. Expected canonical strings, exact rational values,
and re-reading the produced decimals are all checked separately.

## W66 — bit-derived canonical source and literal sign lowering

The canonical renderer now passes literal bits to the integer formatter.
The former `%g` candidates, repeated lexing and original-lexeme fallback
are removed. Decimal aliases that produce the same literal bits now have
the same canonical spelling across the complete finite range, independent
of libc formatting. Source grammar documents the precise shortest/closest/
even selection rule and the intentional decimal-f64 v1 migration.

Negating a literal f64 flips its sign bit and emits one constant load.
The old load-positive/load-zero/subtract sequence consumed two unnecessary
instructions and temporaries. A direct negative literal now uses 2 fuel
(LDK + RET) instead of 4; existing opcode costs are unchanged. Nonliteral
negation keeps the typechecked SUB implementation. No host floating-point
operation participates in source literal lowering.

**Signed-zero boundary:** the numeric reader/formatter and constant pool
preserve IEEE literal representation, so negative underflow and `-0.0`
have negative-zero bits in the pool. The existing VM deliberately normalizes
negative zero to positive zero on import, load and arithmetic, and still
does so. Consequently executed `-0.0` returns positive zero. This is an
explicit distinction between source/constant representation and VM values;
the numeric work does not silently change that frozen runtime contract.

Validation: `numeric_cli.py build/axi` runs 46 signed-literal cases through
canonicalization, strict checking, signed v7 compilation and the real VM.
It compares aliases and canonical fixed points with independent expected
strings, inspects raw constant bits, checks the 2-fuel negative-literal path,
and reassembles disassembly. It also exercises nonliteral/double negation,
existing runtime NaN/inf/zero rules, and overflow/junk/u64 refusals with
preexisting-output preservation. `make gate-fast` passes all 67 goldens.

## W67 — reuse exact formatter work

The formatter now constructs one power of five per value, reuses it for
both adjacent candidates, and updates it by one exact multiply/divide when
the precision changes. The positive decimal exponent path scales the
numerator; the negative path uses the same object as a denominator. The
boundary comparator explicitly distinguishes these cases. The exact
decimal expansion also divides by `10^9` per chunk instead of `10`, with
nine-digit padding on nonleading chunks. This removes repeated wide
division without changing the exact value or allocating another buffer.

Validation retains the 1,996 exact reader cases and all 8,318 independent
canonical expectations. `numeric_bench.c` consumes every result into a
deterministic checksum and covers all exponent fields. `numeric_bench.py`
records one warmup and seven alternating pairs on an explicitly pinned CPU,
identical compiler flags, source/binary SHA-256, complete raw samples and
ranges. The baseline is the already-correct W65 numeric core; these timings
do not claim equivalence with the former incorrectly rounded lexer or an
end-to-end compiler speedup. Final measurements include W68 below.

## W68 — exact short-decimal path and environmental limits

Short decimals now bypass multiprecision search when their complete
coefficient fits uint64 and powers of five can be represented or fully
cancelled. The remaining exact `m * 2^e` is rounded once by integer quotient,
remainder and an even-significand tie. Carry into the next binary exponent
is explicit. The admitted decimal exponent range of this shortcut is
[-27,27], so its nonzero values are normal binary64 and cannot suffer a
second subnormal rounding. Every other input uses the exact W63 path.
There is no approximate candidate, host float operation or weaker fallback.

The final reader suite has 3,785 expectations, adding every uint64 width,
rounding carries, cancellation boundaries, successful short paths and
immediate fallback neighbors to the earlier long-input tests. The formatter
still passes 8,318 independent interval expectations. `numeric_limits.c`
also checks all four standard rounding modes while preexisting floating-
point exception flags are raised; reader, formatter and lexer preserve
both the mode and those flags. It tests all available locale names from
C/POSIX/C.UTF-8/German/French and reports how many use a non-dot separator,
so an unavailable locale is not presented as evidence. The local audit
generates German and French locales in its build directory for the comma
separator cases; they are optional test infrastructure, not product
dependencies.

One-MiB tests exercise exact midpoints, a nonzero digit after a million
discarded zeroes, a tail of nines just below a midpoint, overflow, tiny
underflow, leading integer zeroes and final-byte syntax refusal. Output
sentinels, null-argument refusals, nonfinite formatter refusals, and complete
1-MiB scans are checked. Numeric workspace remains **2,372 bytes** on the
tested C99 ABI, exposed via `sizeof` rather than a guessed constant.

### Final measured helper cost

The final paired run compares the exact W65 numeric source with W67–W68.
Both binaries used GCC 13.3.0, C99, `-O1 -Wall -Wextra -Werror -Wpedantic`,
CPU affinity `{0}`, one warmup per workload/binary and seven alternating
pairs. The timed region uses C `clock()` process CPU time, with no timed
I/O. Every warmup and sample matched the workload's output checksum.

| Workload | W65 median (range), ms | W68 median (range), ms | Median change |
|---|---:|---:|---:|
| 8,192 formatted values, all exponent fields | 453.746 (435.144–470.197) | 121.553 (118.503–125.474) | -73.21% |
| 65,536 reads, repeated fixed 16-value mix | 86.569 (84.805–95.057) | 29.346 (28.232–31.109) | -66.10% |

The reader mix includes exact integers/dyadics and decimals that take the
general path; its proportions are explicit in `numeric_bench.c`. The
formatter mixes exponent fields uniformly, which differs from many real
programs. These are descriptive local microbenchmarks, with the ranges
shown, and establish no end-to-end speedup or production latency promise.
Workspace is unchanged at 2,372 bytes. Raw warmups/pairs, compiler identity,
flags and source/binary hashes are emitted by `numeric_bench.py` to the
requested JSON path; the audit's final run is
`build/numeric80-final-benchmark.json` for final evidence integration.

### Reproduction and integration

```sh
make -j2 dev
sh tests/audit80/frontend.sh build/axi
sh tests/audit80/numeric.sh build/axi
sh tests/audit40/frontend.sh build/axi
make gate-fast

make -j2 BUILD=build-numeric-san \
  CFLAGS='-std=c99 -Wall -Wextra -Werror -O1 -D_POSIX_C_SOURCE=200809L -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie' \
  LDFLAGS='-fsanitize=address,undefined -no-pie' dev
# Optional comma locales, when localedef and locale sources are installed:
mkdir -p build/numeric80-locales
localedef --no-archive -i de_DE -f UTF-8 build/numeric80-locales/de_DE.UTF-8
localedef --no-archive -i fr_FR -f UTF-8 build/numeric80-locales/fr_FR.UTF-8
LOCPATH="$PWD/build/numeric80-locales" \
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
CFLAGS='-std=c99 -Wall -Wextra -Werror -Wpedantic -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie -no-pie' \
AXI_TEST_BUILD=build-numeric-san/audit80-numeric \
sh tests/audit80/numeric.sh build-numeric-san/axi
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
CFLAGS='-std=c99 -Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie -no-pie' \
AXI_TEST_BUILD=build-numeric-san/audit80-frontend \
sh tests/audit80/frontend.sh build-numeric-san/axi
```

Standalone lexer tests link `axi_numeric.c`; `numeric_limits.c` additionally
links `-lm` for the test's fenv operations. The numeric implementation itself
has no libm dependency. Both the numeric reader and renderer take an explicit
workspace; the lexer and canonical builder must reserve
`AXI_NUMERIC_SCRATCH_BYTES` through the root compiler quota integration.
The numeric helpers are not recursive and retain no additional arrays.

Limits: this is mathematical reasoning with bounded arithmetic, independent
differential evidence and local sanitizer execution, not a machine-checked
proof or exhaustive enumeration of all 2^64 bit patterns. Actual native
execution was tested on the available binary64 host; no guest, big-endian
hardware or alternative double encoding is claimed. The standalone numeric
core consumes/produces raw uint64 IEEE bits; source/VM double storage keeps
the project's native IEEE layout requirement. The VM's existing arithmetic
and signed-zero/NaN normalization contracts remain separate. LeakSanitizer
is disabled in the reported ASan/UBSan commands; hosted CI is not inferred
from these local results.
