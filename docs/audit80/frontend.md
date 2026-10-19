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
