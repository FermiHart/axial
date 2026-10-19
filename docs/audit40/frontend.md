# Axial audit40 — compiler and JSON workstream

Scope: W01–W10, based on the repository revision selected for audit40.
The public embed v1 header, bytecode wire IDs, capability vocabulary and
external projects are unchanged. Performance claims require matched builds;
the fixtures below also run against the audit baseline.

## W01 — bounded diagnostic work after saturation

**Problem.** Every invalid source byte asked `axi_diag_add_source` to scan
the entire preceding source, even after its 64-entry output was full.
A long invalid input therefore consumed quadratic CPU while retaining
only 64 diagnostics. The dropped counter could also overflow signed `int`.

**Change.** Stop coordinate work when the set is full, while preserving the
first 64 diagnostic spans and saturating the dropped count at `INT_MAX`.
Normal diagnostic order and the public schema are unchanged.

**Validation.** `frontend_diag.c` scans 65,536 invalid bytes and checks every
retained offset, the exact dropped count, and counter saturation. Run:

```sh
cc -std=c99 -O1 -Wall -Wextra -Werror -Isrc -Iinclude -Ivendor \
  tests/audit40/frontend_diag.c src/axi_lex.c src/axi_diag.c src/axi_alloc.c \
  -o build/frontend-diag
build/frontend-diag
```

Pass a byte count (for example `1000000`) to reproduce the work-scaling
benchmark. This optimization bounds diagnostics after saturation; it is
not a general source-size or compiler-memory ceiling.

## W02 — stable branch relocation

**Problem.** Patching an `if` displacement could widen its text before the
saved `jmp` position was used. With a four-digit branch distance and a
nested `if` at the end of the first branch, that stale position rewrote the
inner branch and left the real jump at `+0`. A valid terminating program
then exhausted its fuel budget.

**Change.** Measure both branches before mutations and apply relocation
from the later byte offset to the earlier one.

**Validation.** `python3 tests/audit40/frontend_codegen.py build/axi branches`
checks signed artifacts on the real VM across both paths, displacement
widths through four digits, and nested conditionals. The baseline fails the
1,001-statement case with `AXI-R008`; the corrected compiler returns `u64 77`.

## W03 — owned contiguous call windows

**Problem.** Codegen allocated the first free register as a call base,
evaluated arguments, then reserved unrelated free registers. A live local
could lie inside the actual argument window. The program
`let keep = 99; add(1, 2); ret keep` returned `u64 2` on the baseline,
without any trap. Argument temporaries also leaked from the register pool,
eventually refusing repeated calls in otherwise small cells.

**Change.** Reserve the entire contiguous window before evaluating arguments;
preserve the return slot; release the argument temporaries after copying.
Nested calls reserve independent windows. The VM call ABI is unchanged.

**Validation.** `python3 tests/audit40/frontend_codegen.py build/axi calls`
covers user cells and builtins, preserved locals, nested and zero-argument
calls, sixteen arguments, and 100 repeated calls without register leakage.

## W04 — correct unit returns and branch-local register lifetime

**Problem.** The checker defines bare `ret` as `ok`, but codegen emitted
integer zero. Running the signed artifact therefore trapped with `AXI-R025`.
An early `ret` also kept its temporary register live in subsequent generated
branches, refusing a function with many independent early returns.

**Change.** Bare and explicit unit returns use the untouched UNIT register.
Return temporaries are retired after emission; bound locals and the dedicated
unit register retain their separate lifetimes. A missing expression elsewhere
is an internal refusal, never implicit integer zero.

**Validation.** `python3 tests/audit40/frontend_codegen.py build/axi returns`
checks `ok`, `u64 0`, and `bool false` as distinct results, plus both outcomes
of 80 independent conditional returns.

## W05 — one bounded-stack codegen traversal

**Problem.** Builtin collection recursed through every sibling statement,
even though the parser only bounds child nesting. It also restarted from
each cell, re-walking all later cells. A valid 40,000-statement body crashed
with SIGSEGV under a 2 MiB host stack before producing an artifact.

**Change.** Iterate sibling lists, recurse only into bounded child structure,
and collect once for the whole unit. Stop emission after an established
allocation or register/table refusal. Empty output buffers start terminated.

**Validation.** `python3 tests/audit40/frontend_codegen.py build/axi traversal`
compiles and runs the 40,000-statement case under a 2 MiB compiler stack.
The collection walk now visits each AST node once, excluding builtin table
lookups; it uses stack proportional to structural depth rather than width.

## W06 — exact signed-literal range and cheaper lowering

**Problem.** The source literal `-18446744073709551615` was accepted as i64
and emitted as positive one. This is a literal-range error, distinct from
the language's defined arithmetic wrap. Every ordinary negative literal
also consumed an unused u64 constant and load before its real i64 load.

**Change.** Reject magnitudes above 2^63 in the type checker and again at
codegen's boundary. Emit an admitted negative literal with one i64 constant
and one `ldk`, preserving the minimum signed value. Opcode prices stay fixed;
generated programs spend one less fuel unit per negative-literal evaluation.

**Validation.** `python3 tests/audit40/frontend_codegen.py build/axi signed`
checks both invalid magnitudes, signed boundary values, artifact absence on
refusal, and 80 distinct negatives within the constant-pool bound. Arithmetic
over existing i64 values retains its documented wrapping semantics.
