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
