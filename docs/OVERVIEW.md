# Axial — product overview

## The unit

The compilation unit is a **cell**: one function, its signature, its
fuel budget, its capability manifest and its proof block — hashed
together, content-addressed, sealed.

- A cell does not seal without a green proof.
- Names are local bindings; identity is the hash.
- Editing is a new cell + rebind: total audit trail, no silent mutation.

## The signature is the blast radius

Types, error sets, fuel budget and the complete capability list sit in
the first lines. Review concentrates on the contract, because the body
cannot exceed it — two independent walls (type checker, runtime) enforce
the same promise.

## Effects

Capabilities are opaque values. Host builds resolve them through a
small POSIX shim (`src/axi_platform_posix.c`); the effect plane
(`src/axi_effect.c`) knows only fuel, grants and the ledger — never
sockets, forks or files directly. Dual authorization: the module must
declare the authority **and** the operator must grant it (`--cap`).
One key alone opens nothing.

## Budgets

- `fuel N` — every opcode has a deterministic cost; exhaustion is
  verdict `AXI-R008`.
- Memory — one arena per invocation, freed wholesale; exhaustion is
  verdict `AXI-R009`. No garbage collector in the core by design.

## Evidence

- `axi seal` — prove-then-emit. Red law, trap or zero laws: no artifact.
- `axi sign / axi verify` — attribution by a different actor than the
  prover. One word, one meaning: `seal` proves, `sign` attributes.
- `axi bind` — ties a module back to the exact source bytes it was
  assembled from.
- Ledger — one ordered, hash-chained line per effect; the root is the
  bytes the loader actually parsed, never a self-declared field.
- `axi run --record / axi replay` — capture and bit-identical re-run.

## Grammar

Eight laws (§SPEC-GRAMMAR): one spelling per meaning, canonical form
or error with mechanical fix, every node span-addressed, no ambient
authority in syntax, fuel is syntax, LL(1), no hidden top-level flow,
caged diagnostics that never abort on the first error.

## Embed

The C API is four symbols (`abi_version`, `context_create`,
`context_destroy`, `eval`), pure CAP-free execution semantics in the
beta scope. Policy verdicts are boolean at source checking and at the
embed boundary — any other type is refused.

## What is deliberately refused

Package manager. Ambient authority. Unbounded execution.
Nondeterminism in the base tier. Style debates (canonical or error).
Nil, exceptions, silent coercion, globals, metatables, macros,
operator overloading. Unsealed execution outside dev mode.
