# Driver, integration and evidence — W31–W40

Baseline: `2d6752255ffcc92e0b103c97609daf205a5a39de`, public tree of
2026-10-19. This campaign is confined to Axial. The public embed-v1 header
and its ABI are preserved. Host results do not establish native/guest
enforcement or a production trusted runner.

## W31 — Incremental, dependency-aware builds

The original Makefile compiled all translation units in one command for
both executables, did not track headers and ignored `LDFLAGS`. It now shares
objects, emits compiler dependencies and uses a content-stable compiler/flag
stamp. `BUILD` can isolate toolchain configurations; link flags and libraries
are honored. The default optimization remains `-O1` for comparable baselines.

Validation: clean build, unchanged no-op build, header-triggered dependent
rebuild, and demo reuse of core objects. No public API or artifact format
changes. Evidence commands: `make -j4 dev`, `make dev`,
`touch src/axi_hash.h && make -j4 dev`, `make demo`.

## W32 — Portable and fail-closed fixture preparation

The baseline built successfully but its gate reported 54 PASS / 13 FAIL
because `xxd` was missing. The same original executable passes all 67
goldens when supplied the correct public fixture key. A shared POSIX-shell
fixture helper replaces xxd/Python in both demos and the gate; setup checks
both key lengths. The gate also refuses absent required suites and missing
golden/command files rather than silently reducing coverage.

Validation: 67/67 original goldens with both original and candidate
executables; policy and supply-chain demos. The fixture is explicitly
documented as a deterministic public test identity, not fresh private keys.

## W33 — Exercise the real signed CLI boundary

`make gate-cli` now covers signed compilation, signature tampering, absent
trust, checked versus unchecked sealing, all red proof fixtures, exact fuel,
overflow refusal, confined filesystem effects, missing grants, signed replay
with distinct identities, tampered replay and pre-effect recorder admission.
These checks were absent from the public 67-test gate. `make gate` includes
both the original goldens and this suite.

The added same-producer/recorder test exposed a real baseline late refusal:
io.Write occurred before the invalid recording identity was refused. W20
fixes that preflight. The restricted execution sandbox also denies even
local Unix datagram sends; fs.Write's fsync worker therefore needs an
IPC-capable host for the positive integration case. This environmental
denial was reproduced with a separate socketpair probe; the test retains
the positive assertion and a bounded deadline, with no skipped success case.

## W34 — Bounded, nonblocking CLI file snapshots

The CLI used an unbounded seek/allocate/read path, followed FIFOs into a
blocking open and did not detect file growth or close/read errors. It now
opens once with nonblocking/CLOEXEC flags, requires a regular file, enforces
a 64 MiB limit before allocation, checks exact EOF and reports an explicit
oversize diagnostic. Empty regular files remain valid inputs to the parser.
All CLI parser calls now handle the internal NULL-on-OOM contract introduced
in W10; allocation failure no longer becomes a CLI null dereference.

Validation: `make gate-audit` runs the actual reader against regular, empty,
oversized sparse, absent, directory, device and FIFO inputs (16 checks).
The 67 original goldens remain green. Source files above 64 MiB and special
files are intentionally refused; this is a documented CLI resource bound.

## W35 — Project the interface from the checked snapshot

`iface` previously checked a pathname, freed its source/tree, reopened the
name and parsed it again. The second source did not pass canonical checking;
an intervening replacement could therefore project an interface for bytes
that were never accepted by the advertised check ladder. The shared checker
now optionally transfers ownership of its validated source and typed AST to
the interface command. Both iface and iface-diff reuse that exact snapshot.

Validation: all interface goldens, plus a reader-open counter and projection
after the source pathname is unlinked. The path is opened once; canonical
form and inferred capability annotations remain attached to the same AST.
This also removes one complete parse/type-check cycle per projected file.
