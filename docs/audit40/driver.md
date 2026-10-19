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
io.Write occurred before the invalid recording identity was refused. W16
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

## W36 — Strict command options and publication errors

Source commands previously accepted misspelled/extra options while reporting
success (for example `check file --jsno`). They now accept only their
documented arity and optional `--json`. A single dispatch wrapper checks the
final output flush, preventing `version > /dev/full` and similar publication
failures from returning success.

Validation: negative option cases across 11 command forms, original CLI
goldens and the Linux /dev/full write-failure test. Normal command results
and documented options retain their exit-status contracts.

## W37 — Immutable public-embed cell index

The frozen v1 API previously scanned every cell name (including repeated
strlen calls) on each evaluation. Context admission now builds a private
sorted index with cached lengths. Lookup is bounded binary search; manifests,
cell IDs, interface hashes and wire order are unchanged. The additional
storage is 512 bytes per context, with no extra allocation or mutable global
state. Setup work is paid once per admitted context.

The legacy boolean-only policy door also removes its unreachable generic
JSON serializer, initializes the entire argument value and checks canonical
boolean bits before publishing true/false. This preserves its existing
failure-output contract.

Validation: 776 checks through the real public v1 API over 256 reverse-ordered
cells, exact values/fuel, prefixes, absent cells, interface mismatch and zero
fuel. The same test executable supports `--bench ITERATIONS CELLS` for a
warm-context comparison against pristine sources. Small modules and context
creation must be assessed separately from repeated large-module lookup.

## W38 — Verify the model once per seal verification

Checked-seal verification previously reverified the whole module separately
for every law, even after the subject-root encoder had already verified that
same immutable model. Law execution now uses the existing private preverified
pure VM door, after exact proof-identity and transitive-capability checks.
The accounted variant uses the accounted VM path instead of allocating its
execution state outside the caller's account. Seal construction validates
law shape before execution. Signing seed cleanup uses the existing volatile
wipe helper.

Validation: a 64-law record executes at exactly 192 fuel, both ordinary and
accounted verification release all ownership, and altered fuel/verdict/name/
subject/checker fields are refused. A well-formed but false fuel assertion
passes structural verification and fails re-execution, explicitly preserving
the distinction between signed facts and checked behavior. One-byte memory
limits refuse cleanly. `seal --bench ITERATIONS LAWS` is a matched probe.

## W39 — Reproducible checker identity and public ABI guard

The public tree referenced an absent identity-generation tool and carried a
fixed source root. Keeping that root after changing VM behavior would confuse
old and new checker semantics. The restored tool commits to sorted paths,
byte lengths and SHA-256 file digests for all C, header, inc and def files in
src/include/vendor, with an explicit versioned domain and little-endian
length framing. It excludes only the generated identity header. Added and
removed source files change the commitment. `--check` refuses stale identity;
`--write` is an explicit maintainer operation after reviewing changes.

The gate also pins the original public header and ABI-profile bytes and
compiles independent sizeof/alignment/offsetof checks against the recorded
amd64 SysV LP64 layout. The original header is byte-for-byte unchanged.
Negative probes show that source additions and public-header drift are
refused; even `--write` cannot silently accept a changed public ABI.

Compatibility: the checker identity intentionally changes. Existing CHECKED
certificates must be re-executed and explicitly resealed by the new checker;
they are not relabeled or automatically upgraded. Any artifact carrying an
old CHECKED seal is refused even under SIGNATURE_VALID admission, because
the decoder verifies a present seal before applying the requested profile.
Unsealed ordinary signed artifacts are identity-independent. The AXB
encoding, signature framing and public v1 ABI remain unchanged. A source commitment
does not attest the compiled binary, prove implementation correctness or
establish native/guest enforcement. Building still needs C99/POSIX tools;
the identity and extended audit gates additionally need Python 3.

## W40 — Integrated gates, matched measurements and delivery

The full gate now executes every workstream, including the specially linked
parser/handle tests, injected store failures, deterministic work counters and
positive Unix IPC. Standalone security test caches also invalidate on header
changes. Benchmark binaries are opt-in and never impose noisy speed gates.
`make release` builds a separate portable `-O2` executable; normal, optimized
and ASan/UBSan full gates all pass. The public default stays `-O1`, matching
the baseline used for the algorithm comparison.

The GitHub workflow runs these three profiles on pull requests and applicable
pushes, with read-only repository permission, no persisted checkout credential
and a commit-pinned checkout action. Its hosted result is separate from the
recorded local runs. No main-branch merge is part of this campaign.

`tools/audit40-bench.py` builds the identical C probes against the pristine and
candidate trees with the same compiler/flags. It pins the measurement process
to one available CPU, uses one warmup and seven alternating before/after pairs,
checks return codes and semantic results, and saves every sample. Its CLI
cases require byte-identical observed outputs. Hardware frequency and other
host tenants are not controlled; small timing deltas with overlapping ranges
are inconclusive. C microbenchmarks and end-to-end CLI timings are labeled
separately. See [raw measurements](benchmark.json), the [Portuguese report](REPORT.md)
and [verification metadata](evidence/verification.json).

Cross-review examined the preverified proof boundary, immutable embed index,
CLI ownership, compiler OOM handling, capability propagation, numeric
canonicalization and hash-work reductions. No new blocker was found. The
[migration probe](evidence/migration.log) confirms that old checked artifacts
are refused, including ordinary execution of an artifact carrying such a seal,
and that explicit resealing succeeds.
