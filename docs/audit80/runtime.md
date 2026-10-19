# Axial W69–W76 — runtime workloads and operational evidence

Baseline: `82596bf8faf607e25f7366e36381a8dad58302a1` (completed W40).
Public embed-v1 ABI and wire representations stay fixed. No production traffic
was supplied: every workload below is synthetic and its generation is checked
in. A host measurement is not a production latency or durability guarantee.

## W69 — transparent mixed runtime workloads

`runtime_fixture.c` generates signed AXS modules and caller-owned requests for
12 paths: policy allow/deny, ordinary false, borrowed/decoded JSON strings,
eight nested calls, a 128-iteration arithmetic loop, division/fuel traps,
interface mismatch, insufficient output workspace and malformed JSON. Each
path asserts its distinct outcome, exact fuel, result and output preservation
on refusal across 32 inputs. These are workload families, not user traces.

Run `python3 tools/audit80-runtime-bench.py check`. The runner builds product
sources separately from fixtures, has a source/header/compiler content cache,
and accepts `--source` for baseline comparison without writing that source tree.
Use a separate `--output` and `--cflags` for sanitizer instrumentation.

Further waves add lifecycle, concurrency, memory, measured latency and storage
failure evidence. They will not claim physical power-loss or guest/kernel
enforcement from process-level experiments.

## W70 — full context lifecycle and allocation refusal

The lifecycle lane covers 13/64/256-cell modules, signature-valid and CHECKED
admission, evaluation, destruction and module-source lifetime independence.
It injects each of the 120 allocation failures reached while creating the
13-cell context: every refusal returns OUT_OF_MEMORY, clears the context
output and restores the exact tracked live-byte count. 489 checks pass.

The GNU/ELF link wrappers count requested bytes in direct allocation calls,
including decoder and verifier temporaries. They do not count allocator
metadata, libc-internal allocation, or stack. They exist only in the test
binary; the product remains free of a pthread or instrumentation dependency.
Observed peak extra requested bytes for 13/64/256 cells were
90,264/439,408/1,336,432, respectively (0/16/16 laws). These are measured
lifecycle costs, not a configured runtime quota.

`python3 tools/audit80-runtime-bench.py context --report <file>` builds a
separate uninstrumented timing probe. Five samples of 20 newly created
contexts per configuration, after a warmup process, are recorded in
`runtime-context-w70.json`. Parsing/signing fixture setup is excluded. Each
context is new but CPU, process and OS caches are warmed; this is not a
machine-cold startup experiment. The measurement is pinned to one shared CPU,
with no frequency, tenant-isolation or production-SLA claim.
