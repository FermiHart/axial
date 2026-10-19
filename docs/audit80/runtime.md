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
