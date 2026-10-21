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

## W71 — eliminate maximum-size stack frames for small callees

The workload expansion found a real availability defect: valid pure calls
reserved all 256 registers per level even when their manifests used one.
The W40 baseline died with SIGSEGV for 64 one-register cells on a 512-KiB
pthread stack and for 256 cells on a 2-MiB stack. These are controlled child
process experiments; the parent records signal and exit status.

After `run_cell_prepare` validates register count 1..256 and call depth,
the pure path now uses a C99 VLA of the actual count. Accounted invocations
retain their existing checked slab. GCC `-fstack-usage` reported a 22,672-byte
unaccounted-frame allocation before the change; the variable register
storage is now 88 bytes per declared register, plus bounded function overhead.
This removes 22,440 bytes of unnecessary register storage per one-register
callee. All three probes pass after the change, including eight callees that
actually require 256 registers. Return values and 36/316/1,276 fuel agree.
The W69–W71 workloads, all 120 lifecycle allocation failpoints and all stack
probes also pass with ASan/UBSan. LeakSanitizer remains disabled on this traced
host; the requested-byte wrapper independently checks observed cleanup.

This is a measured stack reduction and prevented crash, not a claimed
context-creation speedup. Maximum-register recursion still requires a large
host stack; the C API has no promise to run on an arbitrarily small stack.

## W72 — concurrent independent invocations and first-use hash safety

Eight threads exercise isolated context creation/evaluation/destruction and
shared immutable-context evaluation, each with private request/workspace/
outcome storage. All readers join before destruction. Each mode completes
1,920 mixed evaluations with exact result and fuel oracles; no concurrent
destruction, mutable-request sharing or one-shot CAP reuse is permitted.

The experiment exposed a real first-use data race in the SHA-NI detection
cache. A freshly instantiated copy of the W40 header reports a read/write
race at its cache access under ThreadSanitizer (exit 66), even though digest
checks appear to pass. The cache now uses relaxed atomic accesses on supported
GCC/Clang; no other state is published by that integer. Each hash context
retains its own detection result. The uncached fallback queries CPUID once
per initialized context, never per compression block. Product code acquires
no pthread dependency. A compile-time uncached lane and the existing forced
software lane verify identical digests independently.

Full product+fixture ThreadSanitizer runs pass for cached, uncached and
software test-header lanes. Each also performs both context workloads; this
is evidence for these lifetimes and inputs, not proof of all race freedom.
Reproduce with `--only runtime_concurrency runtime_concurrency_uncached
runtime_concurrency_software`, a separate `--output` and CFLAGS including
`-fsanitize=thread -fno-omit-frame-pointer -fno-pie -no-pie`.

## W73 — retained contexts, bounded JSON and accounted memory

The memory lane retains 1/2/4/8 CHECKED contexts containing 256 cells and
64 laws, then destroys every context. Requested live heap grows by exactly
1,023,088 bytes per admitted context in this build. Eight contexts retain
8,184,704 bytes and reach 8,498,048 peak extra requested bytes; destruction
restores the starting live-byte count. Caller input/output and fixture
construction are outside those extra-byte intervals.

Forty-eight JSON evaluations alternate a successful decoded result, output
workspace refusal, and a failed scratch allocation. The accepted document is
exactly the existing 65,536-byte JSON input limit and returns 32,762 decoded
bytes. Successful and workspace-refused evaluations each allocate one
65,536-byte scratch region and release it; allocation failure retains no
memory. A separate 65,537-byte document traps before any opcode/allocation,
using zero fuel and preserving output. The initial experimental assertion
was a fixture mistake: its 65,547-byte document exceeded that existing limit.
No JSON product limit or behavior was changed to accommodate the workload.

The accounted nested-call path is also checked at 0/4,096/131,072-byte
budgets: the first two refuse with the existing quota failure, the last
succeeds with 24,016 peak accounted bytes and unchanged result/fuel. All
three leave zero live allocations. The lane passes 273 checks normally and
with ASan/UBSan (`ASAN_OPTIONS=detect_leaks=0`). Linux `ru_maxrss` is printed
separately as whole-process high water, including fixture and tracking
overhead; it is neither runtime-only heap nor a portable quota measure.

Run `python3 tools/audit80-runtime-bench.py check --only runtime_memory`.

## W74 — latency distributions and validated throughput

The comparator builds the exact W40 revision into a snapshot below its own
build directory. It never modifies another checkout. Both variants use the
same generated workloads and GCC 13.3 C99 `-O1` flags; source and fixture
hashes are recorded. Five rounds alternate the order of baseline/candidate
processes. Each round measures 2,000 individual calls per family and 100 new
contexts per size. Raw samples, including outliers, are retained alongside
the summary in `runtime-latency-w74.json` and its compressed sample file.
Percentiles use integer nearest rank. The median clock-pair interval was
20 ns; it is reported, not subtracted.

| Workload | W40 p50/p95/p99, ns | W73 p50/p95/p99, ns | Exact fuel |
| --- | ---: | ---: | ---: |
| Policy allow | 330 / 381 / 501 | 321 / 371 / 510 | 3 |
| Policy deny | 320 / 400 / 490 | 311 / 400 / 491 | 3 |
| Ordinary false | 291 / 361 / 461 | 290 / 360 / 441 | 4 |
| Plain JSON string | 641 / 751 / 1,142 | 631 / 711 / 1,092 | 10 |
| Escaped JSON string | 711 / 811 / 1,272 | 691 / 751 / 1,152 | 10 |
| Eight calls | 712 / 852 / 1,252 | 651 / 721 / 1,102 | 38 |
| 128-iteration loop | 3,455 / 3,576 / 25,348 | 3,445 / 3,535 / 18,567 | 512 |
| Division trap | 371 / 461 / 721 | 361 / 420 / 681 | 4 |
| Fuel trap | 491 / 601 / 891 | 471 / 541 / 842 | 0 |
| Interface refusal | 130 / 161 / 190 | 130 / 160 / 190 | 0 |
| Workspace refusal | 721 / 871 / 1,402 | 711 / 812 / 1,362 | 10 |
| Invalid JSON trap | 360 / 421 / 561 | 350 / 401 / 550 | 0 |

There are 10,000 latency observations per family and variant. Every result
and fuel value is checked outside its timing interval. A separate amortized
loop includes those checks: its median was 1.153 versus 1.205 million
evaluations/s. Parallel readers share one immutable context, keep private
requests/workspaces/outcomes, and join before destruction. With 1/2/4/8
readers, candidate median loop rates were 1.234/2.420/3.338/5.418 million/s.
The 8-reader baseline median was 5.908 million/s, with ranges overlapping
the candidate (4.158–6.589 versus 3.908–6.304 million/s). These are five
throughput samples, not thousands of independent throughput observations.

Context creation initially regressed: median 13-cell/0-law admission was
2.732 to 3.370 ms; 64/16 was 3.498 to 3.931 ms; 256/64 was 5.589 to
6.194 ms. This is retained as an adverse result, not hidden by aggregate
evaluation improvements. The phase probe `runtime_context_profile` isolates
SHA-256 and Ed25519 verification using test-only link wrappers. Its initial
13/0 experiment observed 34 SHA-256 calls taking 15–20 microseconds total,
while unchanged Ed25519 verification consumed more than 96% of creation
time. W75 follows up with controlled placement and release-build evidence.

The runner supports `compare`, `latency` and the earlier `context` mode.
For the recorded comparison run:

```sh
python3 tools/audit80-runtime-bench.py compare --samples 5 --iterations 2000 \
  --context-iterations 100 --report docs/audit80/runtime-latency-w74.json
```

CPU affinity is pinned for single-reader latency and widened to the requested
reader count for parallel loops. The host cgroup reported an eight-CPU quota,
but CPUs, frequencies and other tenants were not isolated. Setup, signing and
thread creation are outside timed intervals; crypto/allocator/OS caches are
warmed. No result here establishes a production SLA, a guaranteed scaling
factor, or a latency distribution under a supplied real arrival process.
The three timing modes also pass ASan/UBSan smoke runs; those instrumented
timings are discarded. All published distributions were recomputed exactly
from the retained raw sample file, including its SHA-256 digest check.
