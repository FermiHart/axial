# Games policy workload

SPDX-License-Identifier: LicenseRef-SPL-1.0

Run:

```sh
node tools/games-policy-workload.cjs
```

This synthetic Node workload builds the actual C compiler/exporter, compiles
`examples/games/inventory.axi`, admits its exact exported bytes through the trusted
host digest manifest and evaluates that admitted decision-v2 program. No fake rule
substitution is used. The manifest is constructed by the benchmark's trusted setup,
not received from any simulated actor.

## Workload and assertions

- 1,000 distinct actor identities for 100 explicit ticks, 100,000 commands total.
- All 16 combinations of four authoritative boolean facts cycle through the workload.
- Every seventeenth command has zero fuel and must trap, never allow.
- Other commands must return the exact first denial reason or `allow`.
- A tampered artifact is rejected by admission.
- Scheduling uses count, byte, per-actor and per-tick limits. Every tick asserts that
  all commands are selected, limits are obeyed and queue accounting returns to zero.
- Outputs include source/compiler/artifact digests for identifying the actual input.

Latency percentiles are reported separately for 100 admissions, 100,000 enqueues,
100 batches, 100,000 admitted evaluations, and 100 complete ticks. Admission is setup,
not repeated per decision; evaluation still includes copying/validation performed by
the current runtime. Timing uses a measurement clock only: tick scheduling and policy
inputs never use that clock. Build/export time is reported separately.

The benchmark retains timing arrays and assertions and samples the process heap;
heap numbers include this harness. It does not force GC, prove a peak-memory bound,
or measure RSS. A 100-sample p99 is particularly noisy; repeat on target hosts.
There is no pass/fail latency threshold.

## Initial observed run (not a capacity promise)

Node 24.22.1, Linux x64, one local run:

- 5,883 allow, 88,234 deny, 5,883 fuel traps; 100,000 asserted results.
- Evaluation p50 16.10 µs, p95 37.86 µs, p99 91.33 µs.
- Full tick including harness p50 24.28 ms, p95 37.02 ms, p99 52.78 ms.
- Peak pending queue: 1,000 items, 97,318 UTF-8 payload bytes.
- Sampled heap peak: 81,269,744 bytes, including measurement overhead.

This does **not** establish a 60 Hz budget for 1,000 policy evaluations per game tick.
It identifies admission reuse, validation/copying overhead and bounded scheduling as
areas to measure and optimize with actual game workloads. It does not measure
RustRoots simulation, rendering, networking, browser/mobile execution, persistence,
transactions, worker concurrency or real multiplayer deployment.
