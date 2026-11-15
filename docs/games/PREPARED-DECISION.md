# Prepared portable decision v2 evaluation

This optional API optimizes repeated evaluation of the same validated policy.
It does not change bytecode, compiler identity, decision semantics or the native ABI.

`prepare(program)` returns a frozen opaque evaluator with only
`evaluate(facts, {fuel})`, or null on invalid input. It validates once and
captures its own recursively frozen snapshot. No caller-owned array, constant,
return type or program is used thereafter. Each call still validates facts and
options through descriptors and creates fresh register state. The existing
public `evaluate(program, facts, options)` still validates every program on
every invocation; there is no caller-supplied skip-validation flag.

Preparation is **not authentication or admission**. Provenance hashes remain
unverified provenance at VM level. The trusted games admission path hashes
copied artifact bytes against the host manifest before preparing, stores the
evaluator privately, and checks loader ownership, revocation and facts byte
limits on every invocation. Numeric admission retains its existing path.
Transparent JavaScript proxies are not claimed to be a sandbox boundary.

## Executed local evidence

Node synthetic workload, unchanged `tools/games-policy-workload.cjs`:
1,000 actors x 100 ticks; **100,000 actual policy evaluations** both runs.
Both: allow 5,883; deny 88,234; fuel traps 5,883. No decision frequency reduction.
Recorded JSON includes platform, source/artifact digests and queue bounds in
`evidence/prepared-before.json` and `evidence/prepared-after.json`.

| Metric | Before | Prepared |
| --- | ---: | ---: |
| Evaluation p50 (microseconds) | 16.684 | 3.015 |
| Evaluation p95 (microseconds) | 46.488 | 6.489 |
| Evaluation p99 (microseconds) | 105.015 | 22.333 |
| Tick including harness p50 (milliseconds) | 27.128 | 8.097 |
| Tick including harness p95 (milliseconds) | 39.385 | 13.861 |

One before/after run in a shared Linux container, uncontrolled CPU scheduling and
GC. This is evidence of local overhead reduction, not an FPS, capacity, mobile,
browser, server authority, or production latency guarantee.

Executed tests:
- Prepared + existing admission + numeric admission: 16/16 at first run.
- Prepared (six tests) + decision differential + adversarial: 28/28.
- Equivalence compares complete result objects across all inventory fact masks,
  fuel bounds, trap programs and deterministic malformed instruction mutations.
- Mutation isolation, descriptor/getter refusal, opaque freezing, repeat-call
  independence, digest mismatch, foreign handles, facts limits and revocation.

Reproduce serially to avoid shared exporter build races:

```sh
node --test --test-concurrency=1 tests/portable-decision-prepared.test.cjs tests/games-admission-v1.test.cjs tests/games-numeric-admission.test.cjs tests/portable-decision-differential.cjs tests/portable-decision-wave2-adversarial.cjs
node tools/games-policy-workload.cjs
```

Final combined gate after adding the cross-realm shared-memory test: **40/40**.
Admission now uses Node's `types.isSharedArrayBuffer` for policy and facts backing
stores, including buffers created from another VM realm. This enforces the
documented shared-memory refusal contract; it is not a claim that the previous
copy-before-hash path allowed digest bypass. Benchmark recordings precede this
minor guard adjustment; no post-adjustment latency number is claimed here.

## Alternating warmed direct-VM comparison

`node tools/games-prepared-comparison.cjs` uses the already-built exporter;
run the normal build first if absent. After 20,000 warmup evaluations per path,
three paired runs alternate public/prepared ordering, 20,000 calls per path per
pair, identical fact/fuel sequence and checked counts plus total fuel consumed.
Raw JSON: `evidence/prepared-alternating.json`.

| Pair | Public median / p99 (us) | Prepared median / p99 (us) |
| --- | ---: | ---: |
| 0 | 14.631 / 96.873 | 1.853 / 3.245 |
| 1 (prepared first) | 14.612 / 84.334 | 1.833 / 3.325 |
| 2 | 14.942 / 59.127 | 1.863 / 3.265 |

Direct VM comparison excludes admission parsing. These are shared-host local
measurements, not universal speedup or end-to-end game performance promises.
