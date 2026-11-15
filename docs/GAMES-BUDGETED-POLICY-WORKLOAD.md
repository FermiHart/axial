# Budgeted policy workload: latency versus frequency

SPDX-License-Identifier: LicenseRef-SPL-1.0

Run `node tools/games-budgeted-policy-workload.cjs`. The benchmark builds the native
compiler/exporter once, compiles `inventory.axi`, admits its digest and evaluates the
actual decision-v2 program with the current runtime. Cases limit batch selection to
64, 128, 256 or 1,000 decisions per explicit logical tick. All cases process exactly
the same 100,000 decisions from 100 cohorts of 1,000 actors, including all 16 boolean
fact masks and a zero-fuel trap every seventeenth command. Individual ordinal tracking
rejects duplicate or missing completions, and outcome totals must match between cases.

## Important experimental boundary

The next cohort arrives **only after the previous backlog drains**. This finite,
closed-loop test has controlled ingress, not sustained 1,000-new-decisions-per-tick
traffic. Under an ingress rate above service capacity, a finite queue must eventually
refuse new work; this benchmark does not conceal that by dropping work. It neither
coalesces nor silently drops any accepted decision. Capacity refusals in a real host
must be exposed as backpressure/retry, or dealt with by a separately specified policy.

| Max evaluations/tick | Logical ticks for 100,000 decisions | Worst queue wait |
| --- | ---: | ---: |
| 64 | 1,600 | 15 ticks |
| 128 | 800 | 7 ticks |
| 256 | 400 | 3 ticks |
| 1,000 | 100 | 0 ticks |

**These cases do not have the same decision frequency or logical duration.** A smaller
batch smooths CPU service at the cost of older observations and longer decision delay.
It does not magically speed up the same simulation. A host must refresh/version-check
facts at execution and reject stale intent before applying any effect. Critical actions
and NPC ambience may require different trusted host priorities and bounded queues.

## Host scheduling and fairness

The workload rotates the first actor of each cohort deterministically. Every actor
receives exactly one item per cohort and all cohorts drain; this verifies bounded
completion for this workload only. The generic scheduler remains first-fit, not a
formal fair-share scheduler. Priority must be assigned by the trusted host, never by
a client assertion. A production design should cap critical-class budget, reserve a
minimum service share for lower-priority actors, apply aging with explicit logical
ticks, and measure per-actor service gaps under adversarial arrivals. Those facilities
are a design plan, not implemented or proven by this benchmark.

## Measurement interpretation

The JSON reports evaluation, batch-service and tick p50/p95/p99, logical queue-wait
tails, observed total duration, queue bounds and sampled heap. Tick timings exclude
cohort enqueueing; total duration includes it. Heap includes timing arrays, completed
ordinals and data from prior cases until GC. There is no forced GC, maximum heap proof,
production latency threshold or deterministic timing promise. Measurement clocks do
not influence scheduling or policy facts. Run order/JIT/GC affect comparisons.

An initial Linux x64 Node 24.22.1 run after prepared-policy admission observed tick
p99 approximately 1.82, 3.44, 2.07 and 8.32 ms respectively. Their non-monotonic order
is a reminder to repeat and inspect noisy tail measurements, not choose an allegedly
optimal cap from one run. Every case produced 5,883 allows, 88,234 denials and 5,883
fuel traps. This is not RustRoots world simulation, browser/mobile, network, persistence
or a 60 Hz production-capacity demonstration.
