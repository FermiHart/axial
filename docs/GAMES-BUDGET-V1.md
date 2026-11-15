# Games budget v1: bounded reference scheduler

SPDX-License-Identifier: LicenseRef-SPL-1.0

`runtime/games-budget-v1.cjs` is a Node host-side scheduler, not a sandbox or policy
interpreter. It accepts serialized strings without invoking callbacks or parsing
untrusted objects. Queue count and UTF-8 **payload** bytes are bounded independently;
actor names are at most 128 ASCII characters. Object and string runtime overhead is
not included in the byte counter, so it is not a heap-byte accounting mechanism.
Configuration is trusted host input and hard maxima cannot be raised through it.

Call `beginTick(authoritativeTick)` with a monotonically increasing safe integer.
The caller must not expose this operation to the client. Repeated or regressed ticks
are refused, rather than resetting quotas. Gaps are allowed for resumed simulation.
Then `enqueue(authenticatedActorId, serializedCommand, hostWorkUnits)` and
`takeBatch(maxItems)`. Work units must be estimated by the host, not supplied by a
packet. Per-actor and global charges persist across multiple batches in one tick.
Entries that cannot fit are retained and later entries may run; this is deterministic
first-fit FIFO, **not a starvation-free or fair-share scheduling guarantee**.

Take reserves the work budget even if execution later fails. There is no refund and
no replay after removal: a production adapter must use durable receipts/idempotency
and handle process failure. Queue state and ticks are in memory only. Rate limiting
must also protect ingress before this queue, and authenticated accounts may need
aggregate/IP/session controls to prevent Sybil quota evasion.

No wallclock or RNG changes a scheduling decision. This does not make all host work
bounded: parser complexity, callbacks and actual policy execution require their own
limits and isolation. Batch size, actor count and linear scanning are bounded by the
queue maximum. Budget units are not elapsed time and do not replace VM fuel.

## Three integration fixtures

`examples/games/server-facts.cjs` illustrates door access, inventory ownership and
race admission. Facts come from authenticated session and server state, **never** a
client `authorized` or `owns` claim. These fixtures only derive facts; an admitted
Axial policy must evaluate them, and a transactional authoritative host must recheck
versions and apply effects. They neither grant rewards nor move inventory. They are
not connected to RustRoots production or a deployed multiplayer service.

Run `node --test tests/games-budget-v1.test.cjs tests/games-server-facts.test.cjs`.

The three `.axi` files beside the fact adapters are executable, native-compiled
reference policies. `node --test tests/games-pilots.test.cjs` builds the real C
exporter, compiles each policy and compares portable JS against the C VM oracle
for all 16 combinations and fuel prefixes (1,056 comparisons per policy).
It also routes forged claims and legitimate server facts into the compiled policy.
These are integration pilots with the actual VM, not deployed game endpoints.
An `allow` remains an intent: the host must atomically revalidate state revisions
before changing ownership, opening a door or awarding anything.

## Per-actor pending capacity and synthetic workload

Pending queues also enforce `actorQueueItems` and `actorQueueBytes`, defaulting to
min(32, queueItems) and min(32,768, queueBytes). These are **pending** limits independent
of execution-per-tick quotas: advancing ticks does not erase pending accounting.
Selecting an item releases its pending capacity; this does not refund execution
budget. Actors cannot individually occupy the entire default global queue. Small
custom global queues may equal the actor cap; set a smaller explicit actor cap when
requiring reserved room for other actors. Sybil identities still require host controls.

`node tools/games-budget-bench.cjs` exercises 1,000 distinct synthetic NPC actors for
100 ticks, 100,000 commands total. Output includes p50/p95/p99 per enqueue, per batch
and per tick (including harness), sampled process heap, and asserted queue bounds.
It has no VM evaluation, world simulation, socket or renderer work. It is not a claim
about RustRoots production, browser or phone performance. Harness timing arrays and
uncontrolled GC affect memory figures; sampled heap is not a maximum allocation cap.
