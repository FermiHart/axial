# Axial Games adapter boundary (experimental)

This package is a set of optional Node host adapters. It does not silently
change portable-decision-v2 or Axial native numeric semantics. It is not
production-ready distributed authority or an anti-cheat product.

## Data flow

1. Authenticate session outside Axial; ignore player-supplied actor identity.
2. Decode a byte/count bounded command and rate-limit through games-budget-v1.
   Work units are estimates assigned by the host, not client-reported cost.
3. Resolve authoritative resource, ownership, reservation and revision.
4. Admit policy bytes with games-admission-v1 against trusted deployment pins.
5. Derive immutable boolean facts and execute the bounded policy.
6. On allow only, commit under the same authoritative resource version and
   policy version, atomically persisting state and idempotency receipt.
7. Record world/actor/command/policy/schema/revision/outcome for replay.

The games-authority reference demonstrates steps 3/6 synchronously in memory,
not step 6's durable transaction. It cannot provide restart/replay safety.
Never connect its JSON command entry directly to unauthenticated clients.

## Rollout

Keep current Mordomo production integration unchanged until the consumer
locks the reviewed Axial commit and passes its own tests. New policy first
runs in shadow mode over authoritative events; compare allow/deny/reason,
traps and cost with existing rules, without additional world effects. A
mismatch is diagnostic, not proof of cheating and never an automatic ban.
Promote by a trusted policy version change, retaining old version and replay
fixtures. Durable minimum-version policy must prevent unintended rollback;
emergency rollback needs explicit host authorization and audit trail.

## Required future gates

- Signed policy distribution and durable version/revocation storage where needed.
- Durable command receipts, database CAS and multi-resource wallet transactions.
- Compiler/bytecode support for a separately versioned quantitative profile.
- C/portable/browser/ARM exact-result matrix, not only Node tests.
- Coverage-guided fuzz plus sanitizers and recorded corpus coverage.
- Real workload p50/p95/p99, peak heap/GC and per-tick deadlines; current microbench
  averages 100 calls per batch and cannot imply per-call tail latency.
- Three engine-integrated pilots and interrupted/reconnected multiplayer flows.

Do not relabel these missing gates as complete because helper tests pass.
