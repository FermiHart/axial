# Consumer adoption and rollback: RustRoots / Mordomo

Status: rollout contract and read-only compatibility inventory, **not an adoption
commit**. No RustRoots files, lock, database, Site or deployment were changed by this
work. The reference examples passing in Axial do not establish consumer compatibility.

## Verified consumer baseline (2026-11-15)

GitHub `FermiHart/RustRoots` main was read as
[`07d34a58cf2234bb54c8a605a88a37ffc7ed1698`](https://github.com/FermiHart/RustRoots/commit/07d34a58cf2234bb54c8a605a88a37ffc7ed1698).
This is a pinned inspection snapshot, not a promise that main remains unchanged.

The inspected active subtree is `audit/v191/game-source-patch`:

- [`policies/axial-upstream-lock.json`](https://github.com/FermiHart/RustRoots/blob/07d34a58cf2234bb54c8a605a88a37ffc7ed1698/audit/v191/game-source-patch/policies/axial-upstream-lock.json)
  has schema 2, upstream Axial commit
  `e37ae51a72f18ca73a52c6c60117f0f942e44e49`, and profile
  `axial.portable-decision.v2`. It pins decision runtime, invocation context,
  exporter/build tools, policy source/program and license by bytes and SHA-256.
  The lock explicitly describes provenance, not a signed AXB/CHECKED certificate.
- [`src/axial-mordomo-policy.js`](https://github.com/FermiHart/RustRoots/blob/07d34a58cf2234bb54c8a605a88a37ffc7ed1698/audit/v191/game-source-patch/src/axial-mordomo-policy.js)
  consumes six booleans, fuel 256, exact declared error reasons and invocation
  contexts. It verifies the runtime result shape and distinguishes allow, deny,
  trap and refused. Its API is not the inventory pilot API from this campaign.
- [`multiplayer/family-delivery-service.cjs`](https://github.com/FermiHart/RustRoots/blob/07d34a58cf2234bb54c8a605a88a37ffc7ed1698/audit/v191/game-source-patch/multiplayer/family-delivery-service.cjs)
  requires the Mordomo adapter and maintains native delivery/checkpoint state.
  Invocation handles are process-local and explicitly excluded from checkpoints.
- [`docs/AXIAL-MORDOMO-CONTEXT.md`](https://github.com/FermiHart/RustRoots/blob/07d34a58cf2234bb54c8a605a88a37ffc7ed1698/audit/v191/game-source-patch/docs/AXIAL-MORDOMO-CONTEXT.md)
  documents native observation revalidation, cancellation independent of VM success,
  durable native receipt replay before reevaluation and separate decision/effect outcomes.
- [`.github/workflows/axial-mordomo.yml`](https://github.com/FermiHart/RustRoots/blob/07d34a58cf2234bb54c8a605a88a37ffc7ed1698/.github/workflows/axial-mordomo.yml)
  uses Node 24, checks the consumer lock, checks out its exact Axial pin, recompiles,
  runs differential/adversarial policy/context tests and consumer engine/family gates.

This inspection read those files at the commit above. It did **not** run RustRoots,
its browser or consumer test suite. Evidence recorded in the consumer document is
not recertified by this inspection. Recheck the current main and concurrent work
before any later adoption; do not blindly apply patches against this snapshot.

The Axial candidate validated by this campaign is
[`aa3003f34b969bcfbc1184c26fbc508048e245b9`](https://github.com/FermiHart/axial/commit/aa3003f34b969bcfbc1184c26fbc508048e245b9).
Its Games, Portable consumer, Pages and Audit workflows passed. This is an
upstream candidate only, not a request to replace the consumer pin blindly.

## What exists now versus what adoption still requires

| Axial reference component | Consumer adoption status / obligation |
| --- | --- |
| Node pinned artifact admission | Executable in Axial tests; consumer needs an explicit adapter using trusted deployment pins, not player-supplied manifests |
| Immutable prepared decision evaluator | Opt-in snapshot optimization with unchanged public evaluation semantics; consumer must integrate it behind its own existing validation/context contract |
| Portable numeric profile | Separate versioned runtime/export path; Mordomo's boolean v2 contract must not silently become numeric |
| In-memory authority adapter | Reference only; cannot replace native durable receipts |
| SQLite single-resource authority | Real local transaction/restart tests; **not** a drop-in replacement for RustRoots checkpoints or multi-resource world storage |
| Persistent revocation opt-in | Reference database state and host-only method; consumer needs authenticated operational control and a designed migration |
| Durable inventory pilot | Executed fixture; not connected to actual vehicles, ownership, wallets, network or Mordomo UI |
| Quotas/budgets and adversarial suites | Reusable tests/helpers; consumer must select budgets, bind actor identity and measure actual game workload |

No row here claims a game deployment, production anti-cheat service, wallet atomicity,
marketplace rollout or cross-platform/mobile performance qualification.

## Proposed adoption sequence (not existing consumer APIs)

1. **Freeze a candidate pin.** Record exact Axial and RustRoots commits. Review their
   diffs together; preserve newer work. Choose the required helpers only, preserving
   license headers. Update the consumer lock and artifact provenance through its
   existing build tool, not by editing hashes to bless arbitrary bytes.
2. **Preserve semantics.** Keep the six-boolean Mordomo interface, error priority,
   fuel 256, checkOnly/context retirement and cancellation behavior unchanged. Admit
   policy bytes with a digest from a trusted build/deployment manifest. An external
   manifest must not be inferred from the same untrusted artifact being admitted.
3. **Observe before enforcing.** Add a consumer-specific, explicitly named rollout
   switch and shadow trace sink as new code, if desired; neither is claimed to exist
   today. A shadow decision cannot authorize effects or mutate live state. Compare
   all admitted combinations and native recovery cases against the previous path.
4. **Keep one authoritative writer.** Do not write both SQLite reference state and
   the native checkpoint system as independent authorities. Either retain the native
   transaction/receipt mechanism and adapt rules to it, or design a separate reviewed
   storage migration. The new reference DB stores flat single-resource state and is
   unsuitable for simply copying the consumer's world checkpoint into it.
5. **Bind real identity/state.** Reconstruct facts on the server from authenticated
   session and current resource version; client booleans and actor IDs are not proof.
   Distinguish the context's observation counter from a durable world revision.
   Namespaced command IDs, replay receipts and per-actor admission quotas are needed.
6. **Exercise failures.** Test denial, trap, refused format, fuel exhaustion, forged
   identity, stale observation, ownership change, callback reentrancy, disconnect,
   lost response after commit, restart, cancellation and quota/lock/storage failure.
   Ensure no retry duplicates effects and no failure is converted into allow.
7. **Enforce on a limited scope.** Promote only after shadow comparisons, authoritative
   tests and observed gameplay pass on the candidate. Record exact policy/runtime
   versions with results. A successful build is not acceptance of browser/gameplay.

## Rollback and revocation rules

- Roll back **code/policy selection**, not already committed history. Never erase
  receipts or reset resource versions to make a failed release appear unused.
- Preserve replay of commands committed before revocation; this reports historical
  truth without reexecuting effects. Denied/refused decisions remain auditable.
- On unexpected decisions or storage failures, stop new admissions for the affected
  capability and keep safe cancellation available. Do not fall back to permissive
  execution merely because a policy or runtime is unavailable.
- For the optional SQLite reference, choose `persistedRevocation:true` for a new DB.
  Metadata binds the mode/world/schema/policy digest. Existing legacy DBs require a
  separately designed and tested migration; toggling the option is not migration.
  Do not downgrade the mode or restore an older snapshot that loses revocations and
  receipts. The prototype has no un-revoke, schema migration or policy rotation API.
- The host-only revoke method is an administration capability. Do not route player
  commands to it. A `BUSY` or `STORAGE` result is not a successful revocation.
- Filesystem paths, backup/restore, WAL handling, authentication and operational keys
  remain deployment responsibilities. Test a restore against the command receipt
  and revocation history before any production migration.

## Consumer gate contract

The verified workflow already invokes these commands from the active subtree:

```sh
node scripts/build-axial-mordomo.cjs --check
node scripts/engine-tests.cjs axial
node scripts/family-tests.cjs contracts
node --test tests/engine-composition.test.cjs tests/engine-build-publication.test.cjs
```

Its native differential stage additionally uses `AXIAL_ROOT` and
`AXIAL_DECISION_SOURCE` with the pinned upstream tests. A future adoption must rerun
those gates and relevant browser/native/network recovery tests at the **new exact
commits**. Do not replace them solely with Axial's generic fixture tests. Read the
current workflow again before execution because command sets may evolve.
