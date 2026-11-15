# Games authority v1: an in-memory reference, not production durability

`runtime/games-authority-v1.cjs` demonstrates the **host** side of Axial decisions.
It does not change the portable VM, authenticate users, admit/sign policy bytes,
provide an anti-cheat service, or persist data. Use authenticated server identity
when forming `actorId`; never accept a client's assertion of identity/ownership.

## Contract

Create one authority with a fixed `worldId`, admitted `policyDigest`, schema version,
initial resource JSON, trusted synchronous `decide` and `reduce` callbacks. The digest
is a binding to the host's admitted artifact, not evidence of authentication by itself.
Resources have `{id, revision, state}`; state and command payload are flat records of
at most 32 primitive fields (safe integers, booleans, null and strings up to 256 chars).
This deliberately narrow data model is a reference adapter, not a game world database.

`execute` accepts a bounded JSON string only, with exactly these fields:
`worldId`, `commandId`, `actorId`, `resourceId`, `action`, `expectedRevision`,
`policyDigest`, `schemaVersion`, `payload`. Default bound is 16 KiB. Parsing and
copying precede evaluation. Both callbacks receive frozen copies of command and
resource state. Adapt portable policy decisions into `{allow:boolean, reason:label}`.
Only exact `allow: true` reaches the reducer. Return a fresh flat next state.

A successful command compares the resource revision, computes the new state, then
stores it and a receipt synchronously with no intervening host callback or `await`.
A repeated command returns the identical receipt; reusing its ID with changed content
returns `COMMAND_CONFLICT`. Object field order in payload does not change identity.
A stale resource revision, denial, or callback exception produces a recorded refusal
without changing resource state. Retry a changed operation with a **new** command ID.
All callback reentrancy into `execute` returns `BUSY`.

Receipts are bounded and **never evicted**. At capacity, new commands fail closed;
old receipts remain available. Do not clear/recreate the authority to evade capacity:
that loses replay protection. Production must replace this with durable command IDs
and receipts, an appropriate retention/protocol epoch design, and database atomicity.

## Exact boundaries

- Atomicity here means a synchronous single-process reference only. Process crash,
  restart, multiple servers, OOM and durable writes are not solved.
- Only one resource is updated per command. Wallet plus inventory transactions must
  be implemented as a proper multi-resource database transaction, not chained calls.
- Callbacks are trusted host code and must be pure. The adapter cannot undo a network
  call or other external effect performed by a callback. It only prevents internal
  state mutation after deny/trap and freezes its input snapshots.
- No timing, memory or CPU sandbox is provided for the host callbacks. AsyncFunction callbacks are refused before invocation. Native Promise results
  from synchronous callbacks are rejected and their rejection is observed to avoid
  an unhandled-rejection crash; arbitrary thenables are not assimilated. Arbitrary
  trusted code can still block. Execute only admitted
  bounded policies, not malicious JavaScript functions.
- The revision is authoritative for this instance's resource. It is distinct from the
  observation counter of `invocation-context-v1.js`.
- Authentication, ownership/leases, policy admission and authorized action checks
  belong in the host's facts/decision adapter. `actorId` alone grants nothing.

## Verification

Run `node --test tests/games-authority-v1.test.cjs`. Coverage includes exact replay,
conflicting reuse, two buyers of the last item, stale revisions, policy/schema/world
binding, denial/trap, immutable snapshots, reentrancy, bounded receipts, malformed
inputs, payload normalization, revision exhaustion and async reducer refusal.
