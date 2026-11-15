# Optional SQLite single-resource authority reference

`runtime/games-authority-sqlite-v1.cjs` adds durable receipts and state to the
in-memory reference contract. It uses only built-in `node:sqlite` and requires
Node 22.13+ without experimental flags; tested here with Node 24.22.1. The module
loads SQLite lazily on creation. Older Node versions can use the other adapters.
It is **not** a deployed server, identity provider, anti-cheat system, production
schema migration system or distributed database.

## Guarantees and scope

- `BEGIN IMMEDIATE` serializes database writers. Resource revision CAS, new state
  and the complete command receipt are in the same SQLite transaction.
- A command retried after process restart or response loss reads its persisted
  receipt; a conflicting reuse of the ID refuses. Receipts are not evicted.
- World/policy digest/schema bindings are persisted. Reopening with mismatched
  configuration refuses, not silent upgrade. Initial resources only seed a new DB.
- Denials and traps persist refusal receipts, never a resource update. SQL failures
  roll back both writes. A rollback failure quarantines the handle until closed.
- WAL + `synchronous=FULL` is configured. Actual durability remains dependent on
  SQLite, filesystem and storage honoring flush/locking semantics. It is not a
  proof against storage failure or host tampering.
- Lock contention has a bounded busy timeout (default 2 seconds; maximum 30),
  returning `BUSY` when acquisition fails. Retry is safe with the same command ID.
- At receipt capacity, new commands fail closed. Storage growth requires an explicit
  retention/epoch/archive design; restarting is not a receipt garbage collector.

## Use and trust boundary

`create({...memoryAdapterOptions, filename, busyTimeoutMs})` returns
`execute(commandJson)`, `inspect(resourceId)` and `close()`. `filename` is a
**trusted host configuration**, never a user-controlled path. Authentication must
bind caller identity and the host must admit the policy before evaluation. A digest
string alone does not authenticate code. Host callbacks remain trusted synchronous
pure functions; arbitrary JavaScript is not sandboxed or rolled back. Only internal
single-resource state and receipts are transactional. Multi-resource wallet/item
transfers require a different schema and real multi-resource transaction design.

No asynchronous callbacks, network effects or filesystem effects belong inside
`decide`/`reduce`. Transactions hold the writer lock while these callbacks run;
callbacks must be bounded. Parsing and callback overhead are not VM fuel.

The database stores JSON state and receipts. No backup/restore, schema migration,
key rotation or remote replication protocol is implemented. Back up with SQLite's
supported backup mechanisms or a consistent closed snapshot, not by copying only
the main file while WAL writes are active. Do not put WAL on an unsupported network
filesystem. `inspect` returns copies and is a diagnostic read, not an authorization
for a later action. SQLite files must be protected using deployment filesystem
permissions and backups, neither of which this helper configures.

A `STORAGE` result can be retried using the same command ID; the durable receipt is
the truth if a commit succeeded before response loss. `STORAGE_QUARANTINED` requires
closing/reopening and operator investigation; the adapter never bypasses a failed
rollback. This is a reference for local services, not a claim of multi-region
consensus, load validation, mobile readiness or production deployment.

## Tests

`node --test tests/games-authority-sqlite-v1.test.cjs`

Tests execute real temporary SQLite files, reopen and child processes, abrupt exit
immediately after COMMIT before printing the response, two writers racing for the
last resource, binding mismatch, refusal replay, receipt limits, lock contention,
forced receipt INSERT failure with full rollback, reentrancy and closed handles.
When `node:sqlite` is unavailable, these tests explicitly skip; that is not a pass
of durable behavior. CI should run this suite on Node 24 (or another supported
version) in addition to existing portable gates.

## Optional persisted revocation lifecycle

Pass `persistedRevocation:true` when creating a **new** authority database to opt in.
The setting is included in its persistent binding. Reopening with the option off,
or enabling it on an existing legacy DB without an explicit migration, fails with
binding mismatch. This prototype deliberately provides no automatic migration,
policy replacement, un-revoke operation or administrative network endpoint.

The trusted host receives `revokePolicy()`. It serializes on `BEGIN IMMEDIATE`, marks
the policy revoked monotonically and commits. `REVOKED` means this database durably
records the revocation under the same storage assumptions as other commits. `BUSY`
or `STORAGE` is not success; retry/inspect operationally rather than announcing it.
A failed rollback quarantines the handle. Repeated successful revocation is harmless.
Never expose this method through untrusted command dispatch or accept a client
revocation flag. Its caller is a trusted deployment administrator, not a player.

Every new command reads this state inside its transaction before policy callbacks.
A revoked policy returns a persisted `DENY / policy-revoked`, without effects.
Already committed/refused receipts are returned **before** this check: replay reports
historical truth and never reexecutes effects. Concurrent writers are ordered by
SQLite's transaction lock. A command committed before revocation stays committed;
a new command beginning after revocation committed cannot produce effects. Other
already-open adapter instances observe the persisted state on their next command.

The receipt bound remains fail-closed. Authenticated denied requests can fill that
bound: deployment must enforce per-actor/request quotas and an explicit retention
protocol. Command IDs form a global namespace in this prototype; generate host-bound
names or suitable unique identifiers and enforce actor binding to prevent collision
or deliberate squatting. This helper does not supply that network admission layer.
