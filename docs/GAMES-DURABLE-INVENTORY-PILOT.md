# Durable inventory lifecycle pilot (reference only)

This optional Node 22.13+/24 example combines a real C-compiled Axial decision
artifact, trusted digest admission and SQLite single-resource state/receipt commit.
It is neither RustRoots integration nor a production inventory/network service.

Run `node examples/games/durable-inventory-pilot.cjs`. The demo builds the compiler,
exports `examples/games/inventory.axi`, creates a temporary database, reserves a car
for its owner and replays the command without a second state change. It prints
results and removes only its own temporary directory. In this demo the digest is
computed by the trusted build process. A deployment must supply a trusted pinned
manifest; computing a digest of arbitrary client bytes does not establish trust.

The factory accepts policy bytes and a trusted `inventory.facts.v1` entry. Submission
accepts a trusted authenticated session plus bounded request JSON (1,024 bytes).
The request has exactly `commandId`, `resourceId`, `expectedRevision`, `action`,
`target`. Actions are `reserve` (`target:null`) and `transfer` (target actor label).
The client cannot provide actor identity or policy facts. Host callbacks reconstruct
`authenticated`, `exists`, `owns`, `unreserved` from server session and the row read
**inside** the SQLite writer transaction. Only the admitted policy's allowed result
reaches the reducer. Fuel is bounded to 64; a policy trap becomes `TRAP`, not permission.

`observe()` is a read-only convenience snapshot, never an authorization. If ownership
changes after observation, a request with the old revision refuses as `STALE`; a new
request by the former owner refuses as `DENY / NotOwner`. `revoke()` blocks new policy
evaluations in this process. A committed receipt remains a committed result even
when the policy is subsequently revoked: replay reports historical truth, not a new
execution. Failed commands also retain receipts; changing a failed operation needs
a new command ID, not silent retry with modified contents.

## Deliberate limits

- Session authentication is assumed to be performed by the caller's trusted server.
  Passing a player-supplied session object would violate this example's boundary.
- Revocation is process-local and not a distributed/persisted registry. On restart,
  deployment must load its current trusted manifest and revocation configuration.
  Do not assume restarting maintains a revocation made only in memory.
- This is one resource per transaction. No wallet debit, marketplace settlement,
  fees, stock issuance, item scarcity or multi-resource transfer is implemented.
- The example does not change the boolean policy or enable general host calls.
- No network delivery, load proof, production migration, backup implementation or
  multiplayer deployment is asserted. See the SQLite adapter document for storage,
  locking and recovery limitations.

## Verification

`node --test tests/games-durable-inventory-pilot.test.cjs` executes the real compiled
policy and SQLite adapter: owner reserve, restart/replay, ownership change before
commit, revocation before commit, replay after revocation, forged client facts,
authentication refusal, artifact tampering, schema mismatch, fuel exhaustion and
receipt capacity. Tests skip explicitly if `node:sqlite` is unavailable. Build the
exporter first in a clean checkout (`node tools/portable-decision-build.cjs`).

## Public endpoint limits

Do not expose `submit` directly as an internet endpoint. Bind command identifiers
and session identity at the trusted host boundary so one player cannot deliberately
collide with another player's global command-id namespace. Apply authenticated
rate/admission quotas before the durable adapter: distinct denied command IDs can
consume the bounded receipt store and intentionally force fail-closed capacity.
The generic scheduler is not wired into this pilot, and its actor identity must
also come from authenticated infrastructure. Revocation is process-local: reopening
with the same trusted manifest readmits the policy. Durable policy revocation and
manifest rollback prevention require the deployment's version/revocation store.

## Opt-in durable revocation

Pass `persistedRevocation:true` in factory configuration to use the SQLite adapter's
monotonic persisted policy lifecycle. The pilot's host-only `revoke()` then returns
an `{ok, code}` result: only `REVOKED` establishes success. A storage or contention
failure leaves the local admission loader unchanged, so failures cannot masquerade
as a completed durable revocation. New commands in all instances read the persisted
state transactionally; restart does not readmit effects merely by reusing the same
manifest. Existing committed receipts still replay unchanged.

Default `false` preserves the earlier process-local behavior and return value.
This mode is fixed in database metadata; changing it requires an explicit migration,
not silently reopening the same file with different options. No migration or
un-revoke is implemented. The JavaScript administration method must not be exposed
to players. This is still not remote identity or a production control plane.

Receipt storage can be saturated by otherwise well-formed denied commands. Apply
external authenticated rate limits and command ID namespace controls; the example
has no rate limiter or per-player quota. Global IDs must not be blindly accepted
from clients without collision/squatting controls. See the SQLite reference notes.

For a new deployment, explicitly choose `persistedRevocation:true` as the CLI
demo does. The API default stays false solely for backward compatibility; existing
databases require the documented explicit migration, not a mode toggle.
