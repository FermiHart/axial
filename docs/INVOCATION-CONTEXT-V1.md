# Invocation context v1: bounded, single-use host observations

`runtime/invocation-context-v1.js` is a generic host helper, separate from the
Axial compiler and portable VMs. CommonJS exports the API; the browser global
is `AxialInvocationContextV1`. Both expose
`profile === 'axial.invocation-context.v1'`.

The helper binds an opaque, in-process handle to one owner instance and one
observation of a request. The owner must independently obtain trusted facts,
run its policy, and revalidate its native witness before consuming a handle
and applying an effect. Issuing a context does not itself grant permission.

## API

```js
const owner = AxialInvocationContextV1.create({
  ownerId: 'native-service:local-instance', maxPending: 256
});
const binding = {
  requestId: 'request:17', actorId: 'actor:3',
  resourceId: 'asset:9', action: 'deliver'
};
const issued = owner.issue(binding);
if (!issued.ok) return;

// The application obtains a policy decision and checks its live native witness.
// If either is invalid, retire the observation without executing the effect.
if (!policyAllowed || !nativeWitnessCurrent()) {
  owner.retire(issued.ticket);
  return;
}
const consumed = owner.consume(issued.ticket, binding);
if (!consumed.ok) return;
applyNativeEffect(); // Failure here never rearms the consumed handle.
```

`create` accepts only `ownerId` and optional `maxPending`. It throws on invalid
configuration. The capacity defaults to 256 and is limited to 1..4096.
`issue` accepts exactly the four binding fields above. Labels must be nonempty
strings of at most 128 JavaScript code units without ASCII control characters.
Accessors, extra fields, symbol keys and custom prototypes are rejected;
ordinary objects and null-prototype records are accepted. No coercion occurs.

| Method | Result and behavior |
| --- | --- |
| `issue(binding)` | Returns `{ok, code, context, ticket}` on success. A refusal has no ticket and a null context. |
| `check(ticket, binding)` | Returns `{ok, code, context}` without consuming the handle. A check never authorizes a later effect without a fresh native witness and consumption. |
| `consume(ticket, binding)` | Consumes exactly one current pending handle before returning success. |
| `retire(ticket)` | Permanently retires a pending observation, for preview, denial, cancellation or native refusal. |
| `rotate()` | Invalidates all pending handles and advances this owner's local epoch. |
| `snapshot()` | Returns frozen identity, local counters, capacity, pending count and exhaustion status; never returns handles. |

Failure codes are explicit: `AXC-BINDING`, `AXC-FOREIGN`, `AXC-CAPACITY`,
`AXC-EPOCH`, `AXC-SUPERSEDED`, `AXC-CONSUMED`, `AXC-RETIRED`,
`AXC-ROTATED` or `AXC-EXHAUSTED`, as appropriate to the operation.
Successful issue/check/consume/retire/rotate use `AXC-ISSUED`,
`AXC-CURRENT`, `AXC-CONSUMED`, `AXC-RETIRED`, `AXC-ROTATED`.

## Context and revision meaning

Every successful issue returns a frozen context with exactly these fields:

```js
{
  schemaVersion: 1, ownerId: 'native-service:local-instance',
  ownerEpoch: 1, revision: 17,
  requestId: 'request:17', actorId: 'actor:3',
  resourceId: 'asset:9', action: 'deliver'
}
```

`revision` is a monotonic **observation counter within this issuer**. It does
not identify a world snapshot or detect arbitrary world changes or ABA
transitions. `ownerEpoch` is also local to this issuer's lifetime. Neither
value is durable, globally unique, a signature, an authentication proof, an
asset ownership record, or a multiplayer version. A new issuer may use the
same visible labels and counters and still rejects every old issuer's handle.

Reissuing the same `requestId` supersedes only that request's old pending
handle. Other pending requests remain current. Capacity refusal does not
silently evict a pending request. Superseding a request already in the map is
permitted at capacity. Successful consumption or retirement frees its slot.
The application must retire abandoned observations; the helper has no timer.

The context can be copied for diagnostics. A copied or serialized context,
ticket clone, foreign ticket or retired handle can never be adopted as a
capability. Private WeakMap identity, the current epoch, the current request
entry and the handle state are all checked. No import or deserialization API
exists. Hosts must not persist tickets in saves, durable acknowledgments or
network commands; durable command replay belongs to their existing authority.

## Reentrancy, limits and verification

Reading descriptors can still invoke Proxy traps. All expected-binding reads
finish **before** the helper checks its private epoch, pending entry and state.
Reentrant consumption, retirement, rotation or reissue therefore invalidates
an outer attempted consume. After those checks, consumption performs no
application callbacks. This does not turn the helper into a sandbox for
arbitrary hostile host code or remove the host's native witness obligation.

Revisions and epochs never wrap beyond `Number.MAX_SAFE_INTEGER`. Exhaustion
refuses further issuance or rotation and invalidates pending handles. Rotation
does not reset observation revisions. Consumption and retirement counts are
bounded by successful issuances. The helper executes no policy, native effect,
clock read, persistence write or network operation.

Run the focused contracts with:

```sh
node --test tests/invocation-context-v1.test.cjs
node --test tests/invocation-context-wave2-adversarial.cjs
```

The application still tests its own order of operations: derive trusted facts,
evaluate the actual Axial program, revalidate native identity and facts,
consume once, and only then mutate. A preview must retire its observation;
a fresh request or resumed operation obtains a new one.
