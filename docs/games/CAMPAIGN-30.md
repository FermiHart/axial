# Games hardening campaign

This campaign is additive. It does not claim a deployed multiplayer service,
anti-cheat protection of an attacker-controlled client, or a new C bytecode ABI.

## Acceptance ledger

| Waves | Goal | Status |
|---|---|---|
| 1 | Define trusted host/client boundary and threat assumptions | implemented below |
| 2 | Bound and decode untrusted policy/facts bytes | games-admission-v1 |
| 3 | Admit actual SHA256 bytes against external trusted manifest | games-admission-v1 |
| 4 | Opaque handles and monotonic loader revocation | games-admission-v1 |
| 5 | Adversarial mutation, forgery, fuel and bounds gate | 10 tests, admission.tap |
| 6–10 | Reference revision/CAS, idempotency, binding, reentrancy, contention tests | 13 tests; in-memory scope only |
| 11–15 | Quantitative checked arithmetic and compiler integration | host helper tested; compiler integration pending |
| 16–20 | Quotas, batch and representative measurements | scheduler tested; realistic workloads pending |
| 21–25 | Fuzz/differential and cross-platform validation | pending |
| 26–30 | Pilots, SDK lifecycle, rollout and integration | pending |

Waves are accepted only against named evidence, not by counting commits.
A helper/reference fixture is not a finished production integration.

## Threat boundary

The player controls the client. A client-side decision is only prediction/UI.
The authoritative host supplies facts, chooses admitted policy, revalidates
resource ownership/revision, and performs effects transactionally. Existing
portable v2 remains pure and returns allow/deny/trap/refused; none is an effect.

The manifest is trusted deployment configuration, not a field of a player
request. Its SHA256 digest pins exact serialized bytes (whitespace changes
therefore require a new pin). The compiler's declared source/body hashes are
not used for authentication. Digest pinning is not a signature protocol.
Revocation invalidates existing handles, but restart/rollback prevention must
be enforced by the host's durable version store. The loader is not a JS realm
sandbox. Trusted host API calls/configuration must not be malicious Proxies.

No changes to RustRoots are made here. Its parallel Mordomo integration must
explicitly adopt these adapters after its own tests and version lock update.
