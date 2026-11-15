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
| 6–10 | Reference revision/CAS, idempotency, binding, reentrancy, contention tests | 16 in-memory + 10 SQLite tests; single-resource durable adapter |
| 11–15 | Quantitative checked arithmetic and compiler integration | modular i64 compiler profile + checked host helper; 16,500 native VM comparisons |
| 16–20 | Quotas, batch and representative measurements | implemented: per-actor quotas, independent 100k-operation model, measured 100k admitted-policy workload and immutable preparation; final CI required |
| 21–25 | Fuzz/differential and cross-platform validation | implemented: seeded native differential, hostile bytes, regressions and verified Linux x64/ARM64 + Darwin ARM64; latest checkpoint CI required |
| 26–30 | Pilots, SDK lifecycle, rollout and integration | compiled pilots + durable single-resource reference + persistent revocation tested; actual consumer adoption/rollout pending |

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

## Partial-work evidence (not completed-wave claims)

- Checked numeric host helper with 11,362 C __int128 oracle cases. This is not
  parity with the native modular Axial arithmetic or a compiler-integrated profile.
- Three compiled .axi fixture pilots (door, inventory, race), 3,168 native/JS
  comparisons; these have no production effects or network server.
- Bounded scheduler and 1,000-item synthetic workload. Benchmark is Node x64 only.
- 10,000 byte mutations and 10,000 garbage facts, seeded, not coverage-guided fuzz.
- Node 20/22/24 Linux, Node 24 ARM64 Linux and macOS CI are configured;
  remote results must be checked separately, not assumed from configuration.

Do not present the remaining blocks as completed on these partial proofs.

## Second implementation block

Portable numeric v1 now compiles real .axi through the C compiler and matches
native i64 modular arithmetic; checked/fixed-point host helpers remain distinct.
The optional Node SQLite adapter commits one resource and its idempotency receipt
in the same transaction and passed restart/lost-response/two-process contention.
It still is not a multiresource production database or deployed game authority.

Current acceptance: waves 1–15 closed within the explicit narrow profiles above.
Waves 16–25 now have implementation and bounded host/runtime evidence listed below;
accept their latest checkpoint only after its required CI concludes successfully.
Waves 26–30 remain partial until actual consumer adoption and rollout. Node SQLite
requires a supported Node runtime.

## Follow-on local validation

The scheduler now limits each actor's pending item count and UTF-8 payload bytes,
retaining that accounting across ticks until selection. Seed 123 covers 100,000
operations against an independent queue/accounting model. A separate reproducible
benchmark measures 1,000 actors across 100 ticks (100,000 commands) with individual
enqueue, batch and harness-inclusive tick samples. It is synthetic Node x64 work,
not an engine, browser, phone or production service benchmark.

The reference adapters remain additive; RustRoots integration/pin is unchanged.

The follow-on numeric corpus performs 97,920 native-VM/JS comparisons over 16
fixtures, full-width seeded inputs and bounded fuel, plus 512 malformed opcode
refusals. Plain and explicit ASan/UBSan-without-leaks runs passed locally.
LeakSanitizer was blocked by ptrace here; CI is configured to attempt the full
sanitizer gate, but is not yet verified. A runnable admitted-policy/SQLite pilot
adds eight lifecycle tests; it is not an adopted RustRoots service. This evidence does not by itself complete the consumer rollout block.

## Latest measured optimization and lifecycle

`prepare` owns a validated immutable decision-program snapshot. Public `evaluate`
continues validating untrusted programs; admission still hashes exact bytes, checks
revocation on every call and validates facts/fuel. The identical 100,000-decision
workload retained every allow/deny/fuel-trap count. Local paired and warmed
alternating measurements are preserved in `docs/games/evidence/`, not generalized
to phone/engine capacity. Budgeted runs execute the same total decisions across
more ticks, explicitly trading frequency/queue delay rather than claiming speedup.

Optional SQLite persisted revocation is monotonic, serializes with execution and
survives process restart. Existing committed receipts replay unchanged. The mode is
part of the database binding, so no implicit downgrade or migration is accepted.
New CLI demo databases opt in; existing API defaults remain compatible.

Prior commit `6ae98f1f4c44f7753396b7babd614b0ad74b4ab1` passed all four remote
workflows, including actual macOS ARM64 execution and Linux sanitizers. That does
not substitute for checking the new prepared/revocation checkpoint. Local final
combined gate passed 133 tests with zero skips, plus the runnable demo.

## Accepted checkpoint after remote verification

At `aa3003f34b969bcfbc1184c26fbc508048e245b9`, all four remote workflows
concluded success: Games 43717201551, Portable consumer 43717201546,
Pages 43717201544 and Audit 43717201608. Games exercised Linux Node 20/22/24,
Linux ARM64 and macOS 15 ARM64; Node 24 Linux/macOS logs report 133 passed,
zero skipped. Linux numeric ASan/UBSan ran with leakDetection=true.

Waves 16–25 are accepted within the bounded host/runtime and test-matrix scope
above, bringing accepted work to 25/30. No claim of game/client protection,
phone performance or generalized proof of VM correctness follows from those tests.
Waves 26–30 remain partial until coordinated consumer adoption and rollout.
See [consumer rollout contract](CONSUMER-ROLLOUT.md) for the verified current
consumer, migration constraints, rollback and required revalidation.
