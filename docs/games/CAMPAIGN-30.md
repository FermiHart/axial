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
| 16–20 | Quotas, batch and representative measurements | per-actor pending limits + 100k-operation model; synthetic 1,000-actor workload measured, engine workload pending |
| 21–25 | Fuzz/differential and cross-platform validation | seeded corpus and C helper oracle implemented; platform/sanitizer matrix pending |
| 26–30 | Pilots, SDK lifecycle, rollout and integration | three compiled fixture pilots tested; SDK boundary documented; real engine rollout pending |

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

Current acceptance: waves 1–15 closed within the explicit narrow profiles above;
16–30 remain partial until representative runtime workloads, broad platform
validation and consumer rollout. Node SQLite requires a supported Node runtime.

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
adds eight lifecycle tests; it is not an adopted RustRoots service. Therefore
waves 16–30 remain partial, rather than being marked complete by fixture counts.
