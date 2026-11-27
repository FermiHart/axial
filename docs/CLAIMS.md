# Axial assurance scope and evidence index

Status: language/toolchain beta; no production trust-anchor qualification.
Scope baseline: `0e53839844362d736680b0ac54973b6c1c30d3e9`, inspected 2026-11-27.
This index defines how public statements are interpreted. It records source and
test references, not a fresh passing execution. For any release, bind the actual
results to the exact source revision, toolchain and target profile.

| Claim | Scope | Evidence / verification entry point | Limit |
| --- | --- | --- | --- |
| Frozen four-function public embed v1, pure and CAP-free | L1, amd64-sysv-lp64 | [BETA-LANGUAGE](BETA-LANGUAGE.md), `make gate`, `tests/audit40/abi.c`, `tests/audit40/embed.c`, `python3 tools/check-release-scope.py` | No new ABI profile or host effect authority |
| Language, types, contracts and deterministic VM instruction fuel | L1 language/toolchain | `make gate-fast`, `make gate-frontend`, `make gate-numeric` | Instruction budget is not a wall-clock or complete host resource envelope |
| Artifact signatures and checked executable laws | Standalone CLI research surface | `make gate-cli`, `make gate`, [audit80 gates](audit80/gates.md) | Selected trust anchors; checked cases are not formal proofs or external certification |
| Explicit effect grants, signed episode recording and replay | Experimental standalone CLI / host fixtures, outside L1 embed guarantee | `make gate-cli`, `make gate`, [audit80 report](audit80/REPORT.md) | No universal mediation, confidential receipts or relying-party validation |
| Host-local authority | Separate opt-in Linux host research profile | `make gate-authority` on a supported isolated host; [gate scope](audit80/gates.md) | Build-only and PR checks are not authority qualification |
| Portable policy, typed decisions and numeric profiles | Separate experimental consumer profiles | `make gate-portable`, `make gate-decision`, [portable pure](PORTABLE-PURE-V1.md), [portable decisions](PORTABLE-DECISION-V2.md), [numeric](PORTABLE-NUMERIC-V1.md) | Consumers remain responsible for trust and mutations |
| Boot-rooted trust, universal mutation mediation, native target qualification, confidential receipts, independent relying-party validation | Not approved by L1; no claim of deployment readiness | [ADR](ADR-AXIAL-0001.md), [release criteria](RELEASE-GATE.md) | Explicitly out of scope until separately accepted |

The public embed header SHA-256 is
`d51b9faa33c8bf757ca2f607282c3c97c1666b6173c29b566f6ecb9cce17e213`.
The existing ABI gate remains authoritative for its symbol and layout checks.
The new scope guard verifies this exact byte commitment and that the public
documentation points to this index. It does not prove the truth of prose.

## Evidence states

- **Implemented:** present in source; not a passing test.
- **Historically tested:** evidence tied to an earlier revision.
- **Qualified:** required checks passed on the exact release revision and
  declared host/profile, with retained outputs and independent review where required.
- **Not approved:** absent evidence or out of scope. A demonstration never
  promotes an integration to qualified.

Audit80 is retained history: its head `26eec8630e8cf1dc3a1808f1580cc12d36410a8e`
is an ancestor of the inspected main. Its reported historical results must not
be treated as a new run. Existing campaign claim IDs remain unchanged.

For campaign navigation, see [scope reconciliation](assurance40/SCOPE.md) and the
[structured claim index](assurance40/CLAIMS.json). These are evidence metadata,
not a release or authority grant.
