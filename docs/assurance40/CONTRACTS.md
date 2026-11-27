# W17–W19 — Contract inventory and bounded admission review

Source reviewed at `543848917e198f00eb4dbf05a5f7c80ceee2e33d` on 2026-11-27. Documentation
and test pointers are scope records, not authorization or new API commitments.

| Contract | Normative source / existing fixture | Observed evidence |
| --- | --- | --- |
| L1 pure CAP-free embed v1 | [BETA-LANGUAGE](../BETA-LANGUAGE.md), [ABI probe](../../tests/audit40/abi.c), [embed](../../tests/audit40/embed.c) | Audit gate normal/release/sanitizers succeeded; full trusted-main authority excluded. |
| Portable boolean pure v1 | [PORTABLE-PURE-V1](../PORTABLE-PURE-V1.md), [differential](../../tests/portable-policy-differential.cjs), make gate-portable | Portable policy consumer run 46001741560, C reference and portable execution step passed. |
| Typed decision v2 | [PORTABLE-DECISION-V2](../PORTABLE-DECISION-V2.md), [differential](../../tests/portable-decision-differential.cjs), make gate-decision | Same run, typed decisions and invocation contexts step passed. |
| Numeric v1 (experimental) | [PORTABLE-NUMERIC-V1](../PORTABLE-NUMERIC-V1.md), [numeric differential](../../tests/portable-numeric-differential.test.cjs) | Games adapters run 46001741509, five host jobs passed. |
| Host-local invocation context | [INVOCATION-CONTEXT-V1](../INVOCATION-CONTEXT-V1.md), [context fixture](../../tests/invocation-context-v1.test.cjs) | Portable decision gate passed; no external trust claim. |
| Node admission | [ADMISSION-V1](../games/ADMISSION-V1.md), [admission fixture](../../tests/games-admission-v1.test.cjs) | Games adapter regression passed on five host jobs. |

## Admission review (documentation only)

Pure decision execution and admission are distinct from host effect authority.
A normal typed error is a policy denial, not a trap; numeric results are not
permissions. Admission uses an externally trusted manifest of exact bytes,
and opaque handles are loader-local. The documented revocation is monotonic
within a loader, not retroactive to a committed effect; persistence across
restart and resource revalidation belong to the caller's authority boundary.
Do not infer a signature, durable rollback database, key rotation or process
isolation from the loader contract. These are documented limitations, not
newly discovered vulnerabilities or instructions for bypassing any control.

Existing regression evidence is scoped to the checked-in fixtures; no new
adversarial tests or production trust policy changes were added. Independent
host integration, persistence/restart guarantees, trusted manifest lifecycle
and external relying-party acceptance remain separate maintainer decisions.
See [A01](../campaign-a00-a19/A01-CONTRACTS.md) for historical responsibilities;
its Beyond snapshot is not a current integration qualification.

Evidence: [portable](https://github.com/FermiHart/axial/actions/runs/46001741560), [games](https://github.com/FermiHart/axial/actions/runs/46001741509),
[audit](https://github.com/FermiHart/axial/actions/runs/46001741433).
