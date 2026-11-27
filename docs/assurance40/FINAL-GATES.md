# W36–W39 — Integrated gate and readiness record

Observed PR head: de9d5836f9515073ee4376e0862524518c4fa872. Actual build checkout:
cf792be2a91489d52978bc62cfffcd07cd746a26, tree 3efbdf4427ae8c34d2028761312cb3a5a66d9111.
Seven PR workflow runs succeeded; Games benchmark skipped, matrix-specific
steps skipped where not selected. PR/non-main audit mode does not execute
elevated trusted-main authority fixtures. Pages publication is not qualification.

| Workflow | Run | Observed job names / host |
| --- | --- | --- |
| Axial assurance build evidence | [46018316942](https://github.com/FermiHart/axial/actions/runs/46018316942) | ordinary-build-evidence; Ubuntu 24.04 |
| Axial assurance compiler matrix | [46018316941](https://github.com/FermiHart/axial/actions/runs/46018316941) | ordinary (clang, -O1/-O2), ordinary (gcc, -O1/-O2), warnings (clang), warnings (gcc); Ubuntu 24.04 |
| Axial assurance public vectors | [46018317388](https://github.com/FermiHart/axial/actions/runs/46018317388) | vectors (clang, 0/1), vectors (gcc, 0/1); hosted ordinary fixtures |
| Axial audit gate | [46018316948](https://github.com/FermiHart/axial/actions/runs/46018316948) | gate (normal/sanitizers/release), focused (clang/optimized-ubsan/leak-fast), threads; Ubuntu 24.04 |
| Portable policy consumer gate | [46018316967](https://github.com/FermiHart/axial/actions/runs/46018316967) | portable; Ubuntu 24.04 |
| Games adapters | [46018316926](https://github.com/FermiHart/axial/actions/runs/46018316926) | node (20/22/24, ubuntu-24.04), node (24, ubuntu-24.04-arm), node (24, macos-15); benchmark skipped |
| Axial scope and static resources | [46018316972](https://github.com/FermiHart/axial/actions/runs/46018316972) | scope; Ubuntu 24.04 |

Observed main 0e53839844362d736680b0ac54973b6c1c30d3e9; branch endpoint
protected=false; rulesets empty; protection detail HTTP 403. Required
status checks are not independently established. These are observed jobs
and policy gates, not asserted configured branch rules.

## Migration review
[BETA-LANGUAGE](../BETA-LANGUAGE.md) freezes ABI v1, amd64-sysv-lp64, four
symbols, pure CAP-free execution. [ADR](../ADR-AXIAL-0001.md) D08 and D15
distinguish integrity, authenticity, CHECKED, authority, ABI and formats.
Changed checker identity or semantics require separately accepted migration
and rerun/reseal where applicable. No runtime or wire-format change here.

## Owner readiness actions
Per [RELEASE-GATE](../RELEASE-GATE.md): independent vendor provenance (W07),
fixed-toolchain and independent host reproduction, trusted-main qualification,
lifecycle and consumer adoption review, full binary SBOM and license review,
branch rules and independent review, signing and recovery, release manifest
and attestation, independent trust anchor. No signing, release or merge.
