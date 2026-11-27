# W40 — Final campaign acceptance

Date: 2026-11-27. Tested PR head and push checkout: `d0db85ef99b45cd3abd8405a9ec1a50172fd5294`.
Tested tree: `b3e8a56def82748269615f0a1f0b7dff94eae33a`. PR build checkout: `7754fdb54ebf3d7f095f7d6a60f9859dd5976220` (same tree).
The final ledger/report commit is a documentation-only successor. No CI result
is attributed to that successor merely because the tested implementation is
unchanged. PR #3 remains open and draft.

## Observed acceptance

13/13 workflow runs succeeded (seven pull_request, six push).
49 jobs succeeded; 2 benchmark jobs were skipped, and
matrix-specific steps were skipped as recorded in [FINAL-EVIDENCE.json](FINAL-EVIDENCE.json).
No elevated trusted-main fixtures, production assurance or release authority
are asserted. No new benchmark or independent host run is claimed.

| PR workflow | Run |
| --- | --- |
| Axial assurance build evidence | [46028587815](https://github.com/FermiHart/axial/actions/runs/46028587815) |
| Axial assurance public vectors | [46028587560](https://github.com/FermiHart/axial/actions/runs/46028587560) |
| Axial scope and static resources | [46028587522](https://github.com/FermiHart/axial/actions/runs/46028587522) |
| Portable policy consumer gate | [46028587512](https://github.com/FermiHart/axial/actions/runs/46028587512) |
| Axial assurance compiler matrix | [46028587527](https://github.com/FermiHart/axial/actions/runs/46028587527) |
| Games adapters | [46028587497](https://github.com/FermiHart/axial/actions/runs/46028587497) |
| Axial audit gate | [46028587485](https://github.com/FermiHart/axial/actions/runs/46028587485) |

Both build jobs report identical binary SHA-256:
`e039bf5f713773d9e1281ff77a698aad75cad641456d57b447537af82e6a3ec2`.
Each compared two fresh directories on one hosted runner. This does not
establish independent fixed-toolchain host reproduction. Three ordinary
capsule fixtures passed on each job; producer and reader both reported local
unsigned metadata consistency. Artifacts contain only build.json and
capsule.json with seven-day retention:
- Run [46028587815](https://github.com/FermiHart/axial/actions/runs/46028587815), artifact [15212813268](https://github.com/FermiHart/axial/actions/runs/46028587815/artifacts/15212813268), GitHub-reported ZIP digest `sha256:e30ed578adb5ae3f090ac19a86a9fd0fb2bac16035521e6842a3ff1548edceb4`.
- Run [46028580043](https://github.com/FermiHart/axial/actions/runs/46028580043), artifact [15214360208](https://github.com/FermiHart/axial/actions/runs/46028580043/artifacts/15214360208), GitHub-reported ZIP digest `sha256:d333ea5aadf6d42a8b6a5360aa65670f46326ef6999ba7c517f10915f3273e5c`.
Archive contents were not independently downloaded; no independent provenance
or signature is claimed. Structured observed build reports are retained in the
repository evidence file.

## Final ledger

37 VERIFIED, 2 IMPLEMENTED, 1 BLOCKED,
zero PLANNED. Documentary acceptances do not imply runtime certification.
W32–W34, W37 and W40 are now verified within their stated ordinary scope.

Remaining:
- W07 BLOCKED: independent upstream/vendor provenance and delta review.
- W11 IMPLEMENTED: GCC/Clang matrix observed, immutable toolchain pin missing.
- W27 IMPLEMENTED: same-runner digest comparison observed; independent fixed-toolchain host missing.

The baseline-to-tested-head comparison listed only documentation, ordinary
fixtures, CI and unsigned metadata tooling (29 paths). No existing runtime,
public header, vendor algorithm or license file was changed in this campaign.
Owner-controlled branch protection, independent review, full binary SBOM,
trusted-main qualification, signing, consumer adoption and distribution
remain outside this acceptance. No merge, signing, release or promotion.

Campaign closed with limitations; no new work is authorized by this record.
