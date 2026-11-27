# W26–W30 — Build and distribution evidence

## Build evidence protocol

The [workflow](../../.github/workflows/assurance-build.yml) builds the
ordinary standalone CLI twice into separate fresh directories, under one
hosted Ubuntu runner with the same checkout, compiler and explicit flags.
It records the exact checkout commit/tree (PR may be a merge revision),
compiler and linker versions, target, architecture, flags and commit-derived
SOURCE_DATE_EPOCH. It records SHA-256 of both `axi` outputs and four explicit
source/notice files. Output is sorted JSON in the CI log and job summary.
A digest mismatch retains both observed digests and fails the check.
No release, key, signing or production artifact is used.

This tests same-runner clean-build repeatability, not independent host or
immutable toolchain reproducibility. Hosted runner images and installed
packages may change. An independent owner-controlled build on a separately
provisioned fixed toolchain is still required before release acceptance.
No digest or equality result is asserted before reading actual CI evidence.

## Inventory and verification

[COMPONENTS.json](COMPONENTS.json) is a source-derived inventory with exact
Git blob identities, declared license notices and known build/optional
consumer dependencies. It is not a complete binary SBOM or legal finding.

For each candidate, review the commit, tree, exact profile and build inputs,
then compare the observed SHA-256 manifest to an independently obtained
trusted manifest for the *same* artifact/profile. A digest alone establishes
byte equality relative to that manifest, not source authorship or authority.
Preserve LICENSE and vendor notices. Retain mismatches and limitations.
Independent reviewers must examine provenance (W07), reproducibility and
license coverage. The maintainer controls signing and release publication
under [RELEASE-GATE](../RELEASE-GATE.md); no signed tag or release is created
by this campaign. Do not treat CI metadata as a runtime trust anchor.

## W30 checkpoint

W21–W25 documented role/fixture/lifecycle boundaries and historical consumer
snapshots. W28 inventory reconciled against the source tree. W26/W27/W29
workflow implemented; execution and observed metadata/digests remain pending.
W11/W12: six compiler matrix jobs passed; version and numeric warning logs
not retrieved and hosted image not immutable. W16: four public-symbol/layout
comparisons passed. W20: integrated evidence reconciled with limitations.
W07 and independent trusted-main authority qualification remain open.
Next: evidence capsule metadata only; no runtime/wire format migration.
