# W31–W35 — Unsigned evidence capsule v1

Offline build metadata, not an Axial runtime, AXB, AXBS or CHECKED format.
It conveys no authority or independent provenance. [Schema](CAPSULE-SCHEMA.json)
describes the fields. The ordinary hosted workflow retains only two metadata
files: build.json (observed build report) and capsule.json (deterministic
manifest binding its exact bytes by SHA-256). The revision is the actual
checkout, which may be a PR merge revision, not the PR head.

From the repository root, using the explicitly synthetic example:

    python3 tests/assurance40/capsule.py
    mkdir -p /tmp/axial-capsule-example
    cp docs/assurance40/examples/build.json /tmp/axial-capsule-example/
    python3 tools/assurance_capsule.py produce /tmp/axial-capsule-example
    python3 tools/assurance_capsule.py verify /tmp/axial-capsule-example

A consistent capsule with a mismatch is a consistent record of a failed
comparison, not a passing build. The workflow separately fails on unequal
output digests. No secrets, arbitrary file inventory or executable artifacts
are packaged. Retention is seven days. The example is synthetic, not observed
build evidence. Obtain a trusted manifest separately to establish provenance;
the reader checks only local metadata consistency. Independent host
reproduction, trusted-main qualification and owner release review remain open.
