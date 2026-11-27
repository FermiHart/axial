# W10 — cryptographic conformance checkpoint (hosted fixtures passed)

W01–W09 deliverables and evidence are recorded in [STATUS.json](STATUS.json).
The [vendor inventory](VENDOR-INVENTORY.md) identifies exact tracked Git blobs
and separates source attribution from independent upstream verification.
The [public vector fixture](../../tests/assurance40/public_vectors.c) covers
three positive Ed25519 vectors (RFC 8032 section 7.1), and three standard
SHA-256/SHA-512 examples (empty, abc, 112-byte message). It tests only public
data and public standard test seeds. No production keys, external targets,
algorithm changes or release signing.

The new read-only [workflow](../../.github/workflows/assurance-vectors.yml)
compiles under GCC and Clang, default dispatch and forced software. A default
dispatch pass alone does not establish that SHA-NI ran; inspect actual logs.
The following run and job records were retrieved on 2026-11-27 for PR head
`543848917e198f00eb4dbf05a5f7c80ceee2e33d`. Scope regression step passed in [run 46001741430](https://github.com/FermiHart/axial/actions/runs/46001741430) (job 140514839158). All four positive vector jobs passed in [run 46001741391](https://github.com/FermiHart/axial/actions/runs/46001741391) (jobs 140514839316, 140514839581, 140514839640, 140514839885). The push counterpart 46001733982 also completed successfully. These are hosted job/step conclusions; stdout, exact toolchain versions, content SHA-256 values and actual hardware dispatch were not independently recovered from logs. W04/W08/W09 are verified within the recorded fixture scope. W07 provenance remains blocked
on pinned original upstream artifacts and independent local-delta review.
Independent cryptographic assessment, full trusted-main qualification and any
external trust deployment remain unapproved.

References: [RFC 8032 section 7.1](https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1);
[NIST secure hashing](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing).
