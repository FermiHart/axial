# W10 — cryptographic conformance checkpoint (pending execution)

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
Record exact source digest and run IDs on completion. W04 scope regression and
W08/W09 vector outcomes are pending, not passing. W07 provenance remains blocked
on pinned original upstream artifacts and independent local-delta review.
Independent cryptographic assessment, full trusted-main qualification and any
external trust deployment remain unapproved.

References: [RFC 8032 section 7.1](https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1);
[NIST secure hashing](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing).
