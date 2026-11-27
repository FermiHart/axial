# Release qualification and maintenance policy

No release or attestation is created by this document. No claim of independent
certification is made. Retain the frozen ABI and the sovereign C99 build.

## Required evidence per candidate

- Immutable candidate commit and tree, declared profile, compiler and host
  versions, exact test commands, exit results, and logs.
- Scope guard, full hosted gate on a supported trusted host, separate TSan,
  portable/decision gates, and explicitly scoped platform checks. An
  unprivileged PR check does not replace host authority qualification.
- Independent cryptographic conformance and dependency provenance review.
  Record any unresolved evidence as a blocker, not as a passing check.
- Credential lifecycle and trust-policy review for any external relying-party
  profile; separate identities where the profile requires them.
- Reproducible independent builds and artifact digest comparison; SBOM with
  source-derived component provenance and LicenseRef-SPL-1.0 license text.
- Maintainer-controlled signed tag, SHA-256 manifest, verifiable build
  provenance and release attestation. Check them from a clean consumer
  environment against an independently configured trust anchor.
- Review and migration notes (particularly CHECKED artifacts and ABI claims).

## Repository governance

Maintain code-owner routing and private reporting. Configure branch rules and
required checks only after confirming successful runs and the actual check
names. Require independent review when qualified reviewers are available;
never fabricate a second reviewer or bypass an unavailable gate.
Enable signed-commit enforcement only after the maintainer's signing workflow
and recovery path are tested. These are owner-side administration requirements,
not properties established by a CODEOWNERS file or an unsigned commit.

## CI profiles

Pull requests and non-main audit branch pushes run the unprivileged audit
subset, including authority build-only, but never the explicitly elevated
authority fixtures. The full authority gate remains a trusted-main push
qualification on a dedicated ephemeral GitHub-hosted runner. A separately
scoped fast matrix exercises Clang, optimized UBSan, and leak detection;
it is not a full product sanitizer or cross-architecture qualification.

## Additional upgrade candidates

1. Machine-readable release evidence manifest with immutable revision,
   profile, toolchain, test status and evidence digests; reject stale evidence.
2. Independent clean-room portable artifact and decision parity across
   supported architecture/compiler combinations; introduce a new named ABI
   profile only after separately accepted layout and symbol checks.
3. Explicit lifecycle for trust snapshots and signer roles, with migration
   and revocation policy accepted before external deployment.
4. Differential conformance, memory/resource accounting and repeatable
   performance baselines with externally reproducible measurements.
