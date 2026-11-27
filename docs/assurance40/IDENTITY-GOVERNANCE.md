# W21–W25 — Identity and trust governance

Source review: Axial `6e44ef2b662746102ec395d28538a9b31140e091`, 2026-11-27. This is a
requirements and responsibility record, not a trust-policy implementation.

## W21: roles and boundaries

| Role | Responsibility | Evidence / limit |
| --- | --- | --- |
| Producer | Emit an artifact, identify exact source and toolchain, preserve notices | [Release gate](../RELEASE-GATE.md); producer output is not independent approval |
| Checker | Evaluate declared laws under its own versioned identity; report actual results | [ADR](../ADR-AXIAL-0001.md); CHECKED is not universal program correctness |
| Recorder | Record observed facts, decisions and effects with explicit source and scope | ADR; integrity is not proof of external truth |
| Operator | Configure and review deployment trust, grants and lifecycle; retain review evidence | Release gate; no active grants or trust anchors created here |
| Host / consumer | Obtain trusted facts, evaluate policy, revalidate native witness, apply effect under native authority | [Invocation context](../INVOCATION-CONTEXT-V1.md); handles are local and not durable credentials |

L1 is bounded by [BETA-LANGUAGE](../BETA-LANGUAGE.md). Do not conflate
standalone, local host fixtures, portable consumers or target authority.

## W22: test-only identity handling

The [A01 contract record](../campaign-a00-a19/A01-CONTRACTS.md)
specifies an isolated local-config-publication demonstration with test data
and test identities, not production stores. [W17–W19](CONTRACTS.md)
records fixture scope. This review covers the documents only, not the
contents of secret stores or a credential inventory. Use explicit test-only
labels, public standard vectors and ephemeral fixture state; no production
private keys, signing credentials, live trust manifests or copied tokens in
source, fixtures, logs or artifacts. Owner must review fixture storage before
external qualification. No credential material was read, generated or moved.

## W23: lifecycle requirements (proposed for owner review)

| Item | Required decision / acceptance record |
| --- | --- |
| Identity and purpose | Named principal, role, allowed profile, version, approval and provenance |
| Rotation | Named owner, planned replacement, reviewed transition and rollback/recovery record |
| Expiration | Explicit validity interval, trusted time source and behavior when time is unavailable |
| Revocation | Named authority, reason, effective time, distribution and acknowledgments; distinguish future decisions from already committed native effects |
| Restart and migration | Define persistence and replay expectations; require tested compatibility and independent review before adoption |
| Review | Document policy version, approvals and unresolved dependencies; no self-certification |

These are governance requirements, not protocol or runtime changes. In
particular the invocation context local epoch is not a cryptographic key
lifecycle, and loader-local revocation is not a global durable trust store.

## W24: consumer responsibility profiles

Evidence comes exclusively from the existing Axial documentation.
No consumer repository was accessed in this review.

| Consumer | Documented snapshot and scope | Remaining independent evidence |
| --- | --- | --- |
| Jash | [A01](../campaign-a00-a19/A01-CONTRACTS.md) and ADR-042 reference a core contract and a Jash pin `6c8f61ada6385dbb75a6547fc263ecf2bea5d666` in historical Beyond checkout; receiver UNWIRED | Actual consumer composition, coverage, gates and owner review; no universal mediation claim |
| Beyond | ADR/A01 historical receiver `050ba81e15dcd5304d2f833f4897964813f67e2f` (codex/gui20-phase1), received Axial `26eec8630e8cf1dc3a1808f1580cc12d36410a8e`; UNWIRED/NONE/NONE in that snapshot | Separate host/target toolchain, composed image and adoption evidence |
| RustRoots / Mordomo | [Consumer rollout](../games/CONSUMER-ROLLOUT.md) records read-only main snapshot `07d34a58cf2234bb54c8a605a88a37ffc7ed1698`, upstream pin `e37ae51a72f18ca73a52c6c60117f0f942e44e49`, portable decision v2 | Current consumer revision, lock, native state and independent integration tests; no deployment claimed |

Historical snapshots are not assertions about current consumer heads.
Reference games adapters do not replace the host's native effect authority.

## W25: governance checkpoint

Maintain the existing L1 / host / target separation. Preserve SPL-1.0,
ABI v1 and all existing runtime and wire formats. Owner-side decisions:
independent cryptographic provenance review (W07); lifecycle policy and
fixture handling approval; independently configured trust anchors; actual
consumer adoption qualification; candidate signing and branch rules.
No production trust changes, signing, release, merge or external authority
promotion took place. This is documentation acceptance only.
