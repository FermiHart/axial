# Axial Sovereign Assurance — W01–W40

Authorized 2026-11-27. Repository: FermiHart/axial. Work exclusively on
`audit/axial-assurance-20261127`, PR #3, preserving the current main and Audit80 history.

Baseline `d2ed63af63624fbdab51bcf2fb60465ed29b6b84`: seven recorded hosted workflow runs succeeded.
See [STATUS.json](STATUS.json) for their IDs and individual wave acceptance.
The baseline does not include trusted-main privileged authority qualification.

## Execution protocol

Work sequentially; resume from the ledger and actual Git head. Verify each
change with appropriate ordinary regression checks, record exact evidence,
and publish checkpoints after W10, W20, W30 and W40. IMPLEMENTED is not VERIFIED.
Do not fabricate completion, test results or external assurance. If unavailable
infrastructure blocks a criterion, record BLOCKED, scope and next safe work;
do not count it as a verified wave. The ledger is a record, not a trust anchor.
Check the branch head before writes; never force push or silently overwrite
another agent's work. Reports distinguish historical evidence from current runs.

Scope: defensive maintenance, standard conformance, ordinary local regression,
documentation, CI, reproducibility and nonsecret evidence artifacts. No external
targets, operational exploitation, offensive automation, production credentials,
live trust policy changes, cryptographic algorithm changes without separate
maintainer review, privilege changes, release signing, publication, or merging.
No runtime or wire-format migration without explicit maintainer review.
Retain SPL-1.0, sovereign C99 build, public ABI v1, and existing scope boundaries.

## Wave acceptance matrix

| Wave | Deliverable | Acceptance |
| --- | --- | --- |
| W01 | Campaign baseline and acceptance ledger | Pin the reviewed baseline, scope, workflow results and 40 ordered acceptance criteria. |
| W02 | Scope documentation reconciliation | Cross-reference the normative ADR, beta boundary and campaign evidence; preserve L1 and distinguish experimental profiles. |
| W03 | Structured claim index | Create a versioned machine-readable claim inventory using stable existing claim IDs where applicable; check references and status vocabulary. |
| W04 | Scope gate regression coverage | Test the documentation/header guard with isolated ordinary fixtures and check its failure reporting. |
| W05 | Governance checkpoint | Record release administration requirements, maintainer ownership and review dependencies without asserting unavailable owner controls. |
| W06 | Crypto source attribution inventory | Record exact vendor files, digests and source notices, and identify provenance items still needing independent review. |
| W07 | Upstream provenance review | Compare documented origins against available authoritative upstream records; preserve license notices and report uncertainty. |
| W08 | Standard signature conformance | Use published standard positive known-answer vectors on local test fixtures; record results and exact scope. |
| W09 | Hash conformance | Validate standard SHA-256 and SHA-512 known-answer vectors in supported implementation profiles. |
| W10 | Crypto review checkpoint | Record conformance evidence and unresolved independent review requirements; do not certify security or alter cryptographic algorithms automatically. |
| W11 | Compiler portability matrix | Qualify ordinary builds on available supported GCC and Clang versions with pinned inputs. |
| W12 | Warning baseline | Measure and document additional compiler warning classes; make narrowly scoped nonsemantic fixes when supported. |
| W13 | Memory accounting | Qualify leak detection for supported ordinary workloads and separate process-tracing limitations. |
| W14 | Optimized build parity | Compare ordinary golden behavior across supported optimization profiles. |
| W15 | Portable architecture evidence | Record available native CI architecture results, distinguish portable consumer evidence from full C ABI qualification. |
| W16 | Public ABI evidence | Verify exact frozen header and existing layout/symbol contract without expanding the ABI. |
| W17 | Contract inventory | Index documented contract interfaces and their existing test entry points. |
| W18 | Decision semantic parity | Run existing approved local policy conformance fixtures across supported reference and portable implementations. |
| W19 | Admission contract review | Document expected decision semantics and existing regression coverage; flag gaps for separate maintainer review. |
| W20 | Contract checkpoint | Reconcile source, documented boundaries and verified tests; no promotion of experimental authority. |
| W21 | Identity roles | Document producer, checker, recorder, operator and host responsibilities and existing fixture boundaries. |
| W22 | Test credential handling | Review test-only identity documentation and safe fixture storage; avoid production credentials or signing keys. |
| W23 | Trust lifecycle requirements | Specify reviewable rotation, expiration and revocation requirements without modifying live trust policy. |
| W24 | Consumer responsibility profiles | Record the actual Jash, Beyond and RustRoots integration scope without writing to consumer repositories. |
| W25 | Trust governance checkpoint | Collect decisions and remaining owner-side dependencies; no external trust-anchor promotion. |
| W26 | Build metadata capture | Capture revision, compiler, target and flags as deterministic metadata. |
| W27 | Build reproducibility | Compare independent ordinary local or hosted builds with fixed source and toolchain inputs; preserve differences. |
| W28 | Component inventory | Produce source-derived dependency and license inventory suitable for an SBOM. |
| W29 | Artifact manifest | Generate deterministic digests for explicitly selected nonsecret build outputs. |
| W30 | Distribution evidence checkpoint | Document verification procedure and owner-controlled signing requirements; do not sign or publish releases. |
| W31 | Evidence capsule schema | Define a versioned manifest for revision, profile, test results and evidence digests. |
| W32 | Evidence capsule producer | Implement deterministic local metadata packaging with no secret or production input. |
| W33 | Evidence capsule reader | Validate schema and reference integrity in local ordinary fixtures; do not treat unsigned metadata as authorization. |
| W34 | Evidence capsule CI integration | Produce nonsecret evidence artifacts in read-only CI with bounded retention. |
| W35 | Evidence capsule documentation | Provide example and limits; distinguish integrity, provenance and independent trust. |
| W36 | Integrated gate inventory | Reconcile current required checks and their exact names and host constraints. |
| W37 | Qualification run | Observe actual available CI results for the candidate; record skipped, unavailable and failing checks explicitly. |
| W38 | Migration review | Check documentation for ABI, checker identity, and compatibility implications of the candidate. |
| W39 | Release readiness review | Compile remaining owner-side signing, review, branch protection and distribution actions without changing them. |
| W40 | Final campaign acceptance | Produce the exact commit, gate evidence, outcomes and unresolved blockers; retain PR draft for maintainer acceptance. |

## Reporting

At each checkpoint report verified/implemented/blocked counts, changes, exact
commit and CI links, unresolved dependencies, and next waves. Continue within
the available session without asking for routine approval; retain the checkpoint
and resume on the next scheduled execution if the session ends. At W40 report
final readiness, not an invented production certification.
