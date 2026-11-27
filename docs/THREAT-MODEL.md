# Threat model: scope baseline

Assets: artifact identity, selected trust roots, integrity of checked-law
results, compiler/runtime availability, authority boundaries, episode integrity,
and release provenance. Separate source integrity from trust in the producer,
checked behavior, operator authorization and host enforcement.

Actors: source author, producer, checker, operator, recorder, host, consumer,
and release maintainer. The demo may reuse a deterministic public fixture;
production credentials must never reuse fixture identities. Independent actors
and authorization policies must be qualified for the relevant profile.

Trust boundaries: source/compiler, encoded artifact/decoder, pure VM/embed,
experimental host effect adapter, portable consumer, CI, and distribution.
The host and the operator's trust-anchor management remain in the trust base.
Host compromise, universal mutation mediation, physical power-loss behavior,
confidential receipts, and third-party certification are not L1 guarantees.

Required assurance work before any promotion: independent cryptographic
conformance review, canonical format compatibility, key lifecycle and
revocation policy, reproducible build evidence, resource limits by profile,
cross-platform parity, and independently reviewed release provenance.
Record evidence per revision; do not silently promote a previously tested
implementation or a demo to a new scope.
