# Audit80 W41–W50: explicit host-local authority

Base: `82596bf8faf607e25f7366e36381a8dad58302a1`. This opt-in profile is a new
documented interpretation for the existing local action/attempt primitives;
it is not a reconstruction of the missing ADR-059. No public embed header,
grant, receipt, action or attempt wire layout changes.

`resource_device/resource_inode` identify the held private store directory.
`previous.*` describes its `config` entry. The administrator provisions the
issuer in `authority_v1`, a private 64-byte local configuration (magic,
issuer, directory identity, reserved zeros). An enabled store rejects legacy
mutation calls, including when configuration is incomplete/corrupt. There is
no downgrade API. The service UID, host process, kernel and administration
remain trusted; arbitrary same-UID writers and external guests are outside
the claim. Configuration persistence is not a second spent ledger.

Planned proof obligations: bounded prior-content snapshot; real UID/effective
UID, boot ID and boot-time clock; mandatory active epoch; immutable prepared
inputs; under-lock re-observation before spend; fresh expiration checks;
concurrency, status/recovery and injected failures. The existing action codec
requires two distinct nonzero UIDs, so the host profile must refuse ordinary
same-UID processes instead of inventing a principal. Tests use real kernel
credential changes in disposable subprocesses where authorized.

| Wave | Implemented change | Evidence | Limits |
| --- | --- | --- | --- |
| W41 | Opt-in issuer configuration bound to held directory; lifecycle and resource observation; legacy mutation guard under owner lock. | 55 checks: activation/idempotence/wrong key, missing/foreign config, retained fd after rename, legacy mutation refusal. | Owner setup is trusted; activation may remain after an I/O refusal to prevent downgrade. |
| W42 | Under-lock prior-config observation: exact bounded read, SHA-256, checked nanosecond mtime, stable metadata and descriptor/name binding. | 56 checks: absent/empty/4096-byte state, digest/metadata, 4097-byte refusal, hardlink/symlink/FIFO/directory refusal and unchanged output on refusal. | Concurrent writers must participate in the owner lock; same-UID noncooperative writers remain in the TCB. |
| W43 | Observe actual real/effective UID, kernel boot UUID and Linux CLOCK_BOOTTIME; contexts refuse transfer across fork/credential changes. | 22 parent checks plus child assertions: actual identity, stable boot, increasing time, inherited-context refusal, same-UID refusal. Host-disabled source compiles under C99/-Werror. | Requires two nonzero distinct UIDs and Linux boot-time provider. No authenticated remote/guest principal or alternative clock fallback. |
| W44 | Mandatory active-epoch source for trust/policy pins; prepare owns immutable action/payload/observations and an independent descriptor. Real facts must match before producing the existing admission context for AG1. | W41–W44 combined: 228 parent checks plus child assertions. Missing epoch, wrong UID/executor/resource/boot/trust/policy/previous refuse without records/config creation; successful prepare survives input/owner release. | Epoch provisioning and issuer administration remain trusted. Prepare does not execute policy or mint grants; policy pins are not binary attestation. |

## Executed evidence

The normal build uses C99, `-Wall -Wextra -Werror -O2 -g` and
`_POSIX_C_SOURCE=200809L`. `security.sh` compiles product code and the standalone
main, with no identity hooks. The restricted execution surface reports UID 0
but refuses `setgroups` with EPERM. The narrowly authorized host execution of
the same binary succeeded with **real UID 1000 / effective UID 1001**, after
dropping supplementary groups and root credentials.

```
W41: audit80 security: 55 checks PASS (ruid=1000 euid=1001)
W42: audit80 security: 56 checks PASS (ruid=1000 euid=1001)
W43: audit80 security: 22 checks PASS (ruid=1000 euid=1001)
W41-W44: audit80 security: 228 checks PASS (ruid=1000 euid=1001)
```

Facts now include the mandatory `epoch_active` pins and generation. These are
read from the held private store under the owner lock, not request fields.
Request preparation compares measured identities and exact prior content,
then uses the unchanged admission projection. Its original sampled time is
retained for the AG1 decision-context root; fresh commit-time checks will be
separate so the signed context is never rewritten to pretend it was new.

`AXI_LOCAL_AUTHORITY_NO_HOST` can disable this optional host profile at build
time; it does not disable the portable core. Open/observation then refuse with
UNSUPPORTED. No clock callback or supplied boot/UID assertion can re-enable it.

When only the authorized execution surface permits credential changes, build
with `AXI_AUDIT_BUILD_ONLY=1 sh tests/audit80/security.sh`, then execute that
same `build/audit80-security/security` binary there. Exit 77 explicitly means
the host cannot supply the required distinct identities; it is not a pass.
