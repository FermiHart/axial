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
| W45 | Connect the held-fd profile to the existing signed AG1/attempt owner. Reobserve resource/prior state and exact epoch generation under LOCK_EX before records creation/spend/effect. Read replay state first. | 421 checks: grant for A through B, unseen/edited/replaced prior file, advanced epoch, retained target after directory rename, copied mutable payload/action, committed replay with no effect. All 14,775 existing audit40 security assertions still pass against these objects. | Legacy unsigned assertions remain available only on stores never activated for this profile. Under-lock validation covers the local config effect, not arbitrary direct host writes. |
| W46 | Fresh boot-time checks after lock wait, before spend, after spend fsyncs and immediately before config rename; checked monotonic conversion. Preserve irreversible spend if I/O crosses expiration. | 128 ordinary checks cover expired action/grant, real wait past expiry, no-write timeout. 92 fault-harness checks delay real fsyncs until real clock expiry: no config publication, UNKNOWN/effect=0, replay suppressed. | A sample before rename is not a hard real-time completion guarantee. Expiration after durable spend does not refund the grant or claim NOT_ATTEMPTED. |
| W47 | Pin the actual owner.lock device/inode at context open and verify the held lock/name before use and publication. Missing locks are not recreated by activation or a legacy attempt on enabled stores; interrupted lock waits keep their deadline. | 93 parent checks plus two process workers: replaced/missing lock refuses without records/config writes; two signed requests prepared for the same prior state yield exactly one committed effect and one unspent refusal. | Concurrent service operations must obey this lock; the trusted administrator must quiesce the service before replacing lock/control state. Open uses one nonblocking shared-lock attempt. |
| W48 | Add read-only status through the retained directory and shared lock. Existing record recovery remains available after epoch retirement and grant expiration; no action/epoch is recreated to query history. | 77 checks cover moved/replaced pathname, missing/rotated epoch, bounded busy-lock refusal, unchanged output on error, malformed record and a reopened process. Expanded expiry harness: 100 checks plus child assertions recover UNKNOWN through retained/reopened contexts. | A terminal record describes its historical operation, not the current config. Fresh process open still requires the declared host provider and process credentials; absent/corrupt control state refuses. |
| W49 | Confirm unlink plus directory fsync before reporting an unconfirmed spend absent; cleanup failure yields UNKNOWN. Confirm control-file fsync on idempotent activation after an earlier failed sync. Clarify terminal visibility after failed final fsync. | Both pre-fix reproducers failed their required assertions. Fixed fault suite: 504 checks plus child assertions; all ordinary W41–W48: 939 checks. Covers failed spend/file/dir sync plus failed unlink, partial spend corruption, failed cleanup sync, incomplete activation, actual short reads/EINTR, read errors, invalid/unavailable clock provider, OOM and dupfd exhaustion with fd counts. | Fault injection proves program response to these syscall outcomes, not power-loss durability on every filesystem. UNKNOWN may reconcile to a currently visible terminal or absence; that read does not prove which state survives a future crash. |

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
W45: audit80 security: 421 checks PASS (ruid=1000 euid=1001)
W45 legacy regression: audit40 security: 14775 checks passed
W46: audit80 security: 128 checks PASS (ruid=1000 euid=1001)
W46 I/O expiry: audit80 security faults: 92 checks PASS (real-clock expiry)
W47: audit80 security: 93 checks PASS (ruid=1000 euid=1001)
W48: audit80 security: 77 checks PASS (ruid=1000 euid=1001)
W48 I/O recovery: audit80 security faults: 100 checks PASS (real-clock expiry)
W49 ordinary regression: audit80 security: 939 checks PASS (ruid=1000 euid=1001)
W49 fault regression: audit80 security faults: 504 checks PASS (real host, injected failures)
```

`security_faults.sh` links an instrumented attempt object only for tests. Its
fsync wrapper delays a successful real fsync; it never fabricates UID, clock
values or trust. The real kernel clock advances beyond the signed window.
Configuration is not published, the durable attempt stays UNKNOWN on recovery,
and another commit cannot repeat its effect.

W49 extends redirection to the authority owner as well. Both test-only owner
objects disable fortified libc inline aliases so read redirection cannot be
silently bypassed; every selected failure must record a hook hit. The normal
product objects retain their configured hardening. Successful reads and
identities remain kernel-derived. Invalid provider values are injected only
to assert refusal, never used to authenticate a successful request.

Two executable W49 counterexamples preceded their fixes:

```
cleanup (pre-fix): out.state == UNKNOWN && !out.effect_performed failed (errno=13)
activation retry (pre-fix): second enable == REFUSED && fsync_hits == 2 failed
cleanup (fixed): 181 checks PASS
all fault modes (fixed): 504 checks PASS
```

The first left an actual complete or partial record when cleanup failed. A
complete retained ATTEMPTED record queries as UNKNOWN; a partial retained
record queries as CORRUPT. If unlink succeeded but its directory fsync failed,
the call reports uncertainty although a later read currently observes absence.
The second allowed a retry to report successful activation after only syncing
the directory; the retry now also confirms the already-written control file.

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
