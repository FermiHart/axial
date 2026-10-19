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

Covered proof obligations: bounded prior-content snapshot; real UID/effective
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
| W50 | Add end-to-end refusal matrix for all signed context roots/issuer, wrong signature/length and delegated grants; private-store mode and malformed active-epoch changes cannot bypass preparation. Add a compiled-out host-provider probe. Make every runner inherit preprocessor/compiler/linker flags and invalidate cached objects accordingly. | W50 alone: 200 checks. Full ASan/UBSan: 1,137 ordinary + 504 fault checks, all 64 linked candidate/variant/harness objects verified instrumented. Disabled-provider probe: 8 checks normal and sanitized. Existing W27 fault suite against candidate objects: 109 checks pass. | Sanitizers cover these executed paths; LeakSanitizer was disabled. Positive profile tests require real distinct UIDs and a supported host. A disabled provider is tested refusal, never evidence of guest enforcement. |

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
W50 isolated: audit80 security: 200 checks PASS (ruid=1000 euid=1001)
W50 complete normal: audit80 security: 1137 checks PASS (ruid=1000 euid=1001)
W50 complete normal faults: audit80 security faults: 504 checks PASS (real host, injected failures)
W50 ASan/UBSan ordinary: audit80 security: 1137 checks PASS (ruid=1000 euid=1001)
W50 ASan/UBSan faults: audit80 security faults: 504 checks PASS (real host, injected failures)
W50 disabled provider, normal and ASan/UBSan: audit80 security no-host: 8 checks PASS
W50 legacy fault regression: audit40 W27 fault injection: 109 checks passed
Sanitizer object verification: 64 objects; missing ASan instrumentation: 0
```

`security_faults.sh` links instrumented local-owner objects only for tests. Its
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
retained for the AG1 decision-context root; fresh commit-time checks are
separate so the signed context is never rewritten to pretend it was new.

`AXI_LOCAL_AUTHORITY_NO_HOST` can disable this optional host profile at build
time; it does not disable the portable core. Open/observation then refuse with
UNSUPPORTED. No clock callback or supplied boot/UID assertion can re-enable it.

When only the authorized execution surface permits credential changes, build
with `AXI_AUDIT_BUILD_ONLY=1 sh tests/audit80/security.sh`, then execute that
same `build/audit80-security/security` binary there. Exit 77 explicitly means
the host cannot supply the required distinct identities; it is not a pass.

## Profile contract and integration

This is an explicit **opt-in host-local consumer**, scoped to replacing one
relative `config` entry in a held private store. Existing callers and stores
remain on their prior interface until the trusted administrator calls enable.
After activation, legacy mutation calls refuse; no missing/invalid epoch,
clock or control field falls back to requester-supplied assertions.

| Input or object | Producer and interpretation | Revalidated at consumption |
| --- | --- | --- |
| `resource_device/resource_inode` | `fstat` of the context's open private store directory; no target pathname from the requester. | Held directory ownership/mode and exact identity, under the commit lock. |
| `previous.*` | The current relative `config` descriptor: device, inode, exact byte length, checked nanosecond mtime and SHA-256. Absence is a distinct state. | Bounded exact read and stable descriptor/name metadata, then field-by-field equality with the signed action before any spend/config write. |
| `uid/executor_uid` | Actual `getuid()/geteuid()` of the process. The unchanged action codec requires two distinct nonzero UIDs. | Process identity and both credentials must match the opened/prepared context; a fork or credential change requires reopening and a new preparation. |
| `boot/now_ns` | Kernel boot UUID from the host proc mount and Linux `CLOCK_BOOTTIME`. Lock deadlines use `CLOCK_MONOTONIC`. | Exact boot identity, nondecreasing time and action/grant windows at the declared pre-spend/publication boundaries. No fallback provider. |
| Trust, deployment and policy pins | Existing owner-provisioned `epoch_active` record in the same held store. | Mandatory valid active record, identical pins and generation to preparation. A new generation invalidates unspent prepared work even with identical pins. |
| Grant issuer | Administrator-provisioned public key in directory-bound `authority_v1`. | Signature, derived issuer ID and all existing AG1 expectation roots. This profile refuses delegated grants. |
| Lock | Actual private single-link `owner.lock`, pinned by device/inode at open. | Open descriptor and named lock must retain that identity. Missing/replaced lock refuses; it is not silently recreated by a legacy commit. |

The service integration sequence is:

1. Provision and activate the existing local epoch through trusted owner
   administration. Enable this profile with the intended issuer public key,
   checking success before starting service. Failed activation may leave a
   deliberate denial marker; there is no automatic downgrade or repair of a
   partial control record. Administrative replacement requires a quiesced
   service and is outside request processing.
2. Run the local consumer under the intended **real UID and different
   effective service UID**, both nonzero. Open the store context. This is
   host process credential provenance; it does not authenticate an HTTP,
   socket, remote-user or guest principal. A deployment needing those
   identities must supply its own authenticated integration before choosing
   process credentials.
3. Observe current facts and construct the existing canonical action with
   those resource/prior/identity/boot fields and active pins. Prepare snapshots
   its exact action and payload bytes into owned memory and produces the
   existing admission context. Inputs may be released after preparation.
4. The trusted issuer applies the intended policy and issues an existing AG1
   for those exact roots/context. Preparation itself neither runs that policy
   nor mints an authorization. Possessing a valid signature does not establish
   the safety or truth of the approved payload/policy.
5. Commit the signed AG1 through the prepared request. The owner reobserves
   the real inputs under its exclusive lock before entering the existing
   durable attempt protocol. Inspect both return code and outcome; no policy
   deny, runtime error, UNKNOWN or success are interchangeable.
6. Reconcile with status using the retained context; after process restart,
   open a fresh context and query known grant roots. Status never repeats an
   effect or restores authority. Close prepared requests and owner contexts
   after their last caller has finished; closing concurrently with a call is
   outside the API lifetime contract.

The private API declarations live in `src/axi_local_authority_v1.h`:

```c
int axi_local_authority_v1_enable(const char *store_dir, const uint8_t issuer_pk[32]);
int axi_local_authority_v1_open(const char *store_dir, axi_local_authority_v1 **out);
void axi_local_authority_v1_close(axi_local_authority_v1 *owner);
int axi_local_authority_v1_resource(const axi_local_authority_v1 *owner,
                                    uint64_t *device, uint64_t *inode);
int axi_local_authority_v1_previous(const axi_local_authority_v1 *owner,
                                    axi_local_previous_v1 *previous,
                                    uint8_t *present, uint64_t deadline_mono_ns);
int axi_local_authority_v1_observe(const axi_local_authority_v1 *owner,
                                   axi_local_authority_v1_facts *out,
                                   uint64_t deadline_mono_ns);
int axi_local_authority_v1_prepare(const axi_local_authority_v1 *owner,
                                   const void *action_bytes, size_t action_len,
                                   const uint8_t *payload, size_t payload_len,
                                   uint64_t deadline_mono_ns,
                                   axi_local_authority_v1_prepared **out,
                                   axi_local_admission_v1_result *admission);
void axi_local_authority_v1_prepared_close(axi_local_authority_v1_prepared *prepared);
int axi_local_authority_v1_commit(const axi_local_authority_v1_prepared *prepared,
                                  const uint8_t *grant_signed, size_t grant_len,
                                  uint64_t deadline_mono_ns,
                                  axi_local_attempt_v1_outcome *out);
int axi_local_authority_v1_status(const axi_local_authority_v1 *owner,
                                  const uint8_t grant_root[32],
                                  uint64_t deadline_mono_ns,
                                  axi_local_attempt_v1_outcome *out);
```

There is no change to the frozen `include/axial` headers, signed AG1/action
layouts or existing v1/v2 attempt records. The 64-byte control file is private
configuration with no new authorization or spent-ledger semantics. A context
pins one immutable issuer; this API does not rotate keys or authenticate a
replacement administrator. Source checker identity regeneration belongs to
the integrated checkpoint, not these isolated component commits.

## Reproducing the final gates

The ordinary standalone main is `tests/audit80/security.c`; W49 fault modes
are in `security_faults.inc`, linked against the same core plus two redirected
owner objects. `security_nohost.inc` links the real authority implementation
with its host provider compiled out. All runners accept `AXI_AUDIT_BUILD_ONLY`,
`AXI_AUDIT_BUILD`, `AXI_AUDIT_SOURCE_ROOT`, `AXI_AUDIT_CFLAGS`, `CC`, `CFLAGS`,
`CPPFLAGS` and `LDFLAGS`. `AXI_AUDIT_CFLAGS` overrides `CFLAGS`; otherwise the
strict C99 defaults apply. Cache identity includes flags and relevant headers,
so changing sanitizer/preprocessor flags rebuilds every core object.

```sh
AXI_AUDIT_BUILD_ONLY=1 sh tests/audit80/security.sh
AXI_AUDIT_BUILD_ONLY=1 sh tests/audit80/security_faults.sh
AXI_AUDIT_BUILD_ONLY=1 sh tests/audit80/security_nohost.sh

AXI_AUDIT_BUILD_ONLY=1 \
AXI_AUDIT_BUILD=build/audit80-security-sanitize \
AXI_AUDIT_CFLAGS='-std=c99 -Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie' \
CPPFLAGS='-D_POSIX_C_SOURCE=200809L' \
LDFLAGS='-fsanitize=address,undefined -no-pie' \
sh tests/audit80/security_faults.sh
```

Run normal/fault executables on a host that permits the declared real
credentials. For sanitizer execution the observed settings were
`ASAN_OPTIONS=detect_leaks=0:abort_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1`. No sanitizer diagnostic occurred. FD counts
before/after injected failures were equal. LeakSanitizer was not exercised.
The count printed by each main is parent assertions; successful child-process
assertions are additional and child exits are checked by the parent.

## Remaining external limits

These waves close the declared Axial local consumer path. They do not install
a host daemon, a privileged launcher, remote authentication or guest syscall
mediation. Host process/service administration, the selected kernel/proc
namespace, filesystem behavior and noncooperative writers with the same
service UID remain in the trusted base. Coverage=1 concerns this activated
local commit door only. Production trust snapshot creation, correct policy
selection/execution, guest coverage and binary attestation require their
actual external producers/consumers and integration evidence. No universal
host/guest enforcement, payload truth, hard real-time rename completion or
physical power-loss experiment is claimed by these tests.
