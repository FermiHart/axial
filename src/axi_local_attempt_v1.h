/* ADR-059 AXV2-07 / D04: durable AG1 attempt owner for the narrow local profile.
 *
 * Private C interface, fixture-only; no installed ABI promise, no production
 * runner, no Beyond wiring. The owner binds one signed AG1 grant (seven roots
 * + issuer + time) to one AXV2-ACTION-v1 descriptor (05), one admission verdict
 * (06: admitted PROD with coverage bit), boot/deployment pins and exact payload
 * bytes, then drives a versioned attempt record keyed by the grant root:
 * AUTHORIZED -> ATTEMPTED (durable, irrevocable) -> TERMINAL (COMMITTED or
 * UNKNOWN/FAILED as observed). The existing root-only
 * axi_ag1_v1_consume_spent() stays a legacy core primitive and MUST NOT be
 * used as a second spent ledger alongside this record.
 *
 * Effect (fixture only): temp-file write -> file fsync -> rename to `config`
 * -> directory fsync, inside the owner-provided fixture root. No O_TRUNC
 * generic fs.Write, no requester-selected callback/program/path, no retry.
 * Status/retry queries never invoke the effect. Missing/corrupt state stops
 * service. A crash after ATTEMPTED without confirmed terminal stays UNKNOWN.
 * At most 1024 attempt records per store; refuse when full. Concurrent
 * consumers of one grant produce at most one effect entry (O_EXCL serialize).
 */
#ifndef AXI_LOCAL_ATTEMPT_V1_H
#define AXI_LOCAL_ATTEMPT_V1_H

#include "axi_local_action_v1.h"
#include "axi_local_admission_v1.h"

#define AXI_LOCAL_ATTEMPT_V1_OK 0
#define AXI_LOCAL_ATTEMPT_V1_REFUSED (-1)
#define AXI_LOCAL_ATTEMPT_V1_STORE_FULL (-2)
#define AXI_LOCAL_ATTEMPT_V1_CORRUPT (-3)
#define AXI_LOCAL_ATTEMPT_V1_TIMEOUT (-4)

#define AXI_LOCAL_ATTEMPT_V1_MAX_RECORDS 1024u
#define AXI_LOCAL_ATTEMPT_V1_TARGET_NAME "config"

enum {
    AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED = 0,
    AXI_LOCAL_ATTEMPT_V1_ATTEMPTED = 1,
    AXI_LOCAL_ATTEMPT_V1_COMMITTED = 2,
    AXI_LOCAL_ATTEMPT_V1_UNKNOWN = 3,
    AXI_LOCAL_ATTEMPT_V1_FAILED = 4
};

/* Outcome of one owner call. `state` is the durable record state after the
 * call; `effect_performed` is 1 only when this call performed the fixture
 * effect, 0 otherwise (including replays, refusals and status paths). */
typedef struct {
    uint8_t state;
    uint8_t effect_performed;
    uint8_t grant_root[32];
} axi_local_attempt_v1_outcome;

/* One owner transaction over a private fixture store.
 *
 * - `store_dir`: owner-provided private directory (already created, mode 0700).
 * - `grant_signed`/`grant_len`: signed AG1 envelope (AXI_AG1_V1_SIGNED_SIZE).
 * - `trusted_pk`: 32-byte grant-issuer key pinned by the owner (never from
 *   the requester); `issuer_key_id` derived per ADR-059 section 7
 *   must match it.
 * - `action_bytes`/`action_len`: canonical AXV2-ACTION-v1 bytes (05).
 * - `pins`/`observed`: same owner pins and locally measured observations as
 *   the 06 appraisal, which must have admitted PROD with coverage bit.
 * - `payload`/`payload_len`: exact content bytes bound by payload sha/size.
 * - `supplied_time`: explicit u64 ns appraisal instant; no ambient clock read.
 *
 * Returns OK with `out` written, or REFUSED/STORE_FULL/CORRUPT with `out`
 * still written when state is known (replay/status paths), or without
 * side effects on invalid input. Never invokes the effect on refusal,
 * replay, status or corrupt state. I/O doctrine: failures before any
 * durable spend report REFUSED/NOT_ATTEMPTED (no decision made,
 * re-query for truth); past the spend, uncertainty is explicit
 * (CORRUPT, UNKNOWN or FAILED), never an unprovable NOT_ATTEMPTED. */
int axi_local_attempt_v1_commit(const char *store_dir,
                                const uint8_t *grant_signed, size_t grant_len,
                                const uint8_t trusted_pk[32],
                                const void *action_bytes, size_t action_len,
                                const axi_local_admission_v1_pins *pins,
                                const axi_local_admission_v1_observed *observed,
                                const uint8_t *payload, size_t payload_len,
                                uint64_t supplied_time,
                                axi_local_attempt_v1_outcome *out);

/* Status-only query: reports durable state, never performs the effect. */
int axi_local_attempt_v1_status(const char *store_dir,
                                const uint8_t grant_root[32],
                                axi_local_attempt_v1_outcome *out);

/* AXV2-11 restart reconciliation: a durable-record view. state carries
 * the observed state with stranded ATTEMPTED already mapped to UNKNOWN;
 * action_root, payload_sha/size and context_root come straight from the
 * record. Views never authorize, spend or effect anything. */
typedef struct {
    uint8_t grant_root[32];
    uint8_t state;
    uint8_t action_root[32];
    uint8_t payload_sha[32];
    uint64_t payload_size;
    uint8_t context_root[32];
    uint8_t has_epoch_link;
    uint64_t epoch_generation;
    uint8_t epoch_deployment[16];
} axi_local_attempt_v1_record_view;

/* Walk every durable record once, read-only, under a shared lock, calling
 * visit() per record. ATTEMPTED records are reported as UNKNOWN; terminal
 * records pass through. Rules: no write, no effect, no spend, no lock
 * upgrade, no re-authorization -- a restart learns file state only.
 * A corrupt record aborts the walk with CORRUPT (never skipped into
 * apparent success); a nonzero visit() return aborts with REFUSED.
 * Visit order is directory order (unspecified); non-record files
 * (crash tmp debris) are ignored with their why documented in the
 * pilot. Empty/missing records dir on an owned store: OK, zero visits.
 * Returns OK when every record was visited, else CORRUPT/REFUSED. */
int axi_local_attempt_v1_scan(const char *store_dir,
                              int (*visit)(const axi_local_attempt_v1_record_view *view,
                                           void *ctx),
                              void *ctx);

/* Bounded variant: shared-lock acquisition dies at deadline_mono_ns
 * (monotonic; zero tries once). On expiry, no visit runs and TIMEOUT
 * is returned with nothing reported. */
int axi_local_attempt_v1_scan_timed(const char *store_dir,
                                     int (*visit)(const axi_local_attempt_v1_record_view *view,
                                                  void *ctx),
                                     void *ctx, uint64_t deadline_mono_ns);

/* AXV2-08 isolation: the store root must be an owner-held directory before
 * the owner touches any record. Returns OK when store_dir is a directory
 * owned by the caller's effective UID with mode exactly 0700; otherwise
 * REFUSED. No record is read or written, no effect is performed. Same-UID
 * attackers stay outside this guarantee (ADR-059 TCB): ownership proves
 * which UID owns the path, not that no other process shares the UID.
 * The final store component and internal entries must not be symlinks.
 * Actual opened descriptors are rechecked; records/locks/epoch files are
 * private regular files with one link, so FIFOs cannot block these reads. */
int axi_local_attempt_v1_store_check(const char *store_dir);

/* Monotonic now for deadlines (CLOCK_MONOTONIC nanoseconds). */
uint64_t axi_local_attempt_v1_now_mono(void);

/* Commit with a bounded lock acquisition. Identical to
 * axi_local_attempt_v1_commit except: the owner lock is acquired no later
 * than deadline_mono_ns (monotonic). A zero deadline tries once without
 * waiting; UINT64_MAX waits indefinitely. On expiry the call performs no
 * write and no effect: it reports the current lock-free status (NOT_ATTEMPTED
 * when no record exists, the terminal state when one does, UNKNOWN for a
 * stranded ATTEMPTED record) with effect_performed=0 and returns TIMEOUT.
 * Slow clients are refused, never queued behind unbounded waits; cancellation
 * is this timeout, and it never fabricates terminal evidence. */
int axi_local_attempt_v1_commit_deadline(
    const char *store_dir, const uint8_t *grant_signed, size_t grant_len,
    const uint8_t trusted_pk[32], const void *action_bytes, size_t action_len,
    const axi_local_admission_v1_pins *pins,
    const axi_local_admission_v1_observed *observed,
    const uint8_t *payload, size_t payload_len, uint64_t supplied_time,
    uint64_t deadline_mono_ns, axi_local_attempt_v1_outcome *out);

#endif
