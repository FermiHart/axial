/* Explicit opt-in host-local authority profile. Private C API, not embed ABI.
 *
 * This profile defines resource_device/resource_inode as the owned store
 * directory held open by the context. The only effect is replacement of its
 * relative `config` entry. previous.* describes that entry, not its parent.
 * It does not reconstruct the unavailable ADR-059 or authenticate a guest.
 *
 * enable() is an administrator operation: provision the grant issuer key,
 * under owner.lock, in a private control record bound to this directory.
 * Activation has no downgrade operation. Legacy commit APIs then refuse on
 * this store, including malformed/incomplete control state; status stays
 * readable. The administrator/service account and kernel are in the TCB.
 * A process able to modify private store files as the service UID is trusted.
 * No requester-supplied callback, pathname, clock, identity or trust verdict
 * supplies an authority observation through this API.
 */
#ifndef AXI_LOCAL_AUTHORITY_V1_H
#define AXI_LOCAL_AUTHORITY_V1_H

#include "axi_local_attempt_v1.h"

typedef struct axi_local_authority_v1 axi_local_authority_v1;
typedef struct axi_local_authority_v1_prepared axi_local_authority_v1_prepared;

typedef struct {
    uint64_t resource_device, resource_inode;
    axi_local_previous_v1 previous;
    uint8_t has_previous;
    uint32_t uid, executor_uid;
    uint8_t boot[16];
    uint64_t now_ns;
    axi_local_admission_v1_pins pins;
    uint64_t epoch_generation;
} axi_local_authority_v1_facts;

#define AXI_LOCAL_AUTHORITY_V1_OK AXI_LOCAL_ATTEMPT_V1_OK
#define AXI_LOCAL_AUTHORITY_V1_REFUSED AXI_LOCAL_ATTEMPT_V1_REFUSED
#define AXI_LOCAL_AUTHORITY_V1_CORRUPT AXI_LOCAL_ATTEMPT_V1_CORRUPT
#define AXI_LOCAL_AUTHORITY_V1_TIMEOUT AXI_LOCAL_ATTEMPT_V1_TIMEOUT
#define AXI_LOCAL_AUTHORITY_V1_UNSUPPORTED (-5)

/* Store must already be private (0700, owned by effective UID). Existing
 * matching activation is idempotent; another key or directory refuses.
 * Failure can leave activation present, deliberately preventing downgrade. */
int axi_local_authority_v1_enable(const char *store_dir,
                                   const uint8_t issuer_pk[32]);

/* Owns an O_CLOEXEC dirfd and immutable issuer pin. No pathname is retained.
 * Successful open publishes *out; refusal leaves it NULL. The context must
 * remain alive for a call and must not be closed concurrently with a call.
 * This host profile requires Linux CLOCK_BOOTTIME and the kernel boot UUID
 * from /proc/sys/kernel/random/boot_id. No alternate clock/domain fallback.
 * uid=getuid(), executor_uid=geteuid(), both nonzero and distinct as required
 * by the unchanged action codec. They identify the current process, not a
 * remote requester. Credential changes/fork require reopening the context.
 * Host /proc mount and namespace configuration are part of the host TCB. */
int axi_local_authority_v1_open(const char *store_dir,
                                 axi_local_authority_v1 **out);
void axi_local_authority_v1_close(axi_local_authority_v1 *owner);

/* Read the identity of the actual held directory, never a pathname alias.
 * Both outputs remain unchanged on refusal. */
int axi_local_authority_v1_resource(const axi_local_authority_v1 *owner,
                                     uint64_t *device, uint64_t *inode);

/* Read config under the same owner lock used by commits. The exact bounded
 * bytes and fstat metadata must stay stable through the read, and the name
 * must still designate that descriptor. Missing config publishes present=0
 * and a zero previous object. Unsafe/special/oversized files refuse.
 * Deadline is CLOCK_MONOTONIC ns (0: try once, UINT64_MAX: wait). All outputs
 * stay unchanged on refusal. This snapshot alone authorizes no mutation. */
int axi_local_authority_v1_previous(const axi_local_authority_v1 *owner,
                                     axi_local_previous_v1 *previous,
                                     uint8_t *present, uint64_t deadline_mono_ns);

/* Observe kernel process identity, boot UUID, CLOCK_BOOTTIME and resource /
 * prior bytes under owner.lock. Complete output only on success. This is a
 * fact snapshot for building an action; commit will observe again. */
int axi_local_authority_v1_observe(const axi_local_authority_v1 *owner,
                                    axi_local_authority_v1_facts *out,
                                    uint64_t deadline_mono_ns);

/* Require an active owner-provisioned epoch (no legacy grandfathering),
 * compare an action with actual host facts, and snapshot its exact bytes and
 * payload. Outputs give the existing admission context for AG1 issuance;
 * this function never issues a grant, executes policy or performs an effect.
 * The opaque prepared request owns an independent dirfd and copied data, so
 * caller buffers and owner can be released afterwards. It is process-bound
 * and reusable only for status/replay semantics after a successful commit.
 * The issuer must sign AG1 roots for these exact bytes/context. Coverage=1
 * means only this activated local attempt door, not general host/guest paths.
 * Outputs must be disjoint from inputs and each other. On refusal *out=NULL;
 * admission is a refusal (zero context unless common appraisal produced it). */
int axi_local_authority_v1_prepare(const axi_local_authority_v1 *owner,
                                    const void *action_bytes, size_t action_len,
                                    const uint8_t *payload, size_t payload_len,
                                    uint64_t deadline_mono_ns,
                                    axi_local_authority_v1_prepared **out,
                                    axi_local_admission_v1_result *admission);
void axi_local_authority_v1_prepared_close(axi_local_authority_v1_prepared *prepared);

/* Verify an ordinary signed AG1 against the immutable prepared request and
 * provisioned issuer, then observe resource/prior content/epoch again under
 * the exclusive commit lock, before any spend/config write. No target path
 * argument exists: the effect is relative to the prepared held dirfd.
 * Reuses the existing attempt ledger and outcome codes. No receipt is minted
 * by this API; status/refusal/unknown are never relabeled as a policy deny.
 * The request remains valid storage until prepared_close(), including replay.
 */
int axi_local_authority_v1_commit(const axi_local_authority_v1_prepared *prepared,
                                   const uint8_t *grant_signed, size_t grant_len,
                                   uint64_t deadline_mono_ns,
                                   axi_local_attempt_v1_outcome *out);

#endif
