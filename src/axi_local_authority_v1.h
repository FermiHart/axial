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
 * remain alive for a call and must not be closed concurrently with a call. */
int axi_local_authority_v1_open(const char *store_dir,
                                 axi_local_authority_v1 **out);
void axi_local_authority_v1_close(axi_local_authority_v1 *owner);

/* Read the identity of the actual held directory, never a pathname alias.
 * Both outputs remain unchanged on refusal. */
int axi_local_authority_v1_resource(const axi_local_authority_v1 *owner,
                                     uint64_t *device, uint64_t *inode);

#endif
