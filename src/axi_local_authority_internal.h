/* Private implementation sharing; no requester-facing validation hooks. */
#ifndef AXI_LOCAL_AUTHORITY_INTERNAL_H
#define AXI_LOCAL_AUTHORITY_INTERNAL_H

#include "axi_local_authority_v1.h"
#include <sys/types.h>

#define AXI_LOCAL_AUTHORITY_CONTROL "authority_v1"
#define AXI_LOCAL_AUTHORITY_CONTROL_SIZE 64u

struct axi_local_authority_v1 {
    int dirfd;
    uint8_t issuer_pk[32];
    uint64_t device, inode;
    uint32_t uid, executor_uid;
    pid_t pid;
    uint8_t boot[16];
};

int axi_local_authority_lock(const axi_local_authority_v1 *owner,
                              int operation, uint64_t deadline, int *lockfd);
int axi_local_authority_validate_locked(const axi_local_authority_v1 *owner);
int axi_local_authority_previous_locked(const axi_local_authority_v1 *owner,
                                          axi_local_previous_v1 *previous,
                                          uint8_t *present);
int axi_local_authority_host_sample(axi_local_authority_v1_facts *facts);
int axi_local_authority_observe_locked(const axi_local_authority_v1 *owner,
                                         axi_local_authority_v1_facts *facts);

#endif
