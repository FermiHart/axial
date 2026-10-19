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
};

#endif
