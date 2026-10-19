#ifndef AXI_DELEGATION_V1_H
#define AXI_DELEGATION_V1_H

#include <stddef.h>
#include <stdint.h>

#define AXI_DELEGATION_V1_MAGIC "DLG1"
#define AXI_DELEGATION_V1_VERSION 1u
#define AXI_DELEGATION_V1_BODY_DOMAIN "AXI-DELEGATION-BODY-v1"
#define AXI_DELEGATION_V1_SIG_DOMAIN "AXI-DELEGATION-SIGN-v1"
#define AXI_DELEGATION_V1_MAX_CAPS 4u
#define AXI_DELEGATION_V1_CAPNAME 64u
#define AXI_DELEGATION_V1_MAX_DEPTH 32u
#define AXI_DELEGATION_V1_BODY_SIZE \
    (4u + 4u + 1u + 32u * 6u + 4u + 4u + 8u + 8u + 8u * 6u + 1u \
     + AXI_DELEGATION_V1_MAX_CAPS * AXI_DELEGATION_V1_CAPNAME)
#define AXI_DELEGATION_V1_SIGNED_SIZE (AXI_DELEGATION_V1_BODY_SIZE + 104u)
#define AXI_DELEGATION_V1_SIG_MSG_SIZE (sizeof(AXI_DELEGATION_V1_SIG_DOMAIN) + 32u)

enum {
    AXI_DELEGATION_V1_PARENT_AG1 = 1,
    AXI_DELEGATION_V1_PARENT_DELEGATION = 2
};

typedef struct {
    uint8_t parent_kind;
    uint8_t parent_root[32];
    uint8_t delegator_root[32];
    uint8_t delegatee_root[32];
    uint8_t trust_snapshot_root[32];
    uint8_t issuer_key_id[32];
    uint8_t branch_nonce[32];
    uint32_t depth;
    uint32_t remaining_depth;
    uint64_t not_before;
    uint64_t not_after;
    uint64_t budget[6];
    uint8_t ncap;
    char caps[AXI_DELEGATION_V1_MAX_CAPS][AXI_DELEGATION_V1_CAPNAME];
} axi_delegation_v1;

typedef struct {
    uint8_t root[32];
    uint8_t principal_root[32];
    uint8_t trust_snapshot_root[32];
    uint32_t depth;
    uint32_t remaining_depth;
    uint64_t not_before;
    uint64_t not_after;
    uint64_t budget[6];
    uint8_t ncap;
    char caps[AXI_DELEGATION_V1_MAX_CAPS][AXI_DELEGATION_V1_CAPNAME];
} axi_delegation_v1_authority;

int axi_delegation_v1_encode(const axi_delegation_v1 *delegation,
                             uint8_t out[AXI_DELEGATION_V1_BODY_SIZE]);
int axi_delegation_v1_decode(axi_delegation_v1 *delegation,
                             const uint8_t *bytes, size_t len);
void axi_delegation_v1_root(const axi_delegation_v1 *delegation,
                            uint8_t out[32]);
int axi_delegation_v1_encode_signed(const axi_delegation_v1 *delegation,
                                    const uint8_t seed[32],
                                    uint8_t out[AXI_DELEGATION_V1_SIGNED_SIZE]);
int axi_delegation_v1_decode_signed(axi_delegation_v1 *delegation,
                                    const uint8_t *bytes, size_t len,
                                    const uint8_t trusted_pk[32]);
int axi_delegation_v1_verify(const axi_delegation_v1 *delegation,
                             const axi_delegation_v1_authority *parent,
                             axi_delegation_v1_authority *child_out);
int axi_delegation_v1_verify_chain(const axi_delegation_v1 *chain, size_t n,
                                   const axi_delegation_v1_authority *root,
                                   axi_delegation_v1_authority *leaf_out);

#endif /* AXI_DELEGATION_V1_H */
