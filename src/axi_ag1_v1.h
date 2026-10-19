#ifndef AXI_AG1_V1_H
#define AXI_AG1_V1_H

#ifdef AXI_AG1_FREESTANDING
#include "axi_ag1_target_types.h"
#else
#include <stddef.h>
#include <stdint.h>
#endif

#define AXI_AG1_V1_MAGIC "AG1B"
#define AXI_AG1_V1_VERSION 1u
#define AXI_AG1_V1_BODY_DOMAIN "AXI-AG1-BODY-v1"
#define AXI_AG1_V1_SIG_DOMAIN "AXI-AG1-SIGN-v1"
#define AXI_AG1_V1_BODY_SIZE (4u + 4u + 9u * 32u + 8u + 8u + 1u + 32u)
#define AXI_AG1_V1_SIGNED_SIZE (AXI_AG1_V1_BODY_SIZE + 104u)
#define AXI_AG1_V1_SIG_MSG_SIZE (sizeof(AXI_AG1_V1_SIG_DOMAIN) + 32u)

typedef struct {
    uint8_t decision_aer_root[32];
    uint8_t principal_root[32];
    uint8_t policy_root[32];
    uint8_t action_root[32];
    uint8_t resource_root[32];
    uint8_t budget_root[32];
    uint8_t trust_snapshot_root[32];
    uint8_t issuer_key_id[32];
    uint8_t nonce[32];
    uint64_t not_before;
    uint64_t not_after;
    uint8_t has_parent;
    uint8_t parent_root[32];
} axi_ag1_v1;

typedef struct {
    uint8_t decision_aer_root[32];
    uint8_t principal_root[32];
    uint8_t policy_root[32];
    uint8_t action_root[32];
    uint8_t resource_root[32];
    uint8_t budget_root[32];
    uint8_t trust_snapshot_root[32];
} axi_ag1_v1_expectation;

int axi_ag1_v1_encode(const axi_ag1_v1 *grant,
                      uint8_t out[AXI_AG1_V1_BODY_SIZE]);
/* Exact structural decoder; destination unchanged on refusal. */
int axi_ag1_v1_decode(axi_ag1_v1 *grant, const uint8_t *bytes, size_t len);
void axi_ag1_v1_root(const axi_ag1_v1 *grant, uint8_t out[32]);
int axi_ag1_v1_encode_signed(const axi_ag1_v1 *grant, const uint8_t seed[32],
                             uint8_t out[AXI_AG1_V1_SIGNED_SIZE]);
int axi_ag1_v1_decode_signed(axi_ag1_v1 *grant, const uint8_t *bytes,
                             size_t len, const uint8_t trusted_pk[32]);
int axi_ag1_v1_matches(const axi_ag1_v1 *grant,
                       const axi_ag1_v1_expectation *expected,
                       uint64_t supplied_time);

/* AX30 source API: verifies signed AG1 and every existing context root plus
 * time. Destination unchanged on refusal. trusted_pk, expected and time are
 * supplied by the trusted owner, never accepted as authority from a requester.
 * No spend, reauthorization, clock read, filesystem or effect is performed. */
int axi_ag1_v1_verify_expected(axi_ag1_v1 *out, const uint8_t *bytes, size_t len,
                              const uint8_t trusted_pk[32],
                              const axi_ag1_v1_expectation *expected,
                              uint64_t supplied_time);

/* 0 = consumed now, 1 = already spent, -1 = invalid input or I/O refusal. */
int axi_ag1_v1_consume_spent(const char *directory,
                             const uint8_t grant_root[32]);

#endif /* AXI_AG1_V1_H */
