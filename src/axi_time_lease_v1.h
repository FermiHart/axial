#ifndef AXI_TIME_LEASE_V1_H
#define AXI_TIME_LEASE_V1_H

#include <stddef.h>
#include <stdint.h>

#define AXI_TIME1_MAGIC "TIM1"
#define AXI_TIME1_VERSION 1u
#define AXI_TIME1_BODY_DOMAIN "AXI-TIME1-BODY-v1"
#define AXI_TIME1_BODY_SIZE (4u + 4u + 32u * 7u + 1u + 8u * 6u)

#define AXI_LEASE1_MAGIC "LSE1"
#define AXI_LEASE1_VERSION 1u
#define AXI_LEASE1_BODY_DOMAIN "AXI-LEASE1-BODY-v1"
#define AXI_LEASE1_MAX_CAPS 4u
#define AXI_LEASE1_CAPNAME 64u
#define AXI_LEASE1_MAX_QUOTAS 4u
#define AXI_LEASE1_BODY_SIZE \
    (4u + 4u + 32u * 5u + 1u + 32u + 1u + 32u + 8u + 8u + 32u * 2u \
     + 1u + AXI_LEASE1_MAX_CAPS * AXI_LEASE1_CAPNAME + 1u \
     + AXI_LEASE1_MAX_QUOTAS * (32u + 8u))

enum {
    AXI_LEASE1_SCOPE_EXACT_OBJECT = 1,
    AXI_LEASE1_SCOPE_ROOTED_SUBTREE = 2,
    AXI_LEASE1_SCOPE_NAMESPACE_SLOT = 3,
    AXI_LEASE1_SCOPE_RENAME_PAIR = 4
};

typedef struct {
    uint8_t domain_id[32];
    uint8_t source_id[32];
    uint8_t trust_snapshot_root[32];
    uint8_t boot_present;
    uint8_t boot_id[32];
    uint64_t sequence;
    uint64_t monotonic_sample;
    uint64_t epoch_lower;
    uint64_t epoch_upper;
    uint64_t uncertainty_before;
    uint64_t uncertainty_after;
    uint8_t predecessor_root[32];
    uint8_t high_water_root[32];
    uint8_t attestation_root[32];
} axi_time1;

typedef struct {
    uint8_t principal_root[32];
    uint8_t issuer_root[32];
    uint8_t trust_snapshot_root[32];
    uint8_t lease_nonce[32];
    uint8_t time_domain_id[32];
    uint8_t boot_bound;
    uint8_t boot_id[32];
    uint8_t scope_kind;
    uint8_t scope_root[32];
    uint64_t not_before;
    uint64_t not_after;
    uint8_t revocation_root[32];
    uint8_t parent_root[32];
    uint8_t ncap;
    char caps[AXI_LEASE1_MAX_CAPS][AXI_LEASE1_CAPNAME];
    uint8_t nquota;
    uint8_t quota_unit[AXI_LEASE1_MAX_QUOTAS][32];
    uint64_t quota_limit[AXI_LEASE1_MAX_QUOTAS];
} axi_lease1;

typedef struct {
    uint8_t lease_root[32];
    uint8_t quota_unit[AXI_LEASE1_MAX_QUOTAS][32];
    uint64_t quota_limit[AXI_LEASE1_MAX_QUOTAS];
    uint64_t quota_reserved[AXI_LEASE1_MAX_QUOTAS];
    uint8_t nquota;
} axi_lease1_state;

int axi_time1_encode(const axi_time1 *time, uint8_t out[AXI_TIME1_BODY_SIZE]);
int axi_time1_decode(axi_time1 *time, const uint8_t *bytes, size_t len);
void axi_time1_root(const axi_time1 *time, uint8_t out[32]);
int axi_time1_verify_successor(const axi_time1 *prev, const axi_time1 *next);

int axi_lease1_encode(const axi_lease1 *lease, uint8_t out[AXI_LEASE1_BODY_SIZE]);
int axi_lease1_decode(axi_lease1 *lease, const uint8_t *bytes, size_t len);
void axi_lease1_root(const axi_lease1 *lease, uint8_t out[32]);
int axi_lease1_authorizes(const axi_lease1 *lease, const axi_time1 *time,
                          const uint8_t principal_root[32],
                          const char *capability,
                          const uint8_t exact_scope_root[32]);
int axi_lease1_state_init(axi_lease1_state *state, const axi_lease1 *lease);
int axi_lease1_reserve(axi_lease1_state *state, const uint8_t unit[32],
                       uint64_t amount);

#endif /* AXI_TIME_LEASE_V1_H */
