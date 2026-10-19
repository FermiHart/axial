#ifndef AXI_AER1_H
#define AXI_AER1_H

#include <stddef.h>
#include <stdint.h>
#include "axi_resource_envelope.h"

#define AXI_AER1_ROOTS 10u
#define AXI_AER1_ENCODED_SIZE (4u + 4u + 13u + (AXI_AER1_ROOTS * 32u) + 8u + (5u * 8u))
#define AXI_AER1_SIGNED_SIZE (AXI_AER1_ENCODED_SIZE + 104u)
#define AXI_AER1_BODY_DOMAIN "AXI-AER1-BODY-v1"
#define AXI_AER1_SIG_DOMAIN "AXI-AER1-SIGN-v1"

#define AXI_AER1_DECISION_UNPROVEN 0u
#define AXI_AER1_DECISION_ALLOW    1u
#define AXI_AER1_DECISION_DENY     2u

#define AXI_AER1_ATTEMPT_NOT_ATTEMPTED 0u
#define AXI_AER1_ATTEMPT_ATTEMPTED     1u

#define AXI_AER1_OUTCOME_NONE        0u
#define AXI_AER1_OUTCOME_PARTIAL     1u
#define AXI_AER1_OUTCOME_COMMITTED   2u
#define AXI_AER1_OUTCOME_FAILED      3u
#define AXI_AER1_OUTCOME_COMPENSATED 4u

#define AXI_AER1_COVERAGE_UNKNOWN  0u
#define AXI_AER1_COVERAGE_PARTIAL  1u
#define AXI_AER1_COVERAGE_COMPLETE 2u

#define AXI_AER1_PROFILE_DEV  1u
#define AXI_AER1_PROFILE_PROD 2u

#define AXI_AER1_OPACITY_CLEAR        1u
#define AXI_AER1_OPACITY_CONFIDENTIAL 2u

#define AXI_AER1_MATURITY_DEV      1u
#define AXI_AER1_MATURITY_TESTED   2u
#define AXI_AER1_MATURITY_ATTESTED 3u

typedef struct {
    uint8_t decision;
    uint8_t attempt;
    uint8_t outcome;
    uint8_t evidence;
    uint8_t coverage;
    uint8_t profile;
    uint8_t opacity;
    uint8_t maturity;
    uint8_t has_policy_root;
    uint8_t has_grant_root;
    uint8_t has_coverage_root;
    uint8_t has_episode_root;
    uint8_t has_artifact_root;
    uint8_t principal_root[32];
    uint8_t artifact_root[32];
    uint8_t policy_root[32];
    uint8_t grant_root[32];
    uint8_t action_root[32];
    uint8_t coverage_root[32];
    uint8_t budget_root[32];
    uint8_t episode_root[32];
    uint8_t ledger_tip[32];
    uint8_t journal_tip[32];
    uint64_t fuel_used;
    axi_resource_vector resources;
} axi_aer1;

int axi_aer1_encode(const axi_aer1 *receipt,
                    uint8_t out[AXI_AER1_ENCODED_SIZE]);
int axi_aer1_decode(axi_aer1 *receipt, const uint8_t *bytes, size_t len);
void axi_aer1_root(const axi_aer1 *receipt, uint8_t root[32]);
int axi_aer1_encode_signed(const axi_aer1 *receipt, const uint8_t seed[32],
                           uint8_t out[AXI_AER1_SIGNED_SIZE]);
int axi_aer1_decode_signed(axi_aer1 *receipt, const uint8_t *bytes, size_t len,
                           const uint8_t trusted_pk[32]);

#endif
