#ifndef AXI_TRUST_V1_H
#define AXI_TRUST_V1_H

#include <stddef.h>
#include <stdint.h>

#define AXI_TRUST_V1_MAGIC "TRS1"
#define AXI_TRUST_V1_VERSION 1u
#define AXI_TRUST_V1_MAX_IDENTITIES 3u
#define AXI_TRUST_V1_MAX_KEYS 3u
#define AXI_TRUST_V1_MAX_GRANTS 3u
#define AXI_TRUST_V1_MAX_POLICIES 1u
#define AXI_TRUST_V1_MAX_REVOCATIONS 1u
#define AXI_TRUST_V1_MAX_APPROVALS 16u
#define AXI_TRUST_V1_APPROVAL_DOMAIN "AXI-TRUST-APPROVAL-v1"
#define AXI_TRUST_V1_APPROVAL_MSG_SIZE \
    (sizeof(AXI_TRUST_V1_APPROVAL_DOMAIN) + 32u + 32u + 32u + 1u + 32u + 1u + 32u)

enum {
    AXI_TRUST_V1_PURPOSE_PRODUCE = 1,
    AXI_TRUST_V1_PURPOSE_APPROVE = 2,
    AXI_TRUST_V1_PURPOSE_ATTEST = 3
};

enum {
    AXI_TRUST_V1_ROLE_AUTHOR = 1,
    AXI_TRUST_V1_ROLE_APPROVER = 2,
    AXI_TRUST_V1_ROLE_AUDITOR = 3
};

typedef struct {
    uint8_t key_id[32];
    uint8_t sig[64];
} axi_trust_v1_approval;

typedef struct {
    uint8_t subject_kind;
    uint8_t subject_digest[32];
    uint8_t has_subject_identity;
    uint8_t subject_identity_id[32];
    uint8_t policy_id[32];
    uint8_t scope_id[32];
    uint64_t evaluation_time;
    const axi_trust_v1_approval *approvals;
    size_t approval_count;
} axi_trust_v1_appraisal_request;

typedef struct {
    uint8_t snapshot_root[32];
    uint64_t snapshot_sequence;
    uint8_t snapshot_valid_at_supplied_time;
    uint8_t policy_found;
    uint8_t authorization;
    uint8_t quorum;
    uint8_t signature_valid;
    uint8_t counted_identities;
} axi_trust_v1_appraisal;

int axi_trust_v1_snapshot_root(const uint8_t *snapshot, size_t len,
                               uint8_t out[32]);
int axi_trust_v1_check_transition(const uint8_t *previous, size_t previous_len,
                                  const uint8_t *next, size_t next_len);
void axi_trust_v1_approval_message(const uint8_t snapshot_root[32],
                                   const axi_trust_v1_appraisal_request *req,
                                   uint8_t out[AXI_TRUST_V1_APPROVAL_MSG_SIZE]);
int axi_trust_v1_appraise(const uint8_t *snapshot, size_t len,
                          const axi_trust_v1_appraisal_request *req,
                          axi_trust_v1_appraisal *out);

#endif /* AXI_TRUST_V1_H */
