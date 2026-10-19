#ifndef AXI_ADMISSION_V1_H
#define AXI_ADMISSION_V1_H

#include <stdint.h>

#define AXI_ADMISSION_V1_DOMAIN "AXI-ADMISSION-v1"

enum {
    AXI_PROFILE_UNTRUSTED_DEV = 1,
    AXI_PROFILE_TRUSTED_PROD = 2
};

enum {
    AXI_ASSURANCE_SIGNATURE_VALID = 1,
    AXI_ASSURANCE_CHECKED = 2
};

enum {
    AXI_ADMISSION_OK = 0,
    AXI_ADMISSION_REFUSE_PROFILE = 1,
    AXI_ADMISSION_REFUSE_ASSURANCE = 2,
    AXI_ADMISSION_REFUSE_TRUST = 3,
    AXI_ADMISSION_REFUSE_COVERAGE = 4,
    AXI_ADMISSION_REFUSE_AG1 = 5,
    AXI_ADMISSION_REFUSE_INPUT = 6
};

typedef struct {
    uint8_t profile;
    uint8_t artifact_assurance;
    uint8_t required_assurance;
    uint8_t trust_authorized;
    uint8_t coverage_complete;
    uint8_t effectful;
    uint8_t ag1_present;
    uint8_t artifact_root[32];
    uint8_t producer_key_id[32];
    uint8_t trust_snapshot_root[32];
    uint8_t coverage_root[32];
    uint8_t checker_root[32];
    uint8_t budget_root[32];
    uint8_t action_root[32];
} axi_admission_v1_request;

typedef struct {
    uint8_t admitted;
    uint8_t refusal;
    uint8_t profile;
    uint8_t artifact_assurance;
    uint8_t required_assurance;
    uint8_t ag1_required;
    uint8_t context_root[32];
} axi_admission_v1_result;

int axi_admission_v1_appraise(const axi_admission_v1_request *req,
                              axi_admission_v1_result *out);

#endif /* AXI_ADMISSION_V1_H */
