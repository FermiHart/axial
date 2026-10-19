#ifndef AXI_EXTDEC_V1_H
#define AXI_EXTDEC_V1_H

#include <stdint.h>

#define AXI_EXTDEC_V1_DOMAIN "AXI-EXTDEC-v1"

enum {
    AXI_EXTDEC_OPA = 1,
    AXI_EXTDEC_CEDAR = 2,
    AXI_EXTDEC_CEL = 3,
    AXI_EXTDEC_JSON_SCHEMA = 4,
    AXI_EXTDEC_OCC = 5
};

enum {
    AXI_EXTDEC_ALLOW = 1,
    AXI_EXTDEC_DENY = 2,
    AXI_EXTDEC_UNPROVEN = 3
};

typedef struct {
    uint8_t adapter_kind;
    uint8_t verdict;
    uint8_t authenticated;
    uint8_t adapter_profile_root[32];
    uint8_t policy_root[32];
    uint8_t query_root[32];
    uint8_t input_root[32];
    uint8_t action_root[32];
    uint8_t native_result_root[32];
    uint8_t obligation_root[32];
} axi_extdec_v1_fact;

int axi_extdec_v1_from_bool(axi_extdec_v1_fact *fact, uint8_t adapter_kind,
                            uint8_t authenticated,
                            const uint8_t adapter_profile_root[32],
                            const uint8_t policy_root[32],
                            const uint8_t query_root[32],
                            const uint8_t input_root[32],
                            const uint8_t action_root[32],
                            const uint8_t native_result_root[32],
                            const uint8_t obligation_root[32],
                            uint8_t has_bool, uint8_t bool_value);
int axi_extdec_v1_root(const axi_extdec_v1_fact *fact, uint8_t out[32]);
int axi_extdec_v1_allows_narrowing(const axi_extdec_v1_fact *fact,
                                   const uint8_t local_action_root[32],
                                   const uint8_t local_obligation_root[32]);

#endif /* AXI_EXTDEC_V1_H */
