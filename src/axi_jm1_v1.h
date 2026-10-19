#ifndef AXI_JM1_V1_H
#define AXI_JM1_V1_H

#include <stdint.h>

#define AXI_JM1_V1_DOMAIN "AXI-JM1-v1"
#define AXI_JM1_V1_REGISTRY_DOMAIN "AXI-JM1-REGISTRY-v1"

typedef struct {
    const char *name;
    uint8_t opaque_child;
} axi_jm1_action;

typedef struct {
    uint8_t action_root[32];
    uint8_t resolved_descriptor_root[32];
    uint8_t admission_root[32];
    uint8_t rollout_root[32];
    uint8_t ag1_action_root[32];
    uint8_t aer_channel_root[32];
} axi_jm1_descriptor;

int axi_jm1_registry_root(uint8_t out[32]);
int axi_jm1_action_root(const char *name, uint8_t out[32]);
int axi_jm1_descriptor_root(const axi_jm1_descriptor *descriptor, uint8_t out[32]);
int axi_jm1_final_door_check(const axi_jm1_descriptor *descriptor);

#endif /* AXI_JM1_V1_H */
