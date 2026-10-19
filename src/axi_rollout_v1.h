#ifndef AXI_ROLLOUT_V1_H
#define AXI_ROLLOUT_V1_H

#include <stdint.h>

#define AXI_ROLLOUT1_DOMAIN "AXI-ROLLOUT1-v1"
#define AXI_ROLLOUT1_CANARY_DOMAIN "AXI-ROLLOUT1-CANARY-v1"

enum {
    AXI_ROLLOUT_MODE_STAGED = 1,
    AXI_ROLLOUT_MODE_SHADOW = 2,
    AXI_ROLLOUT_MODE_CANARY = 3,
    AXI_ROLLOUT_MODE_ACTIVE = 4
};

typedef struct {
    uint8_t deployment_id[32];
    uint64_t sequence;
    uint8_t predecessor_root[32];
    uint8_t active_policy_root[32];
    uint8_t candidate_policy_root[32];
    uint8_t ca38_appraisal_root[32];
    uint8_t rollout_authority_root[32];
    uint8_t mode;
    uint64_t generation;
    uint32_t canary_permyriad;
    uint64_t kill_epoch;
} axi_rollout1_state;

void axi_rollout1_root(const axi_rollout1_state *state, uint8_t out[32]);
int axi_rollout1_verify_transition(const axi_rollout1_state *prev,
                                   const axi_rollout1_state *next);
int axi_rollout1_context_live(uint64_t context_kill_epoch,
                              const axi_rollout1_state *state);
int axi_rollout1_canary_select(const axi_rollout1_state *state,
                               const uint8_t cohort_key[32]);

#endif /* AXI_ROLLOUT_V1_H */
