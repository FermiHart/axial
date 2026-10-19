#include "axi_rollout_v1.h"

#include "axi_hash.h"

#include <string.h>

static int root_zero(const uint8_t root[32])
{
    size_t i;
    for (i = 0; i < 32; i++) if (root[i] != 0) return 0;
    return 1;
}

static int mode_valid(uint8_t mode)
{
    return mode == AXI_ROLLOUT_MODE_STAGED || mode == AXI_ROLLOUT_MODE_SHADOW
        || mode == AXI_ROLLOUT_MODE_CANARY || mode == AXI_ROLLOUT_MODE_ACTIVE;
}

static uint8_t *wr_u32(uint8_t *p, uint32_t value)
{
    *p++ = (uint8_t)(value >> 24);
    *p++ = (uint8_t)(value >> 16);
    *p++ = (uint8_t)(value >> 8);
    *p++ = (uint8_t)value;
    return p;
}

static uint8_t *wr_u64(uint8_t *p, uint64_t value)
{
    int i;
    for (i = 7; i >= 0; i--) *p++ = (uint8_t)(value >> (i * 8));
    return p;
}

static int state_valid(const axi_rollout1_state *s, int genesis)
{
    if (!s || !mode_valid(s->mode) || s->canary_permyriad > 10000
            || root_zero(s->deployment_id) || root_zero(s->active_policy_root)
            || root_zero(s->ca38_appraisal_root) || root_zero(s->rollout_authority_root))
        return 0;
    if (genesis) {
        if (s->sequence != 1 || !root_zero(s->predecessor_root)) return 0;
    } else if (s->sequence <= 1 || root_zero(s->predecessor_root)) {
        return 0;
    }
    if ((s->mode == AXI_ROLLOUT_MODE_SHADOW || s->mode == AXI_ROLLOUT_MODE_CANARY)
            && root_zero(s->candidate_policy_root))
        return 0;
    if ((s->mode == AXI_ROLLOUT_MODE_STAGED || s->mode == AXI_ROLLOUT_MODE_ACTIVE)
            && !root_zero(s->candidate_policy_root))
        return 0;
    if (s->mode != AXI_ROLLOUT_MODE_CANARY && s->canary_permyriad != 0) return 0;
    return 1;
}

void axi_rollout1_root(const axi_rollout1_state *s, uint8_t out[32])
{
    uint8_t bytes[sizeof(AXI_ROLLOUT1_DOMAIN) + 32u * 7u + 1u + 8u + 8u + 4u + 8u];
    uint8_t *p = bytes;
    if (!out) return;
    memset(out, 0, 32);
    if (!state_valid(s, s && s->sequence == 1)) return;
    memcpy(p, AXI_ROLLOUT1_DOMAIN, sizeof(AXI_ROLLOUT1_DOMAIN));
    p += sizeof(AXI_ROLLOUT1_DOMAIN);
    memcpy(p, s->deployment_id, 32); p += 32;
    p = wr_u64(p, s->sequence);
    memcpy(p, s->predecessor_root, 32); p += 32;
    memcpy(p, s->active_policy_root, 32); p += 32;
    memcpy(p, s->candidate_policy_root, 32); p += 32;
    memcpy(p, s->ca38_appraisal_root, 32); p += 32;
    memcpy(p, s->rollout_authority_root, 32); p += 32;
    *p++ = s->mode;
    p = wr_u64(p, s->generation);
    p = wr_u32(p, s->canary_permyriad);
    p = wr_u64(p, s->kill_epoch);
    axi_sha256(bytes, (size_t)(p - bytes), out);
}

int axi_rollout1_verify_transition(const axi_rollout1_state *prev,
                                   const axi_rollout1_state *next)
{
    uint8_t prev_root[32];
    if (!state_valid(prev, prev && prev->sequence == 1)
            || !state_valid(next, 0)
            || memcmp(prev->deployment_id, next->deployment_id, 32) != 0
            || next->sequence <= prev->sequence
            || next->generation < prev->generation
            || next->kill_epoch < prev->kill_epoch)
        return -1;
    axi_rollout1_root(prev, prev_root);
    if (memcmp(next->predecessor_root, prev_root, 32) != 0) return -1;
    if (next->kill_epoch > prev->kill_epoch) return 0;
    if (next->generation == prev->generation
            && memcmp(next->active_policy_root, prev->active_policy_root, 32) != 0)
        return -1;
    return 0;
}

int axi_rollout1_context_live(uint64_t context_kill_epoch,
                              const axi_rollout1_state *state)
{
    if (!state_valid(state, state && state->sequence == 1)) return -1;
    return context_kill_epoch >= state->kill_epoch ? 0 : -1;
}

int axi_rollout1_canary_select(const axi_rollout1_state *state,
                               const uint8_t cohort_key[32])
{
    uint8_t bytes[sizeof(AXI_ROLLOUT1_CANARY_DOMAIN) + 32u + 32u];
    uint8_t root[32], digest[32];
    uint32_t bucket;
    if (!state_valid(state, state && state->sequence == 1) || !cohort_key
            || state->mode != AXI_ROLLOUT_MODE_CANARY || root_zero(cohort_key))
        return -1;
    axi_rollout1_root(state, root);
    memcpy(bytes, AXI_ROLLOUT1_CANARY_DOMAIN, sizeof(AXI_ROLLOUT1_CANARY_DOMAIN));
    memcpy(bytes + sizeof(AXI_ROLLOUT1_CANARY_DOMAIN), root, 32);
    memcpy(bytes + sizeof(AXI_ROLLOUT1_CANARY_DOMAIN) + 32, cohort_key, 32);
    axi_sha256(bytes, sizeof bytes, digest);
    bucket = ((uint32_t)digest[0] << 24) | ((uint32_t)digest[1] << 16)
           | ((uint32_t)digest[2] << 8) | digest[3];
    return bucket % 10000u < state->canary_permyriad ? 1 : 0;
}
