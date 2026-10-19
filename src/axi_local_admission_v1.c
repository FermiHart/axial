/* ADR-059 AXV2-06 / AXI-INV-185: unified local appraisal before any effect. */
#include "axi_local_admission_v1.h"
#include "axi_hash.h"
#include "axi_local_action_v1.h"
#include <string.h>

/* Context projection is a fixed binary layout (494 bytes total):
 * domain "AXV2-ADMISSION-v1"+NUL (18), profile(1), refusal(1),
 * coverage_complete(1), clock_available(1), now_ns BE(8),
 * claimed deployment(16), boot(16), trust(32), policy x4(128),
 * uid BE(4), executor_uid BE(4), resource_device BE(8),
 * resource_inode BE(8), payload_size BE(8), payload_sha(32),
 * not_before BE(8), not_after BE(8),
 * pinned deployment(16), trust(32), policy x4(128), observed boot(16).
 * The Python oracle replicates this layout byte for byte. */
#define AXI_LOCAL_ADMISSION_V1_CONTEXT_LEN 494u

static int zero(const uint8_t *bytes, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) if (bytes[i]) return 0;
    return 1;
}

static int equal_bytes(const uint8_t *a, const uint8_t *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

static void put_be32(uint8_t **p, uint32_t v)
{
    (*p)[0] = (uint8_t)(v >> 24); (*p)[1] = (uint8_t)(v >> 16);
    (*p)[2] = (uint8_t)(v >> 8); (*p)[3] = (uint8_t)v;
    *p += 4;
}

static void put_be64(uint8_t **p, uint64_t v)
{
    (*p)[0] = (uint8_t)(v >> 56); (*p)[1] = (uint8_t)(v >> 48);
    (*p)[2] = (uint8_t)(v >> 40); (*p)[3] = (uint8_t)(v >> 32);
    (*p)[4] = (uint8_t)(v >> 24); (*p)[5] = (uint8_t)(v >> 16);
    (*p)[6] = (uint8_t)(v >> 8); (*p)[7] = (uint8_t)v;
    *p += 8;
}

static void put_copy(uint8_t **p, const uint8_t *src, size_t n)
{
    memcpy(*p, src, n);
    *p += n;
}

int axi_local_admission_v1_appraise(const void *action_bytes, size_t action_len,
                                    const axi_local_admission_v1_pins *pins,
                                    const axi_local_admission_v1_observed *observed,
                                    axi_local_admission_v1_result *out)
{
    axi_local_admission_v1_result staged;
    axi_local_action_v1 action;
    uint8_t refusal = AXI_LOCAL_ADMISSION_V1_REFUSE_INPUT;
    uint8_t profile = 0;
    int decoded = 0;
    memset(&staged, 0, sizeof staged);
    if (!out) return AXI_LOCAL_ADMISSION_V1_REFUSED;
    if (!action_bytes || !pins || !observed) {
        staged.refusal = AXI_LOCAL_ADMISSION_V1_REFUSE_INPUT;
        memcpy(out, &staged, sizeof staged);
        return AXI_LOCAL_ADMISSION_V1_REFUSED;
    }
    profile = observed->profile;
    staged.profile = profile;
    if (!action_len || action_len > AXI_LOCAL_ACTION_V1_MAX_BYTES) {
        staged.refusal = AXI_LOCAL_ADMISSION_V1_REFUSE_INPUT;
        memcpy(out, &staged, sizeof staged);
        return AXI_LOCAL_ADMISSION_V1_REFUSED;
    }
    if (observed->clock_available > 1 || observed->coverage_complete > 1 ||
            zero(pins->deployment, sizeof pins->deployment) ||
            zero(pins->trust_snapshot_root, sizeof pins->trust_snapshot_root) ||
            zero(pins->policy_binary, sizeof pins->policy_binary) ||
            zero(pins->policy_module, sizeof pins->policy_module) ||
            zero(pins->policy_producer, sizeof pins->policy_producer) ||
            zero(pins->policy_iface, sizeof pins->policy_iface)) {
        staged.refusal = AXI_LOCAL_ADMISSION_V1_REFUSE_INPUT;
        memcpy(out, &staged, sizeof staged);
        return AXI_LOCAL_ADMISSION_V1_REFUSED;
    }
    /* The codec validates the complete canonical document before any typed
     * extraction; admission never re-parses JSON itself. */
    if (axi_local_action_v1_decode(&action, action_bytes, action_len) != 0) {
        staged.refusal = AXI_LOCAL_ADMISSION_V1_REFUSE_INPUT;
        memcpy(out, &staged, sizeof staged);
        return AXI_LOCAL_ADMISSION_V1_REFUSED;
    }
    decoded = 1;
    if (profile != AXI_LOCAL_ADMISSION_V1_DEV &&
            profile != AXI_LOCAL_ADMISSION_V1_PROD)
        refusal = AXI_LOCAL_ADMISSION_V1_REFUSE_PROFILE;
    else if (!equal_bytes(action.trust_snapshot_root, pins->trust_snapshot_root, 32))
        refusal = AXI_LOCAL_ADMISSION_V1_REFUSE_TRUST;
    else if (!equal_bytes(action.policy_binary, pins->policy_binary, 32) ||
            !equal_bytes(action.policy_module, pins->policy_module, 32) ||
            !equal_bytes(action.policy_producer, pins->policy_producer, 32) ||
            !equal_bytes(action.policy_iface, pins->policy_iface, 32))
        refusal = AXI_LOCAL_ADMISSION_V1_REFUSE_POLICY;
    else if (!equal_bytes(action.deployment, pins->deployment, 16) ||
            !equal_bytes(action.boot, observed->boot, 16))
        refusal = AXI_LOCAL_ADMISSION_V1_REFUSE_BINDING;
    else if (profile == AXI_LOCAL_ADMISSION_V1_PROD && !observed->coverage_complete)
        refusal = AXI_LOCAL_ADMISSION_V1_REFUSE_COVERAGE;
    else if (!observed->clock_available)
        refusal = AXI_LOCAL_ADMISSION_V1_REFUSE_CLOCK;
    else if (observed->now_ns < action.not_before || observed->now_ns >= action.not_after)
        refusal = AXI_LOCAL_ADMISSION_V1_REFUSE_TIME;
    else
        refusal = AXI_LOCAL_ADMISSION_V1_ADMITTED;
    staged.admitted = refusal == AXI_LOCAL_ADMISSION_V1_ADMITTED ? 1u : 0u;
    staged.refusal = refusal;
    staged.profile = profile;
    if (decoded) {
        /* AXI-INV-185: bind the compared claimed, pinned and observed
         * values once; INPUT from shape/decode failure binds zeros. */
        uint8_t bytes[AXI_LOCAL_ADMISSION_V1_CONTEXT_LEN];
        uint8_t *p = bytes;
        put_copy(&p, (const uint8_t *)AXI_LOCAL_ADMISSION_V1_DOMAIN,
                 sizeof AXI_LOCAL_ADMISSION_V1_DOMAIN);
        *p++ = profile; *p++ = refusal;
        *p++ = observed->coverage_complete; *p++ = observed->clock_available;
        put_be64(&p, observed->now_ns);
        put_copy(&p, action.deployment, 16); put_copy(&p, action.boot, 16);
        put_copy(&p, action.trust_snapshot_root, 32);
        put_copy(&p, action.policy_binary, 32); put_copy(&p, action.policy_module, 32);
        put_copy(&p, action.policy_producer, 32); put_copy(&p, action.policy_iface, 32);
        put_be32(&p, action.uid); put_be32(&p, action.executor_uid);
        put_be64(&p, action.resource_device); put_be64(&p, action.resource_inode);
        put_be64(&p, action.payload_size); put_copy(&p, action.payload_sha256, 32);
        put_be64(&p, action.not_before); put_be64(&p, action.not_after);
        put_copy(&p, pins->deployment, 16); put_copy(&p, pins->trust_snapshot_root, 32);
        put_copy(&p, pins->policy_binary, 32); put_copy(&p, pins->policy_module, 32);
        put_copy(&p, pins->policy_producer, 32); put_copy(&p, pins->policy_iface, 32);
        put_copy(&p, observed->boot, 16);
        if ((size_t)(p - bytes) == sizeof bytes) {
            axi_sha256(bytes, sizeof bytes, staged.context_root);
        } else {
            /* Unreachable fixed-layout guard: bind nothing and refuse. */
            staged.admitted = 0;
            staged.refusal = AXI_LOCAL_ADMISSION_V1_REFUSE_INPUT;
            memset(staged.context_root, 0, sizeof staged.context_root);
            refusal = AXI_LOCAL_ADMISSION_V1_REFUSE_INPUT;
        }
    }
    memcpy(out, &staged, sizeof staged);
    return staged.admitted ? AXI_LOCAL_ADMISSION_V1_OK : AXI_LOCAL_ADMISSION_V1_REFUSED;
}
