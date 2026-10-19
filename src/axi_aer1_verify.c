#include "axi_aer1_verify.h"

#include "axi_hash.h"
#include "ed25519.h"

#include <string.h>

typedef struct {
    const uint8_t *p;
    size_t len;
    size_t off;
    int err;
} aer_reader;

static const uint8_t *rd(aer_reader *r, size_t len)
{
    const uint8_t *p;
    if (!r || r->err || len > r->len - r->off) {
        if (r) r->err = 1;
        return NULL;
    }
    p = r->p + r->off;
    r->off += len;
    return p;
}

static uint8_t rd_u8(aer_reader *r)
{
    const uint8_t *p = rd(r, 1);
    return p ? p[0] : 0;
}

static uint32_t rd_u32(aer_reader *r)
{
    const uint8_t *p = rd(r, 4);
    return p ? ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
             | ((uint32_t)p[2] << 8) | (uint32_t)p[3] : 0;
}

static uint64_t rd_u64(aer_reader *r)
{
    uint64_t value = 0;
    const uint8_t *p = rd(r, 8);
    size_t i;
    if (!p) return 0;
    for (i = 0; i < 8; i++) value = (value << 8) | p[i];
    return value;
}

static void rd_root(aer_reader *r, uint8_t root[32])
{
    const uint8_t *p = rd(r, 32);
    if (p) memcpy(root, p, 32);
}

static int root_zero(const uint8_t root[32])
{
    size_t i;
    for (i = 0; i < 32; i++) if (root[i] != 0) return 0;
    return 1;
}

static int optional_root_valid(uint8_t present, const uint8_t root[32])
{
    return present <= 1u && (present || root_zero(root));
}

static int parsed_valid(const axi_aer1 *receipt)
{
    if (!receipt || receipt->decision > AXI_AER1_DECISION_DENY
            || receipt->attempt > AXI_AER1_ATTEMPT_ATTEMPTED
            || receipt->outcome > AXI_AER1_OUTCOME_COMPENSATED
            || receipt->evidence > 1u
            || receipt->coverage > AXI_AER1_COVERAGE_COMPLETE
            || receipt->profile < AXI_AER1_PROFILE_DEV
            || receipt->profile > AXI_AER1_PROFILE_PROD
            || receipt->opacity < AXI_AER1_OPACITY_CLEAR
            || receipt->opacity > AXI_AER1_OPACITY_CONFIDENTIAL
            || receipt->maturity < AXI_AER1_MATURITY_DEV
            || receipt->maturity > AXI_AER1_MATURITY_ATTESTED)
        return 0;
    if (receipt->attempt == AXI_AER1_ATTEMPT_NOT_ATTEMPTED
            && receipt->outcome != AXI_AER1_OUTCOME_NONE)
        return 0;
    if (receipt->attempt == AXI_AER1_ATTEMPT_ATTEMPTED
            && receipt->outcome == AXI_AER1_OUTCOME_NONE)
        return 0;
    if (!receipt->has_policy_root
            && receipt->decision != AXI_AER1_DECISION_UNPROVEN)
        return 0;
    if (receipt->coverage == AXI_AER1_COVERAGE_UNKNOWN
            ? receipt->has_coverage_root != 0
            : receipt->has_coverage_root == 0)
        return 0;
    if (!receipt->has_artifact_root || root_zero(receipt->principal_root)
            || root_zero(receipt->action_root) || root_zero(receipt->budget_root))
        return 0;
    return optional_root_valid(receipt->has_policy_root, receipt->policy_root)
        && optional_root_valid(receipt->has_grant_root, receipt->grant_root)
        && optional_root_valid(receipt->has_coverage_root, receipt->coverage_root)
        && optional_root_valid(receipt->has_episode_root, receipt->episode_root)
        && optional_root_valid(receipt->has_artifact_root, receipt->artifact_root);
}

static int parse_body(axi_aer1 *receipt, const uint8_t *bytes, size_t len)
{
    aer_reader r = {bytes, len, 0, 0};
    if (!receipt || !bytes || len != AXI_AER1_ENCODED_SIZE
            || memcmp(rd(&r, 4), "AER1", 4) != 0 || rd_u32(&r) != 1)
        return -1;
    memset(receipt, 0, sizeof *receipt);
    receipt->decision = rd_u8(&r);
    receipt->attempt = rd_u8(&r);
    receipt->outcome = rd_u8(&r);
    receipt->evidence = rd_u8(&r);
    receipt->coverage = rd_u8(&r);
    receipt->profile = rd_u8(&r);
    receipt->opacity = rd_u8(&r);
    receipt->maturity = rd_u8(&r);
    receipt->has_policy_root = rd_u8(&r);
    receipt->has_grant_root = rd_u8(&r);
    receipt->has_coverage_root = rd_u8(&r);
    receipt->has_episode_root = rd_u8(&r);
    receipt->has_artifact_root = rd_u8(&r);
    rd_root(&r, receipt->principal_root);
    rd_root(&r, receipt->artifact_root);
    rd_root(&r, receipt->policy_root);
    rd_root(&r, receipt->grant_root);
    rd_root(&r, receipt->action_root);
    rd_root(&r, receipt->coverage_root);
    rd_root(&r, receipt->budget_root);
    rd_root(&r, receipt->episode_root);
    rd_root(&r, receipt->ledger_tip);
    rd_root(&r, receipt->journal_tip);
    receipt->fuel_used = rd_u64(&r);
    receipt->resources.calls = rd_u64(&r);
    receipt->resources.input_bytes = rd_u64(&r);
    receipt->resources.output_bytes = rd_u64(&r);
    receipt->resources.handles = rd_u64(&r);
    receipt->resources.children = rd_u64(&r);
    return !r.err && r.off == len && parsed_valid(receipt) ? 0 : -1;
}

static void signature_message(const uint8_t *body, uint8_t message[sizeof(AXI_AER1_SIG_DOMAIN) + 32])
{
    memcpy(message, AXI_AER1_SIG_DOMAIN, sizeof(AXI_AER1_SIG_DOMAIN));
    axi_sha256(body, AXI_AER1_ENCODED_SIZE,
               message + sizeof(AXI_AER1_SIG_DOMAIN));
}

int axi_aer1_verify_signed(axi_aer1 *receipt, const uint8_t *bytes,
                           size_t len, const uint8_t trusted_pk[32])
{
    axi_aer1 parsed;
    uint8_t message[sizeof(AXI_AER1_SIG_DOMAIN) + 32];
    const uint8_t *pk, *signature;
    if (!receipt || !bytes || !trusted_pk || len != AXI_AER1_SIGNED_SIZE
            || memcmp(bytes + AXI_AER1_ENCODED_SIZE, "AERS", 4) != 0
            || bytes[AXI_AER1_ENCODED_SIZE + 4] != 0
            || bytes[AXI_AER1_ENCODED_SIZE + 5] != 0
            || bytes[AXI_AER1_ENCODED_SIZE + 6] != 0
            || bytes[AXI_AER1_ENCODED_SIZE + 7] != 1)
        return -1;
    pk = bytes + AXI_AER1_ENCODED_SIZE + 8;
    signature = bytes + AXI_AER1_ENCODED_SIZE + 40;
    if (memcmp(pk, trusted_pk, 32) != 0) return -1;
    signature_message(bytes, message);
    if (ed25519_verify(signature, message, (uint32_t)sizeof message, pk) != 0)
        return -1;
    if (parse_body(&parsed, bytes, AXI_AER1_ENCODED_SIZE) != 0) return -1;
    *receipt = parsed;
    return 0;
}
