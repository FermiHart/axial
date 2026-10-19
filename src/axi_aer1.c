#include "axi_aer1.h"
#include "axi_hash.h"
#include "ed25519.h"

#include <string.h>

static void put32(uint8_t **p, uint32_t value)
{
    *(*p)++ = (uint8_t)(value >> 24);
    *(*p)++ = (uint8_t)(value >> 16);
    *(*p)++ = (uint8_t)(value >> 8);
    *(*p)++ = (uint8_t)value;
}

static void put64(uint8_t **p, uint64_t value)
{
    unsigned shift;
    for (shift = 64; shift != 0; shift -= 8) *(*p)++ = (uint8_t)(value >> (shift - 8));
}

static uint32_t get32(const uint8_t **p)
{
    uint32_t value = ((uint32_t)(*p)[0] << 24) | ((uint32_t)(*p)[1] << 16)
        | ((uint32_t)(*p)[2] << 8) | (*p)[3];
    *p += 4;
    return value;
}

static uint64_t get64(const uint8_t **p)
{
    uint64_t value = 0;
    unsigned i;
    for (i = 0; i < 8; i++) value = (value << 8) | *(*p)++;
    return value;
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

static int aer1_valid(const axi_aer1 *receipt)
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

int axi_aer1_encode(const axi_aer1 *receipt,
                    uint8_t out[AXI_AER1_ENCODED_SIZE])
{
    uint8_t *p = out;
    if (!out || !aer1_valid(receipt)) return -1;
    memcpy(p, "AER1", 4); p += 4;
    put32(&p, 1);
    *p++ = receipt->decision;
    *p++ = receipt->attempt;
    *p++ = receipt->outcome;
    *p++ = receipt->evidence;
    *p++ = receipt->coverage;
    *p++ = receipt->profile;
    *p++ = receipt->opacity;
    *p++ = receipt->maturity;
    *p++ = receipt->has_policy_root;
    *p++ = receipt->has_grant_root;
    *p++ = receipt->has_coverage_root;
    *p++ = receipt->has_episode_root;
    *p++ = receipt->has_artifact_root;
#define PUT_ROOT(field) memcpy(p, receipt->field, 32); p += 32
    PUT_ROOT(principal_root);
    PUT_ROOT(artifact_root);
    PUT_ROOT(policy_root);
    PUT_ROOT(grant_root);
    PUT_ROOT(action_root);
    PUT_ROOT(coverage_root);
    PUT_ROOT(budget_root);
    PUT_ROOT(episode_root);
    PUT_ROOT(ledger_tip);
    PUT_ROOT(journal_tip);
#undef PUT_ROOT
    put64(&p, receipt->fuel_used);
    put64(&p, receipt->resources.calls);
    put64(&p, receipt->resources.input_bytes);
    put64(&p, receipt->resources.output_bytes);
    put64(&p, receipt->resources.handles);
    put64(&p, receipt->resources.children);
    return p == out + AXI_AER1_ENCODED_SIZE ? 0 : -1;
}

int axi_aer1_decode(axi_aer1 *receipt, const uint8_t *bytes, size_t len)
{
    const uint8_t *p = bytes;
    if (!receipt || !bytes || len != AXI_AER1_ENCODED_SIZE
            || memcmp(p, "AER1", 4) != 0) return -1;
    p += 4;
    if (get32(&p) != 1) return -1;
    memset(receipt, 0, sizeof *receipt);
    receipt->decision = *p++;
    receipt->attempt = *p++;
    receipt->outcome = *p++;
    receipt->evidence = *p++;
    receipt->coverage = *p++;
    receipt->profile = *p++;
    receipt->opacity = *p++;
    receipt->maturity = *p++;
    receipt->has_policy_root = *p++;
    receipt->has_grant_root = *p++;
    receipt->has_coverage_root = *p++;
    receipt->has_episode_root = *p++;
    receipt->has_artifact_root = *p++;
#define GET_ROOT(field) memcpy(receipt->field, p, 32); p += 32
    GET_ROOT(principal_root);
    GET_ROOT(artifact_root);
    GET_ROOT(policy_root);
    GET_ROOT(grant_root);
    GET_ROOT(action_root);
    GET_ROOT(coverage_root);
    GET_ROOT(budget_root);
    GET_ROOT(episode_root);
    GET_ROOT(ledger_tip);
    GET_ROOT(journal_tip);
#undef GET_ROOT
    receipt->fuel_used = get64(&p);
    receipt->resources.calls = get64(&p);
    receipt->resources.input_bytes = get64(&p);
    receipt->resources.output_bytes = get64(&p);
    receipt->resources.handles = get64(&p);
    receipt->resources.children = get64(&p);
    return p == bytes + len && aer1_valid(receipt) ? 0 : -1;
}

void axi_aer1_root(const axi_aer1 *receipt, uint8_t root[32])
{
    uint8_t bytes[sizeof(AXI_AER1_BODY_DOMAIN) - 1 + AXI_AER1_ENCODED_SIZE];
    if (!root) return;
    memcpy(bytes, AXI_AER1_BODY_DOMAIN, sizeof(AXI_AER1_BODY_DOMAIN) - 1);
    if (axi_aer1_encode(receipt, bytes + sizeof(AXI_AER1_BODY_DOMAIN) - 1) != 0)
        memset(root, 0, 32);
    else axi_sha256(bytes, sizeof bytes, root);
}

static void aer1_signature_message(const uint8_t bytes[AXI_AER1_ENCODED_SIZE],
                                   uint8_t message[sizeof(AXI_AER1_SIG_DOMAIN) + 32])
{
    memcpy(message, AXI_AER1_SIG_DOMAIN, sizeof(AXI_AER1_SIG_DOMAIN));
    axi_sha256(bytes, AXI_AER1_ENCODED_SIZE,
               message + sizeof(AXI_AER1_SIG_DOMAIN));
}

int axi_aer1_encode_signed(const axi_aer1 *receipt, const uint8_t seed[32],
                           uint8_t out[AXI_AER1_SIGNED_SIZE])
{
    uint8_t secret[64], message[sizeof(AXI_AER1_SIG_DOMAIN) + 32];
    int rc = -1;
    if (!receipt || !seed || !out
            || axi_aer1_encode(receipt, out) != 0) return -1;
    memcpy(out + AXI_AER1_ENCODED_SIZE, "AERS", 4);
    out[AXI_AER1_ENCODED_SIZE + 4] = 0;
    out[AXI_AER1_ENCODED_SIZE + 5] = 0;
    out[AXI_AER1_ENCODED_SIZE + 6] = 0;
    out[AXI_AER1_ENCODED_SIZE + 7] = 1;
    ed25519_keypair_from_seed(seed, out + AXI_AER1_ENCODED_SIZE + 8, secret);
    aer1_signature_message(out, message);
    if (ed25519_sign(out + AXI_AER1_ENCODED_SIZE + 40, message,
                     (uint32_t)sizeof message, secret) == 0)
        rc = 0;
    memset(secret, 0, sizeof secret);
    return rc;
}

int axi_aer1_decode_signed(axi_aer1 *receipt, const uint8_t *bytes, size_t len,
                           const uint8_t trusted_pk[32])
{
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
    aer1_signature_message(bytes, message);
    if (ed25519_verify(signature, message, (uint32_t)sizeof message, pk) != 0)
        return -1;
    return axi_aer1_decode(receipt, bytes, AXI_AER1_ENCODED_SIZE);
}
