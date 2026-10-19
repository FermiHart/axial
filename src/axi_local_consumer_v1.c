/* ADR-059 AXV2-13: thin orchestration over 05-12. See header. */
#include "axi_local_consumer_v1.h"

#include "axi_ag1_v1.h"

#include <string.h>

int axi_local_consumer_v1_authorize(
    const void *action_bytes, size_t action_len,
    const axi_local_admission_v1_pins *pins,
    const axi_local_admission_v1_observed *observed,
    axi_local_admission_v1_result *out)
{
    axi_local_action_v1 action;
    if (!action_bytes || action_len == 0
            || action_len > AXI_LOCAL_ACTION_V1_MAX_BYTES || !pins
            || !observed || !out) {
        return AXI_LOCAL_CONSUMER_V1_INVALID;
    }
    memset(out, 0, sizeof(*out));
    /* Decode first so malformed bytes refuse as INPUT with zeros bound,
     * before any comparison runs. */
    if (axi_local_action_v1_decode(&action, action_bytes, action_len)
            != 0) {
        out->refusal = AXI_LOCAL_ADMISSION_V1_REFUSE_INPUT;
        out->profile = observed->profile;
        return AXI_LOCAL_CONSUMER_V1_REFUSED;
    }
    if (axi_local_admission_v1_appraise(action_bytes, action_len, pins,
                                        observed, out) != 0) {
        return AXI_LOCAL_CONSUMER_V1_REFUSED;
    }
    return out->admitted ? AXI_LOCAL_CONSUMER_V1_OK
                         : AXI_LOCAL_CONSUMER_V1_REFUSED;
}

static int map_owner(int rc,
                     const axi_local_attempt_v1_outcome *ao)
{
    (void)ao;
    switch (rc) {
    case AXI_LOCAL_ATTEMPT_V1_OK:
        return AXI_LOCAL_CONSUMER_V1_OK;
    case AXI_LOCAL_ATTEMPT_V1_TIMEOUT:
        return AXI_LOCAL_CONSUMER_V1_TIMEOUT;
    case AXI_LOCAL_ATTEMPT_V1_STORE_FULL:
        return AXI_LOCAL_CONSUMER_V1_STORE_FULL;
    case AXI_LOCAL_ATTEMPT_V1_CORRUPT:
        return AXI_LOCAL_CONSUMER_V1_CORRUPT;
    default:
        return AXI_LOCAL_CONSUMER_V1_REFUSED;
    }
}

int axi_local_consumer_v1_commit(
    const char *store_dir, const uint8_t *grant_signed, size_t grant_len,
    const uint8_t issuer_pk[32], const void *action_bytes, size_t action_len,
    const axi_local_admission_v1_pins *pins,
    const axi_local_admission_v1_observed *observed,
    const uint8_t *payload, size_t payload_len, uint64_t supplied_time,
    uint64_t deadline_mono_ns, const uint8_t *receipt_seed,
    uint8_t aer2_out[AXI_AER2_V1_SIGNED_SIZE],
    axi_local_attempt_v1_outcome *attempt_out)
{
    axi_local_action_v1 action;
    axi_local_action_roots_v1 roots;
    axi_local_admission_v1_result adm;
    axi_local_attempt_v1_outcome ao;
    int rc;
    if (!store_dir || !*store_dir || !grant_signed || !issuer_pk
            || !action_bytes || action_len == 0
            || action_len > AXI_LOCAL_ACTION_V1_MAX_BYTES || !pins
            || !observed || (!payload && payload_len > 0)
            || payload_len > AXI_LOCAL_ACTION_V1_MAX_BYTES
            || !attempt_out || (receipt_seed && !aer2_out)) {
        return AXI_LOCAL_CONSUMER_V1_INVALID;
    }
    memset(attempt_out, 0, sizeof(*attempt_out));
    if (aer2_out) {
        memset(aer2_out, 0, AXI_AER2_V1_SIGNED_SIZE);
    }
    /* Decode + appraise first (same refusal order as authorize), so the
     * caller learns refusal reasons before any spend or effect. */
    if (axi_local_action_v1_decode(&action, action_bytes, action_len)
            != 0
            || axi_local_action_v1_roots(&action, &roots) != 0) {
        return AXI_LOCAL_CONSUMER_V1_REFUSED;
    }
    memset(&adm, 0, sizeof(adm));
    if (axi_local_admission_v1_appraise(action_bytes, action_len, pins,
                                        observed, &adm) != 0
            || !adm.admitted) {
        return AXI_LOCAL_CONSUMER_V1_REFUSED;
    }
    rc = axi_local_attempt_v1_commit_deadline(
        store_dir, grant_signed, grant_len, issuer_pk, action_bytes,
        action_len, pins, observed, payload, payload_len, supplied_time,
        deadline_mono_ns, &ao);
    *attempt_out = ao;
    if (rc != AXI_LOCAL_ATTEMPT_V1_OK) {
        return map_owner(rc, &ao);
    }
    if (receipt_seed) {
        axi_aer2_v1 receipt;
        uint8_t decision = AXI_AER2_V1_DECISION_ALLOW;
        uint8_t owner_state;
        switch (ao.state) {
        case AXI_LOCAL_ATTEMPT_V1_COMMITTED:
            owner_state = AXI_LOCAL_ATTEMPT_V1_COMMITTED;
            break;
        case AXI_LOCAL_ATTEMPT_V1_FAILED:
            owner_state = AXI_LOCAL_ATTEMPT_V1_FAILED;
            break;
        default:
            return AXI_LOCAL_CONSUMER_V1_CORRUPT;
        }
        memset(&receipt, 0, sizeof(receipt));
        if (axi_aer2_v1_from_attempt(&roots, action.policy_module,
                                     ao.grant_root, 1, &adm,
                                     observed->coverage_complete,
                                     observed->profile, decision,
                                     owner_state, &receipt) != 0
                || axi_aer2_v1_encode_signed(&receipt, receipt_seed,
                                            aer2_out) != 0) {
            memset(aer2_out, 0, AXI_AER2_V1_SIGNED_SIZE);
            return AXI_LOCAL_CONSUMER_V1_CORRUPT;
        }
    }
    return AXI_LOCAL_CONSUMER_V1_OK;
}

int axi_local_consumer_v1_query(const char *store_dir,
                                const uint8_t grant_root[32],
                                axi_local_attempt_v1_outcome *out)
{
    int rc;
    if (!store_dir || !grant_root || !out) {
        return AXI_LOCAL_CONSUMER_V1_INVALID;
    }
    memset(out, 0, sizeof(*out));
    rc = axi_local_attempt_v1_status(store_dir, grant_root, out);
    return map_owner(rc, out);
}

typedef struct {
    unsigned records;
    unsigned unknowns;
    int failed;
} scan_acc;

static int scan_count_visit(const axi_local_attempt_v1_record_view *view,
                            void *ctx)
{
    scan_acc *acc = ctx;
    acc->records++;
    if (view->state == AXI_LOCAL_ATTEMPT_V1_UNKNOWN) {
        acc->unknowns++;
    }
    return 0;
}

int axi_local_consumer_v1_scan_count(const char *store_dir,
                                     unsigned *records, unsigned *unknowns)
{
    scan_acc acc;
    int rc;
    if (!store_dir || !records || !unknowns) {
        return AXI_LOCAL_CONSUMER_V1_INVALID;
    }
    *records = 0;
    *unknowns = 0;
    memset(&acc, 0, sizeof(acc));
    rc = axi_local_attempt_v1_scan(store_dir, scan_count_visit, &acc);
    if (rc != AXI_LOCAL_ATTEMPT_V1_OK) {
        return map_owner(rc, NULL);
    }
    *records = acc.records;
    *unknowns = acc.unknowns;
    return AXI_LOCAL_CONSUMER_V1_OK;
}

int axi_local_consumer_v1_evidence(
    const axi_local_action_roots_v1 *roots, const uint8_t artifact[32],
    const uint8_t *grant_root, int has_grant,
    const axi_local_admission_v1_result *admitted, uint8_t coverage_complete,
    uint8_t profile, uint8_t decision, uint8_t owner_state,
    const uint8_t receipt_seed[32],
    uint8_t aer2_out[AXI_AER2_V1_SIGNED_SIZE])
{
    axi_aer2_v1 receipt;
    if (!roots || !artifact || !receipt_seed || !aer2_out) {
        return AXI_LOCAL_CONSUMER_V1_INVALID;
    }
    memset(aer2_out, 0, AXI_AER2_V1_SIGNED_SIZE);
    memset(&receipt, 0, sizeof(receipt));
    if (axi_aer2_v1_from_attempt(roots, artifact, grant_root, has_grant,
                                 admitted, coverage_complete, profile,
                                 decision, owner_state, &receipt) != 0
            || axi_aer2_v1_encode_signed(&receipt, receipt_seed,
                                        aer2_out) != 0) {
        memset(aer2_out, 0, AXI_AER2_V1_SIGNED_SIZE);
        return AXI_LOCAL_CONSUMER_V1_REFUSED;
    }
    return AXI_LOCAL_CONSUMER_V1_OK;
}
