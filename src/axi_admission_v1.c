#include "axi_admission_v1.h"

#include "axi_hash.h"

#include <string.h>

static int root_zero(const uint8_t root[32])
{
    size_t i;
    for (i = 0; i < 32; i++) if (root[i] != 0) return 0;
    return 1;
}

static int profile_valid(uint8_t profile)
{
    return profile == AXI_PROFILE_UNTRUSTED_DEV
        || profile == AXI_PROFILE_TRUSTED_PROD;
}

static int assurance_valid(uint8_t assurance)
{
    return assurance == AXI_ASSURANCE_SIGNATURE_VALID
        || assurance == AXI_ASSURANCE_CHECKED;
}

static uint8_t *wr_root(uint8_t *p, const uint8_t root[32])
{
    memcpy(p, root, 32);
    return p + 32;
}

static void context_root(const axi_admission_v1_request *req,
                         uint8_t ag1_required, uint8_t refusal, uint8_t out[32])
{
    uint8_t bytes[sizeof(AXI_ADMISSION_V1_DOMAIN) + 8u + 32u * 7u];
    uint8_t *p = bytes;
    memcpy(p, AXI_ADMISSION_V1_DOMAIN, sizeof(AXI_ADMISSION_V1_DOMAIN));
    p += sizeof(AXI_ADMISSION_V1_DOMAIN);
    *p++ = req->profile;
    *p++ = req->artifact_assurance;
    *p++ = req->required_assurance;
    *p++ = req->trust_authorized;
    *p++ = req->coverage_complete;
    *p++ = req->effectful;
    *p++ = ag1_required;
    *p++ = refusal;
    p = wr_root(p, req->artifact_root);
    p = wr_root(p, req->producer_key_id);
    p = wr_root(p, req->trust_snapshot_root);
    p = wr_root(p, req->coverage_root);
    p = wr_root(p, req->checker_root);
    p = wr_root(p, req->budget_root);
    p = wr_root(p, req->action_root);
    axi_sha256(bytes, (size_t)(p - bytes), out);
}

static int request_valid(const axi_admission_v1_request *req)
{
    return req && profile_valid(req->profile)
        && assurance_valid(req->artifact_assurance)
        && assurance_valid(req->required_assurance)
        && req->trust_authorized <= 1 && req->coverage_complete <= 1
        && req->effectful <= 1 && req->ag1_present <= 1
        && !root_zero(req->artifact_root) && !root_zero(req->producer_key_id)
        && !root_zero(req->trust_snapshot_root) && !root_zero(req->coverage_root)
        && !root_zero(req->checker_root) && !root_zero(req->budget_root)
        && !root_zero(req->action_root);
}

int axi_admission_v1_appraise(const axi_admission_v1_request *req,
                              axi_admission_v1_result *out)
{
    uint8_t refusal = AXI_ADMISSION_OK;
    uint8_t ag1_required = 0;
    if (!out) return -1;
    memset(out, 0, sizeof *out);
    if (!req) {
        out->refusal = AXI_ADMISSION_REFUSE_INPUT;
        return -1;
    }
    if (!profile_valid(req->profile)) refusal = AXI_ADMISSION_REFUSE_PROFILE;
    else if (!request_valid(req)) refusal = AXI_ADMISSION_REFUSE_INPUT;
    else if (req->artifact_assurance < req->required_assurance)
        refusal = AXI_ADMISSION_REFUSE_ASSURANCE;
    else if (req->profile == AXI_PROFILE_TRUSTED_PROD && !req->trust_authorized)
        refusal = AXI_ADMISSION_REFUSE_TRUST;
    else if (req->profile == AXI_PROFILE_TRUSTED_PROD && !req->coverage_complete)
        refusal = AXI_ADMISSION_REFUSE_COVERAGE;
    ag1_required = req->profile == AXI_PROFILE_TRUSTED_PROD && req->effectful;
    if (refusal == AXI_ADMISSION_OK && ag1_required && !req->ag1_present)
        refusal = AXI_ADMISSION_REFUSE_AG1;
    out->admitted = refusal == AXI_ADMISSION_OK ? 1u : 0u;
    out->refusal = refusal;
    out->profile = req->profile;
    out->artifact_assurance = req->artifact_assurance;
    out->required_assurance = req->required_assurance;
    out->ag1_required = ag1_required;
    if (request_valid(req)) context_root(req, ag1_required, refusal, out->context_root);
    return out->admitted ? 0 : -1;
}
