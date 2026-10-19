/* ADR-059 AXV2-09 / D02: AER2 terminal evidence for the narrow profile.
 *
 * Separate codec/verifier; AER1's code and corpus are never touched here.
 * Only primitives are reused (SHA-256, ed25519, resource envelope shape).
 * The independent verifier keeps its own reader and validity copy on
 * purpose: a verifier that shares the producer's checks proves nothing.
 */
#include "axi_aer2_v1.h"

#include "axi_hash.h"
#include "axi_wipe.h"
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
    for (shift = 64; shift != 0; shift -= 8)
        *(*p)++ = (uint8_t)(value >> (shift - 8));
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

/* Strict presence: a set flag binds a nonzero root, always. */
static int present_root_valid(uint8_t present, const uint8_t root[32])
{
    if (present > 1u) {
        return 0;
    }
    if (present) {
        return !root_zero(root);
    }
    return root_zero(root);
}

static int aer2_valid(const axi_aer2_v1 *r)
{
    if (!r || r->decision > AXI_AER2_V1_DECISION_DENY
            || r->attempt > AXI_AER2_V1_ATTEMPT_ATTEMPTED
            || r->outcome > AXI_AER2_V1_OUTCOME_UNKNOWN
            || r->evidence > 1u
            || r->coverage > AXI_AER2_V1_COVERAGE_COMPLETE
            || r->profile < AXI_AER2_V1_PROFILE_DEV
            || r->profile > AXI_AER2_V1_PROFILE_PROD
            || r->opacity < AXI_AER2_V1_OPACITY_CLEAR
            || r->opacity > AXI_AER2_V1_OPACITY_CONFIDENTIAL
            || r->maturity < AXI_AER2_V1_MATURITY_DEV
            || r->maturity > AXI_AER2_V1_MATURITY_ATTESTED)
        return 0;
    /* NONE exactly when NOT_ATTEMPTED; UNKNOWN only when ATTEMPTED. */
    if ((r->attempt == AXI_AER2_V1_ATTEMPT_NOT_ATTEMPTED)
            != (r->outcome == AXI_AER2_V1_OUTCOME_NONE))
        return 0;
    if (r->outcome == AXI_AER2_V1_OUTCOME_UNKNOWN
            && r->attempt != AXI_AER2_V1_ATTEMPT_ATTEMPTED)
        return 0;
    /* No authority bound to a non-attempt; full binding on terminals. */
    if (r->attempt == AXI_AER2_V1_ATTEMPT_NOT_ATTEMPTED) {
        if (r->has_grant_root) {
            return 0;
        }
    } else if (r->outcome != AXI_AER2_V1_OUTCOME_NONE) {
        if (!r->has_grant_root || root_zero(r->grant_root)
                || !r->has_policy_root || root_zero(r->policy_root)
                || !r->has_artifact_root || root_zero(r->artifact_root))
            return 0;
    }
    if (!r->has_policy_root
            && r->decision != AXI_AER2_V1_DECISION_UNPROVEN)
        return 0;
    if (r->coverage == AXI_AER2_V1_COVERAGE_UNKNOWN
            ? r->has_coverage_root != 0
            : r->has_coverage_root == 0)
        return 0;
    if (!r->has_artifact_root || root_zero(r->principal_root)
            || root_zero(r->action_root) || root_zero(r->budget_root))
        return 0;
    return present_root_valid(r->has_policy_root, r->policy_root)
        && present_root_valid(r->has_grant_root, r->grant_root)
        && present_root_valid(r->has_coverage_root, r->coverage_root)
        && present_root_valid(r->has_episode_root, r->episode_root)
        && present_root_valid(r->has_artifact_root, r->artifact_root);
}

int axi_aer2_v1_encode(const axi_aer2_v1 *receipt,
                       uint8_t out[AXI_AER2_V1_BODY_SIZE])
{
    uint8_t *p = out;
    if (!out || !aer2_valid(receipt)) return -1;
    memcpy(p, AXI_AER2_V1_MAGIC, 4); p += 4;
    put32(&p, AXI_AER2_V1_VERSION);
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
    return p == out + AXI_AER2_V1_BODY_SIZE ? 0 : -1;
}

int axi_aer2_v1_decode(axi_aer2_v1 *out, const uint8_t *bytes,
                       size_t len)
{
    axi_aer2_v1 parsed, *receipt = &parsed;
    const uint8_t *p = bytes;
    if (!out || !bytes || len != AXI_AER2_V1_BODY_SIZE
            || memcmp(p, AXI_AER2_V1_MAGIC, 4) != 0) return -1;
    p += 4;
    if (get32(&p) != AXI_AER2_V1_VERSION) return -1;
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
    if (p != bytes + len || !aer2_valid(receipt)) return -1;
    *out = parsed;
    return 0;
}

void axi_aer2_v1_root(const axi_aer2_v1 *receipt, uint8_t out[32])
{
    uint8_t bytes[sizeof(AXI_AER2_V1_BODY_DOMAIN) - 1 + AXI_AER2_V1_BODY_SIZE];
    if (!out) return;
    memcpy(bytes, AXI_AER2_V1_BODY_DOMAIN, sizeof(AXI_AER2_V1_BODY_DOMAIN) - 1);
    if (axi_aer2_v1_encode(receipt, bytes + sizeof(AXI_AER2_V1_BODY_DOMAIN) - 1) != 0)
        memset(out, 0, 32);
    else axi_sha256(bytes, sizeof bytes, out);
}

static void aer2_signature_message(const uint8_t bytes[AXI_AER2_V1_BODY_SIZE],
                                   uint8_t message[sizeof(AXI_AER2_V1_SIG_DOMAIN) + 32])
{
    memcpy(message, AXI_AER2_V1_SIG_DOMAIN, sizeof(AXI_AER2_V1_SIG_DOMAIN));
    axi_sha256(bytes, AXI_AER2_V1_BODY_SIZE,
               message + sizeof(AXI_AER2_V1_SIG_DOMAIN));
}

int axi_aer2_v1_encode_signed(const axi_aer2_v1 *receipt,
                              const uint8_t seed[32],
                              uint8_t out[AXI_AER2_V1_SIGNED_SIZE])
{
    uint8_t secret[64], message[sizeof(AXI_AER2_V1_SIG_DOMAIN) + 32];
    int rc = -1;
    if (!receipt || !seed || !out
            || axi_aer2_v1_encode(receipt, out) != 0) return -1;
    memcpy(out + AXI_AER2_V1_BODY_SIZE, "AERS", 4);
    out[AXI_AER2_V1_BODY_SIZE + 4] = 0;
    out[AXI_AER2_V1_BODY_SIZE + 5] = 0;
    out[AXI_AER2_V1_BODY_SIZE + 6] = 0;
    out[AXI_AER2_V1_BODY_SIZE + 7] = AXI_AER2_V1_VERSION;
    ed25519_keypair_from_seed(seed, out + AXI_AER2_V1_BODY_SIZE + 8, secret);
    aer2_signature_message(out, message);
    if (ed25519_sign(out + AXI_AER2_V1_BODY_SIZE + 40, message,
                     (uint32_t)sizeof message, secret) == 0)
        rc = 0;
    axi_private_wipe(secret, sizeof secret);
    return rc;
}

int axi_aer2_v1_decode_signed(axi_aer2_v1 *receipt, const uint8_t *bytes,
                              size_t len, const uint8_t trusted_pk[32])
{
    uint8_t message[sizeof(AXI_AER2_V1_SIG_DOMAIN) + 32];
    const uint8_t *pk, *signature;
    if (!receipt || !bytes || !trusted_pk || len != AXI_AER2_V1_SIGNED_SIZE
            || memcmp(bytes + AXI_AER2_V1_BODY_SIZE, "AERS", 4) != 0
            || bytes[AXI_AER2_V1_BODY_SIZE + 4] != 0
            || bytes[AXI_AER2_V1_BODY_SIZE + 5] != 0
            || bytes[AXI_AER2_V1_BODY_SIZE + 6] != 0
            || bytes[AXI_AER2_V1_BODY_SIZE + 7] != AXI_AER2_V1_VERSION)
        return -1;
    pk = bytes + AXI_AER2_V1_BODY_SIZE + 8;
    signature = bytes + AXI_AER2_V1_BODY_SIZE + 40;
    if (memcmp(pk, trusted_pk, 32) != 0) return -1;
    aer2_signature_message(bytes, message);
    if (ed25519_verify(signature, message, (uint32_t)sizeof message, pk) != 0)
        return -1;
    return axi_aer2_v1_decode(receipt, bytes, AXI_AER2_V1_BODY_SIZE);
}

/* ---- Independent verifier: own reader, own validity. Deliberately not
 * shared with the producer/codec above; a verifier that reuses the
 * producer's checks proves nothing about the bytes on the wire. ---- */

typedef struct {
    const uint8_t *p;
    size_t len;
    size_t off;
    int err;
} aer2_reader;

static const uint8_t *v_rd(aer2_reader *r, size_t len)
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

static uint8_t v_rd_u8(aer2_reader *r)
{
    const uint8_t *p = v_rd(r, 1);
    return p ? p[0] : 0;
}

static uint32_t v_rd_u32(aer2_reader *r)
{
    const uint8_t *p = v_rd(r, 4);
    return p ? ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
             | ((uint32_t)p[2] << 8) | (uint32_t)p[3] : 0;
}

static uint64_t v_rd_u64(aer2_reader *r)
{
    uint64_t value = 0;
    const uint8_t *p = v_rd(r, 8);
    size_t i;
    if (!p) return 0;
    for (i = 0; i < 8; i++) value = (value << 8) | p[i];
    return value;
}

static void v_rd_root(aer2_reader *r, uint8_t root[32])
{
    const uint8_t *p = v_rd(r, 32);
    if (p) memcpy(root, p, 32);
}

static int v_root_zero(const uint8_t root[32])
{
    size_t i;
    for (i = 0; i < 32; i++) if (root[i] != 0) return 0;
    return 1;
}

static int v_present_valid(uint8_t present, const uint8_t root[32])
{
    if (present > 1u) {
        return 0;
    }
    return present ? !v_root_zero(root) : v_root_zero(root);
}

static int v_parsed_valid(const axi_aer2_v1 *r)
{
    if (!r || r->decision > AXI_AER2_V1_DECISION_DENY
            || r->attempt > AXI_AER2_V1_ATTEMPT_ATTEMPTED
            || r->outcome > AXI_AER2_V1_OUTCOME_UNKNOWN
            || r->evidence > 1u
            || r->coverage > AXI_AER2_V1_COVERAGE_COMPLETE
            || r->profile < AXI_AER2_V1_PROFILE_DEV
            || r->profile > AXI_AER2_V1_PROFILE_PROD
            || r->opacity < AXI_AER2_V1_OPACITY_CLEAR
            || r->opacity > AXI_AER2_V1_OPACITY_CONFIDENTIAL
            || r->maturity < AXI_AER2_V1_MATURITY_DEV
            || r->maturity > AXI_AER2_V1_MATURITY_ATTESTED)
        return 0;
    if ((r->attempt == AXI_AER2_V1_ATTEMPT_NOT_ATTEMPTED)
            != (r->outcome == AXI_AER2_V1_OUTCOME_NONE))
        return 0;
    if (r->outcome == AXI_AER2_V1_OUTCOME_UNKNOWN
            && r->attempt != AXI_AER2_V1_ATTEMPT_ATTEMPTED)
        return 0;
    if (r->attempt == AXI_AER2_V1_ATTEMPT_NOT_ATTEMPTED) {
        if (r->has_grant_root) {
            return 0;
        }
    } else if (r->outcome != AXI_AER2_V1_OUTCOME_NONE) {
        if (!r->has_grant_root || v_root_zero(r->grant_root)
                || !r->has_policy_root || v_root_zero(r->policy_root)
                || !r->has_artifact_root || v_root_zero(r->artifact_root))
            return 0;
    }
    if (!r->has_policy_root
            && r->decision != AXI_AER2_V1_DECISION_UNPROVEN)
        return 0;
    if (r->coverage == AXI_AER2_V1_COVERAGE_UNKNOWN
            ? r->has_coverage_root != 0
            : r->has_coverage_root == 0)
        return 0;
    if (!r->has_artifact_root || v_root_zero(r->principal_root)
            || v_root_zero(r->action_root) || v_root_zero(r->budget_root))
        return 0;
    return v_present_valid(r->has_policy_root, r->policy_root)
        && v_present_valid(r->has_grant_root, r->grant_root)
        && v_present_valid(r->has_coverage_root, r->coverage_root)
        && v_present_valid(r->has_episode_root, r->episode_root)
        && v_present_valid(r->has_artifact_root, r->artifact_root);
}

int axi_aer2_v1_verify_signed(axi_aer2_v1 *receipt, const uint8_t *bytes,
                              size_t len, const uint8_t trusted_pk[32])
{
    axi_aer2_v1 parsed;
    uint8_t message[sizeof(AXI_AER2_V1_SIG_DOMAIN) + 32];
    aer2_reader r;
    const uint8_t *pk, *signature;
    if (!receipt || !bytes || !trusted_pk || len != AXI_AER2_V1_SIGNED_SIZE
            || memcmp(bytes + AXI_AER2_V1_BODY_SIZE, "AERS", 4) != 0
            || bytes[AXI_AER2_V1_BODY_SIZE + 4] != 0
            || bytes[AXI_AER2_V1_BODY_SIZE + 5] != 0
            || bytes[AXI_AER2_V1_BODY_SIZE + 6] != 0
            || bytes[AXI_AER2_V1_BODY_SIZE + 7] != AXI_AER2_V1_VERSION)
        return -1;
    pk = bytes + AXI_AER2_V1_BODY_SIZE + 8;
    signature = bytes + AXI_AER2_V1_BODY_SIZE + 40;
    if (memcmp(pk, trusted_pk, 32) != 0) return -1;
    memcpy(message, AXI_AER2_V1_SIG_DOMAIN, sizeof(AXI_AER2_V1_SIG_DOMAIN));
    axi_sha256(bytes, AXI_AER2_V1_BODY_SIZE,
               message + sizeof(AXI_AER2_V1_SIG_DOMAIN));
    if (ed25519_verify(signature, message, (uint32_t)sizeof message, pk) != 0)
        return -1;
    r.p = bytes;
    r.len = AXI_AER2_V1_BODY_SIZE;
    r.off = 0;
    r.err = 0;
    {
        const uint8_t *magic = v_rd(&r, 4);
        if (!magic || memcmp(magic, AXI_AER2_V1_MAGIC, 4) != 0) return -1;
    }
    if (v_rd_u32(&r) != AXI_AER2_V1_VERSION) return -1;
    memset(&parsed, 0, sizeof parsed);
    parsed.decision = v_rd_u8(&r);
    parsed.attempt = v_rd_u8(&r);
    parsed.outcome = v_rd_u8(&r);
    parsed.evidence = v_rd_u8(&r);
    parsed.coverage = v_rd_u8(&r);
    parsed.profile = v_rd_u8(&r);
    parsed.opacity = v_rd_u8(&r);
    parsed.maturity = v_rd_u8(&r);
    parsed.has_policy_root = v_rd_u8(&r);
    parsed.has_grant_root = v_rd_u8(&r);
    parsed.has_coverage_root = v_rd_u8(&r);
    parsed.has_episode_root = v_rd_u8(&r);
    parsed.has_artifact_root = v_rd_u8(&r);
    v_rd_root(&r, parsed.principal_root);
    v_rd_root(&r, parsed.artifact_root);
    v_rd_root(&r, parsed.policy_root);
    v_rd_root(&r, parsed.grant_root);
    v_rd_root(&r, parsed.action_root);
    v_rd_root(&r, parsed.coverage_root);
    v_rd_root(&r, parsed.budget_root);
    v_rd_root(&r, parsed.episode_root);
    v_rd_root(&r, parsed.ledger_tip);
    v_rd_root(&r, parsed.journal_tip);
    parsed.fuel_used = v_rd_u64(&r);
    parsed.resources.calls = v_rd_u64(&r);
    parsed.resources.input_bytes = v_rd_u64(&r);
    parsed.resources.output_bytes = v_rd_u64(&r);
    parsed.resources.handles = v_rd_u64(&r);
    parsed.resources.children = v_rd_u64(&r);
    if (r.err || r.off != AXI_AER2_V1_BODY_SIZE
            || !v_parsed_valid(&parsed))
        return -1;
    *receipt = parsed;
    return 0;
}

/* ---- Narrow-profile producer: owner outcomes to terminal evidence. ---- */

int axi_aer2_v1_from_attempt(const axi_local_action_roots_v1 *roots,
                             const uint8_t artifact[32],
                             const uint8_t *grant_root, int has_grant,
                             const axi_local_admission_v1_result *admitted,
                             uint8_t coverage_complete, uint8_t profile,
                             uint8_t decision, uint8_t owner_state,
                             axi_aer2_v1 *out)
{
    uint8_t attempt, outcome;
    if (!out) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    if (!roots || !artifact || root_zero(artifact)
            || root_zero(roots->principal) || root_zero(roots->action)
            || root_zero(roots->budget)
            || (decision != AXI_AER2_V1_DECISION_UNPROVEN
                && root_zero(roots->policy))
            || (has_grant && (!grant_root || root_zero(grant_root)))
            || (!has_grant && grant_root)
            || (has_grant != 0 && has_grant != 1)
            || (profile != AXI_AER2_V1_PROFILE_DEV
                && profile != AXI_AER2_V1_PROFILE_PROD)
            || (coverage_complete != 0 && coverage_complete != 1)
            || (decision != AXI_AER2_V1_DECISION_ALLOW
                && decision != AXI_AER2_V1_DECISION_DENY
                && decision != AXI_AER2_V1_DECISION_UNPROVEN)) {
        return -1;
    }
    /* Owner-state axis to attempt/outcome axis. In-flight attempts carry
     * no terminal evidence; anything outside the owner enum refuses. */
    switch (owner_state) {
    case AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED:
        attempt = AXI_AER2_V1_ATTEMPT_NOT_ATTEMPTED;
        outcome = AXI_AER2_V1_OUTCOME_NONE;
        break;
    case AXI_LOCAL_ATTEMPT_V1_COMMITTED:
        attempt = AXI_AER2_V1_ATTEMPT_ATTEMPTED;
        outcome = AXI_AER2_V1_OUTCOME_COMMITTED;
        break;
    case AXI_LOCAL_ATTEMPT_V1_FAILED:
        attempt = AXI_AER2_V1_ATTEMPT_ATTEMPTED;
        outcome = AXI_AER2_V1_OUTCOME_FAILED;
        break;
    case AXI_LOCAL_ATTEMPT_V1_UNKNOWN:
        attempt = AXI_AER2_V1_ATTEMPT_ATTEMPTED;
        outcome = AXI_AER2_V1_OUTCOME_UNKNOWN;
        break;
    default:
        return -1;
    }
    if (decision == AXI_AER2_V1_DECISION_ALLOW) {
        if (owner_state == AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED) {
            if (has_grant) {
                return -1;
            }
        } else if (!has_grant) {
            return -1;
        }
    } else if (decision == AXI_AER2_V1_DECISION_DENY) {
        /* Refusal before any attempt; no authority may be bound. */
        if (owner_state != AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED || has_grant) {
            return -1;
        }
    } else { /* UNPROVEN */
        if (owner_state != AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED || has_grant) {
            return -1;
        }
    }
    out->decision = decision;
    out->attempt = attempt;
    out->outcome = outcome;
    out->evidence = 1;
    out->profile = profile;
    out->opacity = AXI_AER2_V1_OPACITY_CLEAR;
    out->maturity = (profile == AXI_AER2_V1_PROFILE_PROD)
        ? AXI_AER2_V1_MATURITY_TESTED : AXI_AER2_V1_MATURITY_DEV;
    out->has_policy_root =
        (uint8_t)(decision != AXI_AER2_V1_DECISION_UNPROVEN);
    out->has_grant_root = (uint8_t)(has_grant && attempt ==
        AXI_AER2_V1_ATTEMPT_ATTEMPTED);
    if (out->has_grant_root) {
        memcpy(out->grant_root, grant_root, 32);
    }
    /* Coverage binds the admitted appraisal's context only for admitted
     * PROD with the door bit; anything else stays UNKNOWN with no root.
     * COMPLETE is never emitted by this producer. */
    if (admitted && admitted->admitted
            && admitted->profile == AXI_LOCAL_ADMISSION_V1_PROD
            && profile == AXI_AER2_V1_PROFILE_PROD && coverage_complete) {
        out->coverage = AXI_AER2_V1_COVERAGE_PARTIAL;
        out->has_coverage_root = 1;
        memcpy(out->coverage_root, admitted->context_root, 32);
    } else {
        out->coverage = AXI_AER2_V1_COVERAGE_UNKNOWN;
        out->has_coverage_root = 0;
    }
    out->has_episode_root = 0;
    out->has_artifact_root = 1;
    memcpy(out->principal_root, roots->principal, 32);
    memcpy(out->artifact_root, artifact, 32);
    if (out->has_policy_root) {
        memcpy(out->policy_root, roots->policy, 32);
    }
    memcpy(out->action_root, roots->action, 32);
    memcpy(out->budget_root, roots->budget, 32);
    out->fuel_used = 0;
    memset(&out->resources, 0, sizeof(out->resources));
    return aer2_valid(out) ? 0 : -1;
}
