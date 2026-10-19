#include "axi_trust_v1.h"

#include "axi_hash.h"
#include "ed25519.h"

#include <string.h>

typedef struct {
    uint8_t id[32];
} trust_identity;

typedef struct {
    uint8_t key_id[32];
    uint8_t identity_id[32];
    uint8_t purpose;
    uint8_t pk[32];
    uint64_t valid_from;
    uint64_t valid_until;
} trust_key;

typedef struct {
    uint8_t identity_id[32];
    uint8_t role;
    uint8_t scope_id[32];
    uint64_t valid_from;
    uint64_t valid_until;
} trust_grant;

typedef struct {
    uint8_t policy_id[32];
    uint8_t role;
    uint8_t scope_id[32];
    uint8_t threshold;
    uint8_t forbid_subject_identity;
} trust_policy;

typedef struct {
    uint8_t key_id[32];
    uint64_t revoked_at;
} trust_revocation;

typedef struct {
    uint8_t org_id[32];
    uint64_t sequence;
    uint8_t has_predecessor;
    uint8_t predecessor_root[32];
    uint8_t time_domain[32];
    uint64_t valid_from;
    uint64_t valid_until;
    size_t nidentities;
    size_t nkeys;
    size_t ngrants;
    size_t npolicies;
    size_t nrevocations;
    trust_identity identities[AXI_TRUST_V1_MAX_IDENTITIES];
    trust_key keys[AXI_TRUST_V1_MAX_KEYS];
    trust_grant grants[AXI_TRUST_V1_MAX_GRANTS];
    trust_policy policies[AXI_TRUST_V1_MAX_POLICIES];
    trust_revocation revocations[AXI_TRUST_V1_MAX_REVOCATIONS];
} trust_snapshot;

typedef struct {
    const uint8_t *p;
    size_t len;
    size_t off;
    int err;
} trust_reader;

static const uint8_t *rd(trust_reader *r, size_t len)
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

static uint8_t rd_u8(trust_reader *r)
{
    const uint8_t *p = rd(r, 1);
    return p ? p[0] : 0;
}

static uint16_t rd_u16(trust_reader *r)
{
    const uint8_t *p = rd(r, 2);
    return p ? (uint16_t)(((uint16_t)p[0] << 8) | p[1]) : 0;
}

static uint32_t rd_u32(trust_reader *r)
{
    const uint8_t *p = rd(r, 4);
    return p ? ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
             | ((uint32_t)p[2] << 8) | p[3] : 0;
}

static uint64_t rd_u64(trust_reader *r)
{
    uint64_t value = 0;
    const uint8_t *p = rd(r, 8);
    size_t i;
    if (!p) return 0;
    for (i = 0; i < 8; i++) value = (value << 8) | p[i];
    return value;
}

static void rd_bytes(trust_reader *r, uint8_t *out, size_t len)
{
    const uint8_t *p = rd(r, len);
    if (p) memcpy(out, p, len);
}

static int root_zero(const uint8_t root[32])
{
    size_t i;
    for (i = 0; i < 32; i++) if (root[i] != 0) return 0;
    return 1;
}

static int in_interval(uint64_t t, uint64_t from, uint64_t until)
{
    return from < until && from <= t && t < until;
}

static int purpose_valid(uint8_t purpose)
{
    return purpose == AXI_TRUST_V1_PURPOSE_PRODUCE
        || purpose == AXI_TRUST_V1_PURPOSE_APPROVE
        || purpose == AXI_TRUST_V1_PURPOSE_ATTEST;
}

static int role_valid(uint8_t role)
{
    return role == AXI_TRUST_V1_ROLE_AUTHOR
        || role == AXI_TRUST_V1_ROLE_APPROVER
        || role == AXI_TRUST_V1_ROLE_AUDITOR;
}

static int identity_exists(const trust_snapshot *s, const uint8_t id[32])
{
    size_t i;
    for (i = 0; i < s->nidentities; i++)
        if (memcmp(s->identities[i].id, id, 32) == 0) return 1;
    return 0;
}

static int grant_cmp(const trust_grant *a, const trust_grant *b)
{
    int c = memcmp(a->identity_id, b->identity_id, 32);
    if (c) return c;
    if (a->role != b->role) return a->role < b->role ? -1 : 1;
    return memcmp(a->scope_id, b->scope_id, 32);
}

static int parsed_key_exists(const trust_snapshot *s, const uint8_t key_id[32])
{
    size_t i;
    for (i = 0; i < s->nkeys; i++)
        if (memcmp(s->keys[i].key_id, key_id, 32) == 0) return 1;
    return 0;
}

static int parse_snapshot(trust_snapshot *s, const uint8_t *bytes, size_t len)
{
    trust_reader r = {bytes, len, 0, 0};
    uint16_t ni, nk, ng, np, nr;
    size_t i;

    if (!s || !bytes || len == 0 || memcmp(rd(&r, 4), AXI_TRUST_V1_MAGIC, 4) != 0
            || rd_u32(&r) != AXI_TRUST_V1_VERSION)
        return -1;
    memset(s, 0, sizeof *s);
    rd_bytes(&r, s->org_id, 32);
    s->sequence = rd_u64(&r);
    s->has_predecessor = rd_u8(&r);
    rd_bytes(&r, s->predecessor_root, 32);
    rd_bytes(&r, s->time_domain, 32);
    s->valid_from = rd_u64(&r);
    s->valid_until = rd_u64(&r);
    ni = rd_u16(&r); nk = rd_u16(&r); ng = rd_u16(&r);
    np = rd_u16(&r); nr = rd_u16(&r);
    if (r.err || s->has_predecessor > 1 || (!s->has_predecessor && !root_zero(s->predecessor_root))
            || root_zero(s->org_id) || root_zero(s->time_domain)
            || s->valid_from >= s->valid_until
            || ni == 0 || ni > AXI_TRUST_V1_MAX_IDENTITIES
            || nk == 0 || nk > AXI_TRUST_V1_MAX_KEYS
            || ng > AXI_TRUST_V1_MAX_GRANTS
            || np == 0 || np > AXI_TRUST_V1_MAX_POLICIES
            || nr > AXI_TRUST_V1_MAX_REVOCATIONS)
        return -1;
    s->nidentities = ni; s->nkeys = nk; s->ngrants = ng;
    s->npolicies = np; s->nrevocations = nr;
    for (i = 0; i < s->nidentities; i++) {
        rd_bytes(&r, s->identities[i].id, 32);
        if (root_zero(s->identities[i].id)
                || (i && memcmp(s->identities[i - 1].id, s->identities[i].id, 32) >= 0))
            return -1;
    }
    for (i = 0; i < s->nkeys; i++) {
        rd_bytes(&r, s->keys[i].key_id, 32);
        rd_bytes(&r, s->keys[i].identity_id, 32);
        s->keys[i].purpose = rd_u8(&r);
        rd_bytes(&r, s->keys[i].pk, 32);
        s->keys[i].valid_from = rd_u64(&r);
        s->keys[i].valid_until = rd_u64(&r);
        if (root_zero(s->keys[i].key_id) || root_zero(s->keys[i].pk)
                || !purpose_valid(s->keys[i].purpose)
                || !identity_exists(s, s->keys[i].identity_id)
                || s->keys[i].valid_from >= s->keys[i].valid_until
                || (i && memcmp(s->keys[i - 1].key_id, s->keys[i].key_id, 32) >= 0))
            return -1;
    }
    for (i = 0; i < s->ngrants; i++) {
        rd_bytes(&r, s->grants[i].identity_id, 32);
        s->grants[i].role = rd_u8(&r);
        rd_bytes(&r, s->grants[i].scope_id, 32);
        s->grants[i].valid_from = rd_u64(&r);
        s->grants[i].valid_until = rd_u64(&r);
        if (!identity_exists(s, s->grants[i].identity_id) || !role_valid(s->grants[i].role)
                || root_zero(s->grants[i].scope_id)
                || s->grants[i].valid_from >= s->grants[i].valid_until)
            return -1;
        if (i && grant_cmp(&s->grants[i - 1], &s->grants[i]) >= 0)
            return -1;
    }
    for (i = 0; i < s->npolicies; i++) {
        rd_bytes(&r, s->policies[i].policy_id, 32);
        s->policies[i].role = rd_u8(&r);
        rd_bytes(&r, s->policies[i].scope_id, 32);
        s->policies[i].threshold = rd_u8(&r);
        s->policies[i].forbid_subject_identity = rd_u8(&r);
        if (root_zero(s->policies[i].policy_id) || !role_valid(s->policies[i].role)
                || root_zero(s->policies[i].scope_id)
                || s->policies[i].threshold == 0
                || s->policies[i].threshold > AXI_TRUST_V1_MAX_APPROVALS
                || s->policies[i].forbid_subject_identity > 1
                || (i && memcmp(s->policies[i - 1].policy_id, s->policies[i].policy_id, 32) >= 0))
            return -1;
    }
    for (i = 0; i < s->nrevocations; i++) {
        rd_bytes(&r, s->revocations[i].key_id, 32);
        s->revocations[i].revoked_at = rd_u64(&r);
        if (root_zero(s->revocations[i].key_id)
                || !parsed_key_exists(s, s->revocations[i].key_id)
                || (i && memcmp(s->revocations[i - 1].key_id, s->revocations[i].key_id, 32) >= 0))
            return -1;
    }
    return !r.err && r.off == len ? 0 : -1;
}

static const trust_key *find_key(const trust_snapshot *s, const uint8_t key_id[32])
{
    size_t i;
    for (i = 0; i < s->nkeys; i++)
        if (memcmp(s->keys[i].key_id, key_id, 32) == 0) return &s->keys[i];
    return NULL;
}

static const trust_policy *find_policy(const trust_snapshot *s, const uint8_t policy_id[32])
{
    size_t i;
    for (i = 0; i < s->npolicies; i++)
        if (memcmp(s->policies[i].policy_id, policy_id, 32) == 0) return &s->policies[i];
    return NULL;
}

static int key_revoked(const trust_snapshot *s, const uint8_t key_id[32], uint64_t t)
{
    size_t i;
    for (i = 0; i < s->nrevocations; i++)
        if (memcmp(s->revocations[i].key_id, key_id, 32) == 0
                && s->revocations[i].revoked_at <= t)
            return 1;
    return 0;
}

static int identity_has_grant(const trust_snapshot *s, const uint8_t identity_id[32],
                              uint8_t role, const uint8_t scope_id[32], uint64_t t)
{
    size_t i;
    for (i = 0; i < s->ngrants; i++)
        if (s->grants[i].role == role
                && memcmp(s->grants[i].identity_id, identity_id, 32) == 0
                && memcmp(s->grants[i].scope_id, scope_id, 32) == 0
                && in_interval(t, s->grants[i].valid_from, s->grants[i].valid_until))
            return 1;
    return 0;
}

static int identity_counted(const uint8_t counted[][32], size_t n, const uint8_t id[32])
{
    size_t i;
    for (i = 0; i < n; i++) if (memcmp(counted[i], id, 32) == 0) return 1;
    return 0;
}

int axi_trust_v1_snapshot_root(const uint8_t *snapshot, size_t len, uint8_t out[32])
{
    trust_snapshot parsed;
    if (!out || parse_snapshot(&parsed, snapshot, len) != 0) return -1;
    axi_sha256(snapshot, len, out);
    return 0;
}

int axi_trust_v1_check_transition(const uint8_t *previous, size_t previous_len,
                                  const uint8_t *next, size_t next_len)
{
    trust_snapshot prev, cur;
    uint8_t prev_root[32];
    size_t i, j;
    if (parse_snapshot(&prev, previous, previous_len) != 0
            || parse_snapshot(&cur, next, next_len) != 0)
        return -1;
    axi_sha256(previous, previous_len, prev_root);
    if (!cur.has_predecessor || memcmp(cur.predecessor_root, prev_root, 32) != 0
            || cur.sequence != prev.sequence + 1)
        return -1;
    for (i = 0; i < prev.nrevocations; i++) {
        int found = 0;
        for (j = 0; j < cur.nrevocations; j++) {
            if (memcmp(prev.revocations[i].key_id, cur.revocations[j].key_id, 32) == 0) {
                if (cur.revocations[j].revoked_at > prev.revocations[i].revoked_at)
                    return -1;
                found = 1;
            }
        }
        if (!found) return -1;
    }
    return 0;
}

void axi_trust_v1_approval_message(const uint8_t snapshot_root[32],
                                   const axi_trust_v1_appraisal_request *req,
                                   uint8_t out[AXI_TRUST_V1_APPROVAL_MSG_SIZE])
{
    size_t off = 0;
    memset(out, 0, AXI_TRUST_V1_APPROVAL_MSG_SIZE);
    if (!snapshot_root || !req) return;
    memcpy(out + off, AXI_TRUST_V1_APPROVAL_DOMAIN, sizeof(AXI_TRUST_V1_APPROVAL_DOMAIN));
    off += sizeof(AXI_TRUST_V1_APPROVAL_DOMAIN);
    memcpy(out + off, snapshot_root, 32); off += 32;
    memcpy(out + off, req->policy_id, 32); off += 32;
    memcpy(out + off, req->scope_id, 32); off += 32;
    out[off++] = req->subject_kind;
    memcpy(out + off, req->subject_digest, 32); off += 32;
    out[off++] = req->has_subject_identity ? 1u : 0u;
    if (req->has_subject_identity) memcpy(out + off, req->subject_identity_id, 32);
}

int axi_trust_v1_appraise(const uint8_t *snapshot, size_t len,
                          const axi_trust_v1_appraisal_request *req,
                          axi_trust_v1_appraisal *out)
{
    trust_snapshot s;
    const trust_policy *policy;
    uint8_t message[AXI_TRUST_V1_APPROVAL_MSG_SIZE];
    uint8_t counted[AXI_TRUST_V1_MAX_APPROVALS][32];
    size_t i, ncounted = 0;
    int saw_valid_sig = 0;

    if (!out || !req || req->approval_count > AXI_TRUST_V1_MAX_APPROVALS
            || (req->approval_count && !req->approvals))
        return -1;
    memset(out, 0, sizeof *out);
    if (parse_snapshot(&s, snapshot, len) != 0) return -1;
    axi_sha256(snapshot, len, out->snapshot_root);
    out->snapshot_sequence = s.sequence;
    out->snapshot_valid_at_supplied_time =
        (uint8_t)in_interval(req->evaluation_time, s.valid_from, s.valid_until);
    policy = find_policy(&s, req->policy_id);
    out->policy_found = policy ? 1u : 0u;
    if (!policy || !out->snapshot_valid_at_supplied_time
            || memcmp(policy->scope_id, req->scope_id, 32) != 0)
        return 0;
    axi_trust_v1_approval_message(out->snapshot_root, req, message);
    for (i = 0; i < req->approval_count; i++) {
        const trust_key *key = find_key(&s, req->approvals[i].key_id);
        if (!key || key->purpose != AXI_TRUST_V1_PURPOSE_APPROVE
                || !in_interval(req->evaluation_time, key->valid_from, key->valid_until)
                || key_revoked(&s, key->key_id, req->evaluation_time)
                || ed25519_verify(req->approvals[i].sig, message,
                                  (uint32_t)sizeof message, key->pk) != 0)
            continue;
        saw_valid_sig = 1;
        if (!identity_has_grant(&s, key->identity_id, policy->role,
                                policy->scope_id, req->evaluation_time))
            continue;
        if (policy->forbid_subject_identity && req->has_subject_identity
                && memcmp(key->identity_id, req->subject_identity_id, 32) == 0)
            continue;
        if (!identity_counted(counted, ncounted, key->identity_id)) {
            memcpy(counted[ncounted++], key->identity_id, 32);
            if (ncounted >= policy->threshold) break;
        }
    }
    out->signature_valid = saw_valid_sig ? 1u : 0u;
    out->counted_identities = (uint8_t)ncounted;
    out->quorum = ncounted >= policy->threshold ? 1u : 0u;
    out->authorization = out->quorum;
    return 0;
}
