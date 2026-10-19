#include "axi_time_lease_v1.h"

#include "axi_hash.h"

#include <string.h>

typedef struct {
    const uint8_t *p;
    size_t len;
    size_t off;
    int err;
} tl_reader;

static const uint8_t *rd(tl_reader *r, size_t len)
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

static uint8_t rd_u8(tl_reader *r)
{
    const uint8_t *p = rd(r, 1);
    return p ? p[0] : 0;
}

static uint32_t rd_u32(tl_reader *r)
{
    const uint8_t *p = rd(r, 4);
    return p ? ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
             | ((uint32_t)p[2] << 8) | p[3] : 0;
}

static uint64_t rd_u64(tl_reader *r)
{
    const uint8_t *p = rd(r, 8);
    uint64_t value = 0;
    size_t i;
    if (!p) return 0;
    for (i = 0; i < 8; i++) value = (value << 8) | p[i];
    return value;
}

static void rd_bytes(tl_reader *r, void *out, size_t len)
{
    const uint8_t *p = rd(r, len);
    if (p) memcpy(out, p, len);
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

static int all_zero(const void *bytes, size_t len)
{
    const uint8_t *p = bytes;
    size_t i;
    for (i = 0; i < len; i++) if (p[i] != 0) return 0;
    return 1;
}

static int root_zero(const uint8_t root[32])
{
    return all_zero(root, 32);
}

static int cap_valid(const char cap[AXI_LEASE1_CAPNAME])
{
    const char *nul = memchr(cap, '\0', AXI_LEASE1_CAPNAME);
    size_t i;
    if (!nul || nul == cap) return 0;
    for (i = (size_t)(nul - cap) + 1; i < AXI_LEASE1_CAPNAME; i++)
        if (cap[i] != '\0') return 0;
    return 1;
}

static int time_valid(const axi_time1 *t)
{
    if (!t || root_zero(t->domain_id) || root_zero(t->source_id)
            || root_zero(t->trust_snapshot_root) || root_zero(t->attestation_root)
            || t->boot_present > 1 || (!t->boot_present && !root_zero(t->boot_id))
            || (t->boot_present && root_zero(t->boot_id))
            || t->sequence == 0 || t->epoch_lower >= t->epoch_upper)
        return 0;
    if (t->epoch_lower < t->uncertainty_before) return 0;
    if (UINT64_MAX - t->epoch_upper < t->uncertainty_after) return 0;
    return 1;
}

static int scope_kind_valid(uint8_t kind)
{
    return kind == AXI_LEASE1_SCOPE_EXACT_OBJECT
        || kind == AXI_LEASE1_SCOPE_ROOTED_SUBTREE
        || kind == AXI_LEASE1_SCOPE_NAMESPACE_SLOT
        || kind == AXI_LEASE1_SCOPE_RENAME_PAIR;
}

static int lease_valid(const axi_lease1 *l)
{
    size_t i;
    if (!l || root_zero(l->principal_root) || root_zero(l->issuer_root)
            || root_zero(l->trust_snapshot_root) || root_zero(l->lease_nonce)
            || root_zero(l->time_domain_id) || l->boot_bound > 1
            || (!l->boot_bound && !root_zero(l->boot_id))
            || (l->boot_bound && root_zero(l->boot_id))
            || !scope_kind_valid(l->scope_kind) || root_zero(l->scope_root)
            || l->not_before >= l->not_after || root_zero(l->revocation_root)
            || l->ncap == 0 || l->ncap > AXI_LEASE1_MAX_CAPS
            || l->nquota == 0 || l->nquota > AXI_LEASE1_MAX_QUOTAS)
        return 0;
    for (i = 0; i < l->ncap; i++) {
        if (!cap_valid(l->caps[i])) return 0;
        if (i && strcmp(l->caps[i - 1], l->caps[i]) >= 0) return 0;
    }
    for (; i < AXI_LEASE1_MAX_CAPS; i++)
        if (!all_zero(l->caps[i], AXI_LEASE1_CAPNAME)) return 0;
    for (i = 0; i < l->nquota; i++) {
        if (root_zero(l->quota_unit[i]) || l->quota_limit[i] == 0) return 0;
        if (i && memcmp(l->quota_unit[i - 1], l->quota_unit[i], 32) >= 0) return 0;
    }
    for (; i < AXI_LEASE1_MAX_QUOTAS; i++)
        if (!root_zero(l->quota_unit[i]) || l->quota_limit[i] != 0) return 0;
    return 1;
}

int axi_time1_encode(const axi_time1 *t, uint8_t out[AXI_TIME1_BODY_SIZE])
{
    uint8_t *p = out;
    if (!out || !time_valid(t)) return -1;
    memcpy(p, AXI_TIME1_MAGIC, 4); p += 4;
    p = wr_u32(p, AXI_TIME1_VERSION);
    memcpy(p, t->domain_id, 32); p += 32;
    memcpy(p, t->source_id, 32); p += 32;
    memcpy(p, t->trust_snapshot_root, 32); p += 32;
    *p++ = t->boot_present;
    memcpy(p, t->boot_id, 32); p += 32;
    p = wr_u64(p, t->sequence);
    p = wr_u64(p, t->monotonic_sample);
    p = wr_u64(p, t->epoch_lower);
    p = wr_u64(p, t->epoch_upper);
    p = wr_u64(p, t->uncertainty_before);
    p = wr_u64(p, t->uncertainty_after);
    memcpy(p, t->predecessor_root, 32); p += 32;
    memcpy(p, t->high_water_root, 32); p += 32;
    memcpy(p, t->attestation_root, 32); p += 32;
    return p == out + AXI_TIME1_BODY_SIZE ? 0 : -1;
}

int axi_time1_decode(axi_time1 *t, const uint8_t *bytes, size_t len)
{
    tl_reader r = {bytes, len, 0, 0};
    if (!t || !bytes || len != AXI_TIME1_BODY_SIZE
            || memcmp(rd(&r, 4), AXI_TIME1_MAGIC, 4) != 0
            || rd_u32(&r) != AXI_TIME1_VERSION)
        return -1;
    memset(t, 0, sizeof *t);
    rd_bytes(&r, t->domain_id, 32);
    rd_bytes(&r, t->source_id, 32);
    rd_bytes(&r, t->trust_snapshot_root, 32);
    t->boot_present = rd_u8(&r);
    rd_bytes(&r, t->boot_id, 32);
    t->sequence = rd_u64(&r);
    t->monotonic_sample = rd_u64(&r);
    t->epoch_lower = rd_u64(&r);
    t->epoch_upper = rd_u64(&r);
    t->uncertainty_before = rd_u64(&r);
    t->uncertainty_after = rd_u64(&r);
    rd_bytes(&r, t->predecessor_root, 32);
    rd_bytes(&r, t->high_water_root, 32);
    rd_bytes(&r, t->attestation_root, 32);
    return !r.err && r.off == len && time_valid(t) ? 0 : -1;
}

void axi_time1_root(const axi_time1 *t, uint8_t out[32])
{
    uint8_t bytes[sizeof(AXI_TIME1_BODY_DOMAIN) + AXI_TIME1_BODY_SIZE];
    if (!out) return;
    memset(out, 0, 32);
    if (!t) return;
    memcpy(bytes, AXI_TIME1_BODY_DOMAIN, sizeof(AXI_TIME1_BODY_DOMAIN));
    if (axi_time1_encode(t, bytes + sizeof(AXI_TIME1_BODY_DOMAIN)) != 0) return;
    axi_sha256(bytes, sizeof bytes, out);
}

int axi_time1_verify_successor(const axi_time1 *prev, const axi_time1 *next)
{
    uint8_t prev_root[32];
    if (!time_valid(prev) || !time_valid(next)
            || memcmp(prev->domain_id, next->domain_id, 32) != 0
            || memcmp(prev->source_id, next->source_id, 32) != 0
            || memcmp(prev->trust_snapshot_root, next->trust_snapshot_root, 32) != 0
            || prev->boot_present != next->boot_present
            || memcmp(prev->boot_id, next->boot_id, 32) != 0
            || next->sequence <= prev->sequence
            || next->monotonic_sample < prev->monotonic_sample)
        return -1;
    axi_time1_root(prev, prev_root);
    return memcmp(next->predecessor_root, prev_root, 32) == 0
        && memcmp(next->high_water_root, prev_root, 32) == 0 ? 0 : -1;
}

int axi_lease1_encode(const axi_lease1 *l, uint8_t out[AXI_LEASE1_BODY_SIZE])
{
    uint8_t *p = out;
    size_t i;
    if (!out || !lease_valid(l)) return -1;
    memcpy(p, AXI_LEASE1_MAGIC, 4); p += 4;
    p = wr_u32(p, AXI_LEASE1_VERSION);
    memcpy(p, l->principal_root, 32); p += 32;
    memcpy(p, l->issuer_root, 32); p += 32;
    memcpy(p, l->trust_snapshot_root, 32); p += 32;
    memcpy(p, l->lease_nonce, 32); p += 32;
    memcpy(p, l->time_domain_id, 32); p += 32;
    *p++ = l->boot_bound;
    memcpy(p, l->boot_id, 32); p += 32;
    *p++ = l->scope_kind;
    memcpy(p, l->scope_root, 32); p += 32;
    p = wr_u64(p, l->not_before);
    p = wr_u64(p, l->not_after);
    memcpy(p, l->revocation_root, 32); p += 32;
    memcpy(p, l->parent_root, 32); p += 32;
    *p++ = l->ncap;
    for (i = 0; i < AXI_LEASE1_MAX_CAPS; i++) {
        memcpy(p, l->caps[i], AXI_LEASE1_CAPNAME);
        p += AXI_LEASE1_CAPNAME;
    }
    *p++ = l->nquota;
    for (i = 0; i < AXI_LEASE1_MAX_QUOTAS; i++) {
        memcpy(p, l->quota_unit[i], 32); p += 32;
        p = wr_u64(p, l->quota_limit[i]);
    }
    return p == out + AXI_LEASE1_BODY_SIZE ? 0 : -1;
}

int axi_lease1_decode(axi_lease1 *l, const uint8_t *bytes, size_t len)
{
    tl_reader r = {bytes, len, 0, 0};
    size_t i;
    if (!l || !bytes || len != AXI_LEASE1_BODY_SIZE
            || memcmp(rd(&r, 4), AXI_LEASE1_MAGIC, 4) != 0
            || rd_u32(&r) != AXI_LEASE1_VERSION)
        return -1;
    memset(l, 0, sizeof *l);
    rd_bytes(&r, l->principal_root, 32);
    rd_bytes(&r, l->issuer_root, 32);
    rd_bytes(&r, l->trust_snapshot_root, 32);
    rd_bytes(&r, l->lease_nonce, 32);
    rd_bytes(&r, l->time_domain_id, 32);
    l->boot_bound = rd_u8(&r);
    rd_bytes(&r, l->boot_id, 32);
    l->scope_kind = rd_u8(&r);
    rd_bytes(&r, l->scope_root, 32);
    l->not_before = rd_u64(&r);
    l->not_after = rd_u64(&r);
    rd_bytes(&r, l->revocation_root, 32);
    rd_bytes(&r, l->parent_root, 32);
    l->ncap = rd_u8(&r);
    for (i = 0; i < AXI_LEASE1_MAX_CAPS; i++)
        rd_bytes(&r, l->caps[i], AXI_LEASE1_CAPNAME);
    l->nquota = rd_u8(&r);
    for (i = 0; i < AXI_LEASE1_MAX_QUOTAS; i++) {
        rd_bytes(&r, l->quota_unit[i], 32);
        l->quota_limit[i] = rd_u64(&r);
    }
    return !r.err && r.off == len && lease_valid(l) ? 0 : -1;
}

void axi_lease1_root(const axi_lease1 *l, uint8_t out[32])
{
    uint8_t bytes[sizeof(AXI_LEASE1_BODY_DOMAIN) + AXI_LEASE1_BODY_SIZE];
    if (!out) return;
    memset(out, 0, 32);
    if (!l) return;
    memcpy(bytes, AXI_LEASE1_BODY_DOMAIN, sizeof(AXI_LEASE1_BODY_DOMAIN));
    if (axi_lease1_encode(l, bytes + sizeof(AXI_LEASE1_BODY_DOMAIN)) != 0) return;
    axi_sha256(bytes, sizeof bytes, out);
}

static int has_cap(const axi_lease1 *l, const char *capability)
{
    size_t i;
    if (!capability) return 0;
    for (i = 0; i < l->ncap; i++)
        if (strcmp(l->caps[i], capability) == 0) return 1;
    return 0;
}

int axi_lease1_authorizes(const axi_lease1 *l, const axi_time1 *t,
                          const uint8_t principal_root[32],
                          const char *capability,
                          const uint8_t exact_scope_root[32])
{
    uint64_t lower, upper;
    if (!lease_valid(l) || !time_valid(t) || !principal_root || !exact_scope_root
            || memcmp(l->principal_root, principal_root, 32) != 0
            || memcmp(l->time_domain_id, t->domain_id, 32) != 0
            || memcmp(l->trust_snapshot_root, t->trust_snapshot_root, 32) != 0
            || (l->boot_bound && (!t->boot_present
                                  || memcmp(l->boot_id, t->boot_id, 32) != 0))
            || l->scope_kind != AXI_LEASE1_SCOPE_EXACT_OBJECT
            || memcmp(l->scope_root, exact_scope_root, 32) != 0
            || !has_cap(l, capability))
        return -1;
    lower = t->epoch_lower - t->uncertainty_before;
    upper = t->epoch_upper + t->uncertainty_after;
    return lower >= l->not_before && upper <= l->not_after ? 0 : -1;
}

int axi_lease1_state_init(axi_lease1_state *state, const axi_lease1 *lease)
{
    size_t i;
    if (!state || !lease_valid(lease)) return -1;
    memset(state, 0, sizeof *state);
    axi_lease1_root(lease, state->lease_root);
    state->nquota = lease->nquota;
    for (i = 0; i < lease->nquota; i++) {
        memcpy(state->quota_unit[i], lease->quota_unit[i], 32);
        state->quota_limit[i] = lease->quota_limit[i];
    }
    return 0;
}

int axi_lease1_reserve(axi_lease1_state *state, const uint8_t unit[32],
                       uint64_t amount)
{
    size_t i;
    if (!state || !unit || root_zero(state->lease_root) || amount == 0
            || state->nquota == 0 || state->nquota > AXI_LEASE1_MAX_QUOTAS)
        return -1;
    /* State is caller-owned and may have been restored or modified since
     * init. Validate the entire bounded image before changing any counter. */
    for (i = 0; i < state->nquota; i++) {
        if (root_zero(state->quota_unit[i]) || state->quota_limit[i] == 0
                || state->quota_reserved[i] > state->quota_limit[i]
                || (i && memcmp(state->quota_unit[i - 1],
                                state->quota_unit[i], 32) >= 0))
            return -1;
    }
    for (; i < AXI_LEASE1_MAX_QUOTAS; i++) {
        if (!root_zero(state->quota_unit[i]) || state->quota_limit[i] != 0
                || state->quota_reserved[i] != 0)
            return -1;
    }
    for (i = 0; i < state->nquota; i++) {
        uint64_t left;
        if (memcmp(state->quota_unit[i], unit, 32) != 0) continue;
        if (state->quota_reserved[i] > state->quota_limit[i]) return -1;
        left = state->quota_limit[i] - state->quota_reserved[i];
        if (amount > left) return -1;
        state->quota_reserved[i] += amount;
        return 0;
    }
    return -1;
}
