#include "axi_delegation_v1.h"

#include "axi_hash.h"
#include "ed25519.h"

#include <string.h>

typedef struct {
    const uint8_t *p;
    size_t len;
    size_t off;
    int err;
} dlg_reader;

static const uint8_t *rd(dlg_reader *r, size_t len)
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

static uint8_t rd_u8(dlg_reader *r)
{
    const uint8_t *p = rd(r, 1);
    return p ? p[0] : 0;
}

static uint32_t rd_u32(dlg_reader *r)
{
    const uint8_t *p = rd(r, 4);
    return p ? ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
             | ((uint32_t)p[2] << 8) | p[3] : 0;
}

static uint64_t rd_u64(dlg_reader *r)
{
    const uint8_t *p = rd(r, 8);
    uint64_t value = 0;
    size_t i;
    if (!p) return 0;
    for (i = 0; i < 8; i++) value = (value << 8) | p[i];
    return value;
}

static void rd_bytes(dlg_reader *r, void *out, size_t len)
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

static int root_zero(const uint8_t root[32])
{
    size_t i;
    for (i = 0; i < 32; i++) if (root[i] != 0) return 0;
    return 1;
}

static int all_zero(const void *bytes, size_t len)
{
    const uint8_t *p = bytes;
    size_t i;
    for (i = 0; i < len; i++) if (p[i] != 0) return 0;
    return 1;
}

static int cap_valid(const char cap[AXI_DELEGATION_V1_CAPNAME])
{
    const char *nul = memchr(cap, '\0', AXI_DELEGATION_V1_CAPNAME);
    size_t i;
    if (!nul || nul == cap) return 0;
    for (i = (size_t)(nul - cap) + 1; i < AXI_DELEGATION_V1_CAPNAME; i++)
        if (cap[i] != '\0') return 0;
    return 1;
}

static int delegation_valid(const axi_delegation_v1 *d)
{
    size_t i;
    if (!d || (d->parent_kind != AXI_DELEGATION_V1_PARENT_AG1
                && d->parent_kind != AXI_DELEGATION_V1_PARENT_DELEGATION)
            || root_zero(d->parent_root) || root_zero(d->delegator_root)
            || root_zero(d->delegatee_root) || root_zero(d->trust_snapshot_root)
            || root_zero(d->issuer_key_id) || root_zero(d->branch_nonce)
            || d->depth == 0 || d->depth > AXI_DELEGATION_V1_MAX_DEPTH
            || d->remaining_depth > AXI_DELEGATION_V1_MAX_DEPTH
            || d->not_before >= d->not_after || d->ncap == 0
            || d->ncap > AXI_DELEGATION_V1_MAX_CAPS)
        return 0;
    for (i = 0; i < d->ncap; i++) {
        if (!cap_valid(d->caps[i])) return 0;
        if (i && strcmp(d->caps[i - 1], d->caps[i]) >= 0) return 0;
    }
    for (; i < AXI_DELEGATION_V1_MAX_CAPS; i++)
        if (!all_zero(d->caps[i], AXI_DELEGATION_V1_CAPNAME)) return 0;
    return 1;
}

static int authority_valid(const axi_delegation_v1_authority *a)
{
    size_t i;
    if (!a || root_zero(a->root) || root_zero(a->principal_root)
            || root_zero(a->trust_snapshot_root)
            || a->depth > AXI_DELEGATION_V1_MAX_DEPTH
            || a->remaining_depth > AXI_DELEGATION_V1_MAX_DEPTH
            || a->not_before >= a->not_after || a->ncap == 0
            || a->ncap > AXI_DELEGATION_V1_MAX_CAPS)
        return 0;
    for (i = 0; i < a->ncap; i++) {
        if (!cap_valid(a->caps[i])) return 0;
        if (i && strcmp(a->caps[i - 1], a->caps[i]) >= 0) return 0;
    }
    return 1;
}

int axi_delegation_v1_encode(const axi_delegation_v1 *d,
                             uint8_t out[AXI_DELEGATION_V1_BODY_SIZE])
{
    uint8_t *p = out;
    size_t i;
    if (!out || !delegation_valid(d)) return -1;
    memcpy(p, AXI_DELEGATION_V1_MAGIC, 4); p += 4;
    p = wr_u32(p, AXI_DELEGATION_V1_VERSION);
    *p++ = d->parent_kind;
    memcpy(p, d->parent_root, 32); p += 32;
    memcpy(p, d->delegator_root, 32); p += 32;
    memcpy(p, d->delegatee_root, 32); p += 32;
    memcpy(p, d->trust_snapshot_root, 32); p += 32;
    memcpy(p, d->issuer_key_id, 32); p += 32;
    memcpy(p, d->branch_nonce, 32); p += 32;
    p = wr_u32(p, d->depth);
    p = wr_u32(p, d->remaining_depth);
    p = wr_u64(p, d->not_before);
    p = wr_u64(p, d->not_after);
    for (i = 0; i < 6; i++) p = wr_u64(p, d->budget[i]);
    *p++ = d->ncap;
    for (i = 0; i < AXI_DELEGATION_V1_MAX_CAPS; i++) {
        memcpy(p, d->caps[i], AXI_DELEGATION_V1_CAPNAME);
        p += AXI_DELEGATION_V1_CAPNAME;
    }
    return p == out + AXI_DELEGATION_V1_BODY_SIZE ? 0 : -1;
}

int axi_delegation_v1_decode(axi_delegation_v1 *d,
                             const uint8_t *bytes, size_t len)
{
    dlg_reader r = {bytes, len, 0, 0};
    size_t i;
    if (!d || !bytes || len != AXI_DELEGATION_V1_BODY_SIZE
            || memcmp(rd(&r, 4), AXI_DELEGATION_V1_MAGIC, 4) != 0
            || rd_u32(&r) != AXI_DELEGATION_V1_VERSION)
        return -1;
    memset(d, 0, sizeof *d);
    d->parent_kind = rd_u8(&r);
    rd_bytes(&r, d->parent_root, 32);
    rd_bytes(&r, d->delegator_root, 32);
    rd_bytes(&r, d->delegatee_root, 32);
    rd_bytes(&r, d->trust_snapshot_root, 32);
    rd_bytes(&r, d->issuer_key_id, 32);
    rd_bytes(&r, d->branch_nonce, 32);
    d->depth = rd_u32(&r);
    d->remaining_depth = rd_u32(&r);
    d->not_before = rd_u64(&r);
    d->not_after = rd_u64(&r);
    for (i = 0; i < 6; i++) d->budget[i] = rd_u64(&r);
    d->ncap = rd_u8(&r);
    for (i = 0; i < AXI_DELEGATION_V1_MAX_CAPS; i++)
        rd_bytes(&r, d->caps[i], AXI_DELEGATION_V1_CAPNAME);
    return !r.err && r.off == len && delegation_valid(d) ? 0 : -1;
}

void axi_delegation_v1_root(const axi_delegation_v1 *d, uint8_t out[32])
{
    uint8_t bytes[sizeof(AXI_DELEGATION_V1_BODY_DOMAIN) + AXI_DELEGATION_V1_BODY_SIZE];
    if (!out) return;
    memset(out, 0, 32);
    if (!d) return;
    memcpy(bytes, AXI_DELEGATION_V1_BODY_DOMAIN, sizeof(AXI_DELEGATION_V1_BODY_DOMAIN));
    if (axi_delegation_v1_encode(d, bytes + sizeof(AXI_DELEGATION_V1_BODY_DOMAIN)) != 0)
        return;
    axi_sha256(bytes, sizeof bytes, out);
}

static void signature_message(const uint8_t body[AXI_DELEGATION_V1_BODY_SIZE],
                              uint8_t out[AXI_DELEGATION_V1_SIG_MSG_SIZE])
{
    memcpy(out, AXI_DELEGATION_V1_SIG_DOMAIN, sizeof(AXI_DELEGATION_V1_SIG_DOMAIN));
    axi_sha256(body, AXI_DELEGATION_V1_BODY_SIZE,
               out + sizeof(AXI_DELEGATION_V1_SIG_DOMAIN));
}

int axi_delegation_v1_encode_signed(const axi_delegation_v1 *d,
                                    const uint8_t seed[32],
                                    uint8_t out[AXI_DELEGATION_V1_SIGNED_SIZE])
{
    uint8_t sk[64], msg[AXI_DELEGATION_V1_SIG_MSG_SIZE];
    if (!d || !seed || !out || axi_delegation_v1_encode(d, out) != 0) return -1;
    memcpy(out + AXI_DELEGATION_V1_BODY_SIZE, "DLGS", 4);
    out[AXI_DELEGATION_V1_BODY_SIZE + 4] = 0;
    out[AXI_DELEGATION_V1_BODY_SIZE + 5] = 0;
    out[AXI_DELEGATION_V1_BODY_SIZE + 6] = 0;
    out[AXI_DELEGATION_V1_BODY_SIZE + 7] = 1;
    ed25519_keypair_from_seed(seed, out + AXI_DELEGATION_V1_BODY_SIZE + 8, sk);
    signature_message(out, msg);
    if (ed25519_sign(out + AXI_DELEGATION_V1_BODY_SIZE + 40, msg, sizeof msg, sk) != 0) {
        memset(sk, 0, sizeof sk);
        return -1;
    }
    memset(sk, 0, sizeof sk);
    return 0;
}

int axi_delegation_v1_decode_signed(axi_delegation_v1 *d,
                                    const uint8_t *bytes, size_t len,
                                    const uint8_t trusted_pk[32])
{
    uint8_t msg[AXI_DELEGATION_V1_SIG_MSG_SIZE];
    const uint8_t *pk, *sig;
    if (!d || !bytes || !trusted_pk || len != AXI_DELEGATION_V1_SIGNED_SIZE
            || memcmp(bytes + AXI_DELEGATION_V1_BODY_SIZE, "DLGS", 4) != 0
            || bytes[AXI_DELEGATION_V1_BODY_SIZE + 4] != 0
            || bytes[AXI_DELEGATION_V1_BODY_SIZE + 5] != 0
            || bytes[AXI_DELEGATION_V1_BODY_SIZE + 6] != 0
            || bytes[AXI_DELEGATION_V1_BODY_SIZE + 7] != 1)
        return -1;
    pk = bytes + AXI_DELEGATION_V1_BODY_SIZE + 8;
    sig = bytes + AXI_DELEGATION_V1_BODY_SIZE + 40;
    if (memcmp(pk, trusted_pk, 32) != 0) return -1;
    signature_message(bytes, msg);
    if (ed25519_verify(sig, msg, sizeof msg, pk) != 0) return -1;
    return axi_delegation_v1_decode(d, bytes, AXI_DELEGATION_V1_BODY_SIZE);
}

static int cap_subset(const axi_delegation_v1 *child,
                      const axi_delegation_v1_authority *parent)
{
    size_t i, j;
    for (i = 0; i < child->ncap; i++) {
        int found = 0;
        for (j = 0; j < parent->ncap; j++) {
            if (strcmp(child->caps[i], parent->caps[j]) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) return 0;
    }
    return 1;
}

int axi_delegation_v1_verify(const axi_delegation_v1 *d,
                             const axi_delegation_v1_authority *parent,
                             axi_delegation_v1_authority *child_out)
{
    axi_delegation_v1_authority child;
    size_t i;
    if (!delegation_valid(d) || !authority_valid(parent)
            || memcmp(d->parent_root, parent->root, 32) != 0
            || memcmp(d->delegator_root, parent->principal_root, 32) != 0
            || memcmp(d->trust_snapshot_root, parent->trust_snapshot_root, 32) != 0
            || d->depth != parent->depth + 1
            || parent->remaining_depth == 0
            || d->remaining_depth >= parent->remaining_depth
            || d->not_before < parent->not_before
            || d->not_after > parent->not_after
            || !cap_subset(d, parent))
        return -1;
    for (i = 0; i < 6; i++) if (d->budget[i] > parent->budget[i]) return -1;
    memset(&child, 0, sizeof child);
    axi_delegation_v1_root(d, child.root);
    memcpy(child.principal_root, d->delegatee_root, 32);
    memcpy(child.trust_snapshot_root, d->trust_snapshot_root, 32);
    child.depth = d->depth;
    child.remaining_depth = d->remaining_depth;
    child.not_before = d->not_before;
    child.not_after = d->not_after;
    for (i = 0; i < 6; i++) child.budget[i] = d->budget[i];
    child.ncap = d->ncap;
    for (i = 0; i < d->ncap; i++)
        memcpy(child.caps[i], d->caps[i], AXI_DELEGATION_V1_CAPNAME);
    if (!authority_valid(&child)) return -1;
    if (child_out) *child_out = child;
    return 0;
}

int axi_delegation_v1_verify_chain(const axi_delegation_v1 *chain, size_t n,
                                   const axi_delegation_v1_authority *root,
                                   axi_delegation_v1_authority *leaf_out)
{
    axi_delegation_v1_authority parent, child;
    size_t i, j;
    if (!chain || n == 0 || n > AXI_DELEGATION_V1_MAX_DEPTH
            || !authority_valid(root))
        return -1;
    parent = *root;
    for (i = 0; i < n; i++) {
        uint8_t expected_kind = i == 0 ? AXI_DELEGATION_V1_PARENT_AG1
                                       : AXI_DELEGATION_V1_PARENT_DELEGATION;
        uint8_t current_root[32];
        if (chain[i].parent_kind != expected_kind
                || axi_delegation_v1_verify(&chain[i], &parent, &child) != 0)
            return -1;
        axi_delegation_v1_root(&chain[i], current_root);
        for (j = 0; j < i; j++) {
            uint8_t prior_root[32];
            axi_delegation_v1_root(&chain[j], prior_root);
            if (memcmp(prior_root, current_root, 32) == 0) return -1;
        }
        parent = child;
    }
    if (leaf_out) *leaf_out = parent;
    return 0;
}
