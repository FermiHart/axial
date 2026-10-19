/* AXI-AG1-CORE-001: canonical codec/context verifier without allocation, POSIX,
 * clock reads or requester crypto. Native consumers compile this same source. */
#include "axi_ag1_v1.h"
#include "axi_ag1_crypto_v1.h"
#ifdef AXI_AG1_FREESTANDING
#include "axi_ag1_target_string.h"
#else
#include <string.h>
#endif

typedef struct { const uint8_t *p; size_t len; size_t off; int err; } ag1_reader;
static const uint8_t *rd(ag1_reader *r, size_t len)
{
    const uint8_t *p;
    if (!r || r->err || r->off > r->len || len > r->len - r->off) {
        if (r) r->err = 1;
        return NULL;
    }
    p = r->p + r->off; r->off += len; return p;
}
static uint32_t rd_u32(ag1_reader *r)
{
    const uint8_t *p = rd(r, 4);
    return p ? ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8) | p[3] : 0;
}
static uint64_t rd_u64(ag1_reader *r)
{
    const uint8_t *p = rd(r, 8);
    uint64_t value = 0;
    size_t i;
    if (!p) return 0;
    for (i = 0; i < 8; ++i) value = (value << 8) | p[i];
    return value;
}
static void rd_root(ag1_reader *r, uint8_t out[32])
{
    const uint8_t *p = rd(r, 32);
    if (p) memcpy(out, p, 32);
}
static int root_zero(const uint8_t root[32])
{
    size_t i;
    for (i = 0; i < 32; ++i) if (root[i]) return 0;
    return 1;
}
static int grant_valid(const axi_ag1_v1 *g)
{
    if (!g || root_zero(g->decision_aer_root) || root_zero(g->principal_root) ||
        root_zero(g->policy_root) || root_zero(g->action_root) ||
        root_zero(g->resource_root) || root_zero(g->budget_root) ||
        root_zero(g->trust_snapshot_root) || root_zero(g->issuer_key_id) ||
        root_zero(g->nonce) || g->not_before >= g->not_after || g->has_parent > 1u)
        return 0;
    return g->has_parent ? !root_zero(g->parent_root) : root_zero(g->parent_root);
}
static uint8_t *wr_u32(uint8_t *p, uint32_t value)
{
    *p++ = (uint8_t)(value >> 24); *p++ = (uint8_t)(value >> 16);
    *p++ = (uint8_t)(value >> 8); *p++ = (uint8_t)value; return p;
}
static uint8_t *wr_u64(uint8_t *p, uint64_t value)
{
    int i;
    for (i = 7; i >= 0; --i) *p++ = (uint8_t)(value >> (i * 8));
    return p;
}
int axi_ag1_v1_encode(const axi_ag1_v1 *g, uint8_t out[AXI_AG1_V1_BODY_SIZE])
{
    uint8_t *p = out;
    if (!out || !grant_valid(g)) return -1;
    memcpy(p, AXI_AG1_V1_MAGIC, 4); p += 4;
    p = wr_u32(p, AXI_AG1_V1_VERSION);
#define ROOT_WRITE(member) do { memcpy(p, g->member, 32); p += 32; } while (0)
    ROOT_WRITE(decision_aer_root); ROOT_WRITE(principal_root); ROOT_WRITE(policy_root);
    ROOT_WRITE(action_root); ROOT_WRITE(resource_root); ROOT_WRITE(budget_root);
    ROOT_WRITE(trust_snapshot_root); ROOT_WRITE(issuer_key_id); ROOT_WRITE(nonce);
#undef ROOT_WRITE
    p = wr_u64(p, g->not_before); p = wr_u64(p, g->not_after);
    *p++ = g->has_parent; memcpy(p, g->parent_root, 32); p += 32;
    return p == out + AXI_AG1_V1_BODY_SIZE ? 0 : -1;
}
int axi_ag1_v1_decode(axi_ag1_v1 *out, const uint8_t *bytes, size_t size)
{
    ag1_reader r;
    axi_ag1_v1 g;
    const uint8_t *flag;
    if (!out || !bytes || size != AXI_AG1_V1_BODY_SIZE ||
        memcmp(bytes, AXI_AG1_V1_MAGIC, 4) != 0) return -1;
    r.p = bytes; r.len = size; r.off = 4; r.err = 0;
    if (rd_u32(&r) != AXI_AG1_V1_VERSION) return -1;
    memset(&g, 0, sizeof g);
    rd_root(&r, g.decision_aer_root); rd_root(&r, g.principal_root);
    rd_root(&r, g.policy_root); rd_root(&r, g.action_root);
    rd_root(&r, g.resource_root); rd_root(&r, g.budget_root);
    rd_root(&r, g.trust_snapshot_root); rd_root(&r, g.issuer_key_id);
    rd_root(&r, g.nonce); g.not_before = rd_u64(&r); g.not_after = rd_u64(&r);
    flag = rd(&r, 1); if (flag) g.has_parent = *flag;
    rd_root(&r, g.parent_root);
    if (r.err || r.off != size || !grant_valid(&g)) return -1;
    *out = g; return 0;
}
void axi_ag1_v1_root(const axi_ag1_v1 *g, uint8_t out[32])
{
    uint8_t bytes[sizeof(AXI_AG1_V1_BODY_DOMAIN) + AXI_AG1_V1_BODY_SIZE];
    if (!out) return;
    memset(out, 0, 32);
    memcpy(bytes, AXI_AG1_V1_BODY_DOMAIN, sizeof(AXI_AG1_V1_BODY_DOMAIN));
    if (axi_ag1_v1_encode(g, bytes + sizeof(AXI_AG1_V1_BODY_DOMAIN)) != 0) return;
    if (axi_ag1_crypto_hash(bytes, sizeof bytes, out) != 0) memset(out, 0, 32);
}
int axi_ag1_signature_message(const uint8_t body[AXI_AG1_V1_BODY_SIZE],
                              uint8_t out[AXI_AG1_V1_SIG_MSG_SIZE])
{
    memcpy(out, AXI_AG1_V1_SIG_DOMAIN, sizeof(AXI_AG1_V1_SIG_DOMAIN));
    return axi_ag1_crypto_hash(body, AXI_AG1_V1_BODY_SIZE,
                               out + sizeof(AXI_AG1_V1_SIG_DOMAIN));
}
int axi_ag1_v1_decode_signed(axi_ag1_v1 *g, const uint8_t *bytes,
                             size_t size, const uint8_t trusted_pk[32])
{
    uint8_t msg[AXI_AG1_V1_SIG_MSG_SIZE];
    const uint8_t *trailer;
    if (!g || !bytes || !trusted_pk || size != AXI_AG1_V1_SIGNED_SIZE) return -1;
    trailer = bytes + AXI_AG1_V1_BODY_SIZE;
    if (memcmp(trailer, "AG1S", 4) || trailer[4] || trailer[5] || trailer[6] ||
        trailer[7] != 1 || memcmp(trailer + 8, trusted_pk, 32)) return -1;
    if (axi_ag1_signature_message(bytes, msg) != 0 ||
        axi_ag1_crypto_verify(trailer + 40, msg, sizeof msg, trusted_pk) != 0)
        return -1;
    return axi_ag1_v1_decode(g, bytes, AXI_AG1_V1_BODY_SIZE);
}
int axi_ag1_v1_matches(const axi_ag1_v1 *g, const axi_ag1_v1_expectation *e,
                       uint64_t now)
{
    if (!grant_valid(g) || !e || now < g->not_before || now >= g->not_after) return 0;
#define MATCH(member) if (memcmp(g->member, e->member, 32)) return 0
    MATCH(decision_aer_root); MATCH(principal_root); MATCH(policy_root);
    MATCH(action_root); MATCH(resource_root); MATCH(budget_root); MATCH(trust_snapshot_root);
#undef MATCH
    return 1;
}
int axi_ag1_v1_verify_expected(axi_ag1_v1 *out, const uint8_t *bytes, size_t size,
                               const uint8_t pk[32], const axi_ag1_v1_expectation *e,
                               uint64_t now)
{
    axi_ag1_v1 g;
    if (!out || !e || axi_ag1_v1_decode_signed(&g, bytes, size, pk) != 0 ||
        !axi_ag1_v1_matches(&g, e, now)) return -1;
    *out = g; return 0;
}
