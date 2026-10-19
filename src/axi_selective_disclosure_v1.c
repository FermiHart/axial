#include "axi_selective_disclosure_v1.h"

#include "axi_hash.h"

#include <string.h>

static int all_zero(const void *bytes, size_t len)
{
    const uint8_t *p = bytes;
    size_t i;
    for (i = 0; i < len; i++) if (p[i] != 0) return 0;
    return 1;
}

static int class_valid(uint8_t class_id)
{
    return class_id == AXI_SD1_PUBLIC || class_id == AXI_SD1_PROTECTED
        || class_id == AXI_SD1_DISCLOSE_ONLY;
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

int axi_sd1_commit_field(uint8_t class_id, uint8_t type_id,
                         const uint8_t field_tag[32], uint32_t index,
                         const uint8_t salt[32],
                         const uint8_t *value, uint64_t value_len,
                         uint8_t out[32])
{
    uint8_t header[sizeof(AXI_SD1_LEAF_DOMAIN) + 1u + 1u + 32u + 4u + 8u + 32u + 32u];
    uint8_t value_hash[32];
    uint8_t *p = header;
    if (!out || !class_valid(class_id) || type_id == 0 || !field_tag || !salt
            || all_zero(field_tag, 32) || all_zero(salt, 32)
            || value_len > (uint64_t)SIZE_MAX
            || (value_len && !value))
        return -1;
    axi_sha256(value, (size_t)value_len, value_hash);
    memcpy(p, AXI_SD1_LEAF_DOMAIN, sizeof(AXI_SD1_LEAF_DOMAIN));
    p += sizeof(AXI_SD1_LEAF_DOMAIN);
    *p++ = class_id;
    *p++ = type_id;
    memcpy(p, field_tag, 32); p += 32;
    p = wr_u32(p, index);
    p = wr_u64(p, value_len);
    memcpy(p, salt, 32); p += 32;
    memcpy(p, value_hash, 32); p += 32;
    axi_sha256(header, (size_t)(p - header), out);
    return 0;
}

int axi_sd1_make_leaf(axi_sd1_leaf *leaf, uint8_t class_id, uint8_t type_id,
                      const uint8_t field_tag[32], uint32_t index,
                      const uint8_t salt[32],
                      const uint8_t *value, uint64_t value_len)
{
    if (!leaf || axi_sd1_commit_field(class_id, type_id, field_tag, index, salt,
                                      value, value_len, leaf->commitment) != 0)
        return -1;
    memset(leaf, 0, sizeof *leaf);
    leaf->class_id = class_id;
    leaf->type_id = type_id;
    memcpy(leaf->field_tag, field_tag, 32);
    leaf->index = index;
    leaf->value_len = value_len;
    return axi_sd1_commit_field(class_id, type_id, field_tag, index, salt,
                                value, value_len, leaf->commitment);
}

int axi_sd1_verify_disclosure(const axi_sd1_leaf *leaf,
                              const uint8_t salt[32],
                              const uint8_t *value, uint64_t value_len)
{
    uint8_t commitment[32];
    if (!leaf || value_len != leaf->value_len
            || axi_sd1_commit_field(leaf->class_id, leaf->type_id, leaf->field_tag,
                                    leaf->index, salt, value, value_len,
                                    commitment) != 0)
        return -1;
    return memcmp(commitment, leaf->commitment, 32) == 0 ? 0 : -1;
}

static int leaf_ordered(const axi_sd1_leaf *prev, const axi_sd1_leaf *next)
{
    int c = memcmp(prev->field_tag, next->field_tag, 32);
    if (c < 0) return 1;
    if (c > 0) return 0;
    return prev->index < next->index;
}

int axi_sd1_root(const axi_sd1_leaf *leaves, size_t n, uint8_t out[32])
{
    uint8_t h[sizeof(AXI_SD1_ROOT_DOMAIN) + 4u];
    uint8_t acc[32], row[1u + 1u + 32u + 4u + 8u + 32u];
    uint8_t node[32u + sizeof row];
    uint8_t *p;
    size_t i;
    if (!out || !leaves || n == 0 || n > UINT32_MAX) return -1;
    p = h;
    memcpy(p, AXI_SD1_ROOT_DOMAIN, sizeof(AXI_SD1_ROOT_DOMAIN));
    p += sizeof(AXI_SD1_ROOT_DOMAIN);
    p = wr_u32(p, (uint32_t)n);
    axi_sha256(h, (size_t)(p - h), acc);
    for (i = 0; i < n; i++) {
        if (!class_valid(leaves[i].class_id) || leaves[i].type_id == 0
                || all_zero(leaves[i].field_tag, 32)
                || all_zero(leaves[i].commitment, 32)
                || (i && !leaf_ordered(&leaves[i - 1], &leaves[i])))
            return -1;
        p = row;
        *p++ = leaves[i].class_id;
        *p++ = leaves[i].type_id;
        memcpy(p, leaves[i].field_tag, 32); p += 32;
        p = wr_u32(p, leaves[i].index);
        p = wr_u64(p, leaves[i].value_len);
        memcpy(p, leaves[i].commitment, 32); p += 32;
        memcpy(node, acc, 32);
        memcpy(node + 32, row, (size_t)(p - row));
        axi_sha256(node, 32 + (size_t)(p - row), acc);
    }
    memcpy(out, acc, 32);
    return 0;
}
