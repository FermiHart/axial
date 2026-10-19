#include "axi_ca43_47_core.h"

#include "axi_hash.h"

#include <string.h>

static const char *const TARGET_EFFECTS[] = {
    "fs.Read",
    "fs.Write",
    "fs.path_under"
};

static const char *const SDK_SYMBOLS[] = {
    "axi_embed_v1_context_create",
    "axi_embed_v1_context_destroy",
    "axi_embed_v1_eval",
    "axi_embed_v1_inspect"
};

static int root_zero(const uint8_t root[32])
{
    size_t i;
    for (i = 0; i < 32; i++) if (root[i] != 0) return 0;
    return 1;
}

static uint8_t *wr_u32(uint8_t *p, uint32_t value)
{
    *p++ = (uint8_t)(value >> 24);
    *p++ = (uint8_t)(value >> 16);
    *p++ = (uint8_t)(value >> 8);
    *p++ = (uint8_t)value;
    return p;
}

int axi_target1_effect_mapping(const char *effect_name)
{
    size_t i;
    if (!effect_name) return AXI_TARGET_EFFECT_MISSING;
    for (i = 0; i < sizeof TARGET_EFFECTS / sizeof TARGET_EFFECTS[0]; i++)
        if (strcmp(effect_name, TARGET_EFFECTS[i]) == 0) return AXI_TARGET_EFFECT_MAPPED;
    return AXI_TARGET_EFFECT_MISSING;
}

int axi_target1_registry_root(uint8_t out[32])
{
    uint8_t header[sizeof(AXI_CA43_47_CORE_DOMAIN) + 4u];
    uint8_t acc[32], name_hash[32], node[64];
    uint8_t *p = header;
    size_t i;
    if (!out) return -1;
    memcpy(p, AXI_CA43_47_CORE_DOMAIN, sizeof(AXI_CA43_47_CORE_DOMAIN));
    p += sizeof(AXI_CA43_47_CORE_DOMAIN);
    p = wr_u32(p, (uint32_t)(sizeof TARGET_EFFECTS / sizeof TARGET_EFFECTS[0]));
    axi_sha256(header, (size_t)(p - header), acc);
    for (i = 0; i < sizeof TARGET_EFFECTS / sizeof TARGET_EFFECTS[0]; i++) {
        axi_sha256(TARGET_EFFECTS[i], strlen(TARGET_EFFECTS[i]), name_hash);
        memcpy(node, acc, 32);
        memcpy(node + 32, name_hash, 32);
        axi_sha256(node, sizeof node, acc);
    }
    memcpy(out, acc, 32);
    return 0;
}

int axi_fd1_admit_once(axi_fd1_attempt *a)
{
    if (!a || root_zero(a->action_root) || root_zero(a->grant_action_root)
            || memcmp(a->action_root, a->grant_action_root, 32) != 0
            || a->spent || a->budget_cost == 0 || a->budget_cost > a->budget_limit)
        return -1;
    a->spent = 1;
    return 0;
}

int axi_vfact1_consume(const axi_vfact1 *f, const uint8_t action_root[32])
{
    if (!f || !action_root || f->maturity != AXI_FACT_CHECKED
            || root_zero(f->checker_root) || root_zero(f->module_root)
            || root_zero(f->action_root) || root_zero(f->requested_root)
            || root_zero(f->observed_root) || root_zero(f->policy_root)
            || memcmp(f->action_root, action_root, 32) != 0
            || memcmp(f->requested_root, f->observed_root, 32) != 0
            || memcmp(f->requested_root, f->policy_root, 32) != 0)
        return -1;
    return 0;
}

int axi_sdkpkg1_symbol_allowed(const char *symbol)
{
    size_t i;
    if (!symbol) return 0;
    for (i = 0; i < sizeof SDK_SYMBOLS / sizeof SDK_SYMBOLS[0]; i++)
        if (strcmp(symbol, SDK_SYMBOLS[i]) == 0) return 1;
    return 0;
}

int axi_sdkpkg1_include_allowed(const char *include_path)
{
    if (!include_path) return 0;
    return strcmp(include_path, "axial/axi_embed_v1.h") == 0;
}

int axi_matrix1_release_green(const axi_matrix1_row *rows, size_t n)
{
    size_t i;
    if (!rows || n == 0) return -1;
    for (i = 0; i < n; i++) {
        if (!rows[i].name || root_zero(rows[i].evidence_root)) return -1;
        if (rows[i].requirement == AXI_MATRIX_REQUIRED) {
            if (rows[i].result != AXI_JOB_PASS) return -1;
        } else if (rows[i].requirement == AXI_MATRIX_OPTIONAL) {
            if (rows[i].result != AXI_JOB_PASS && rows[i].result != AXI_JOB_SKIP)
                return -1;
        } else if (rows[i].requirement == AXI_MATRIX_BLOCKED) {
            if (rows[i].result != AXI_JOB_SKIP) return -1;
        } else {
            return -1;
        }
    }
    return 0;
}
