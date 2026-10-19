#include "axi_jm1_v1.h"

#include "axi_hash.h"

#include <string.h>

static const axi_jm1_action ACTIONS[] = {
    {"cwd.set", 0},
    {"env.assign", 0},
    {"fs.redirect.write", 0},
    {"job.signal", 0},
    {"proc.spawn", 1},
    {"shell.option.set", 0},
    {"state.agent.write", 0},
    {"undo.record", 0}
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

static const axi_jm1_action *find_action(const char *name)
{
    size_t i;
    if (!name) return NULL;
    for (i = 0; i < sizeof ACTIONS / sizeof ACTIONS[0]; i++)
        if (strcmp(name, ACTIONS[i].name) == 0) return &ACTIONS[i];
    return NULL;
}

int axi_jm1_action_root(const char *name, uint8_t out[32])
{
    const axi_jm1_action *action = find_action(name);
    uint8_t name_hash[32];
    uint8_t bytes[sizeof(AXI_JM1_V1_DOMAIN) + 1u + 4u + 32u];
    uint8_t *p = bytes;
    if (!out || !action) return -1;
    axi_sha256(name, strlen(name), name_hash);
    memcpy(p, AXI_JM1_V1_DOMAIN, sizeof(AXI_JM1_V1_DOMAIN));
    p += sizeof(AXI_JM1_V1_DOMAIN);
    *p++ = action->opaque_child;
    p = wr_u32(p, (uint32_t)strlen(name));
    memcpy(p, name_hash, 32); p += 32;
    axi_sha256(bytes, (size_t)(p - bytes), out);
    return 0;
}

int axi_jm1_registry_root(uint8_t out[32])
{
    uint8_t acc[32], row[32], node[64];
    uint8_t header[sizeof(AXI_JM1_V1_REGISTRY_DOMAIN) + 4u];
    uint8_t *p = header;
    size_t i;
    if (!out) return -1;
    memcpy(p, AXI_JM1_V1_REGISTRY_DOMAIN, sizeof(AXI_JM1_V1_REGISTRY_DOMAIN));
    p += sizeof(AXI_JM1_V1_REGISTRY_DOMAIN);
    p = wr_u32(p, (uint32_t)(sizeof ACTIONS / sizeof ACTIONS[0]));
    axi_sha256(header, (size_t)(p - header), acc);
    for (i = 0; i < sizeof ACTIONS / sizeof ACTIONS[0]; i++) {
        if (axi_jm1_action_root(ACTIONS[i].name, row) != 0) return -1;
        memcpy(node, acc, 32);
        memcpy(node + 32, row, 32);
        axi_sha256(node, sizeof node, acc);
    }
    memcpy(out, acc, 32);
    return 0;
}

static int descriptor_valid(const axi_jm1_descriptor *d)
{
    return d && !root_zero(d->action_root) && !root_zero(d->resolved_descriptor_root)
        && !root_zero(d->admission_root) && !root_zero(d->rollout_root)
        && !root_zero(d->ag1_action_root) && !root_zero(d->aer_channel_root)
        && memcmp(d->action_root, d->ag1_action_root, 32) == 0;
}

int axi_jm1_descriptor_root(const axi_jm1_descriptor *d, uint8_t out[32])
{
    uint8_t bytes[sizeof(AXI_JM1_V1_DOMAIN) + 32u * 6u];
    uint8_t *p = bytes;
    if (!out || !descriptor_valid(d)) return -1;
    memcpy(p, AXI_JM1_V1_DOMAIN, sizeof(AXI_JM1_V1_DOMAIN));
    p += sizeof(AXI_JM1_V1_DOMAIN);
    memcpy(p, d->action_root, 32); p += 32;
    memcpy(p, d->resolved_descriptor_root, 32); p += 32;
    memcpy(p, d->admission_root, 32); p += 32;
    memcpy(p, d->rollout_root, 32); p += 32;
    memcpy(p, d->ag1_action_root, 32); p += 32;
    memcpy(p, d->aer_channel_root, 32); p += 32;
    axi_sha256(bytes, (size_t)(p - bytes), out);
    return 0;
}

int axi_jm1_final_door_check(const axi_jm1_descriptor *descriptor)
{
    uint8_t root[32];
    return axi_jm1_descriptor_root(descriptor, root) == 0 ? 0 : -1;
}
