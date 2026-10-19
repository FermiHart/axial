#include "axi_gateway_v1.h"

#include "axi_hash.h"

#include <string.h>

static const char *const ACTIONS[] = {
    "cloud.sim.Put",
    "fs.object.Write",
    "git.fixture.Commit",
    "shell.exec.Fixed"
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

int axi_gateway_v1_action_known(const char *action_name)
{
    size_t i;
    if (!action_name) return 0;
    for (i = 0; i < sizeof ACTIONS / sizeof ACTIONS[0]; i++)
        if (strcmp(action_name, ACTIONS[i]) == 0) return 1;
    return 0;
}

static int request_valid(const axi_gateway_request *r)
{
    return r && axi_gateway_v1_action_known(r->action_name)
        && !root_zero(r->request_id) && !root_zero(r->principal_root)
        && !root_zero(r->admission_root) && !root_zero(r->action_descriptor_root)
        && !root_zero(r->ag1_action_root) && !root_zero(r->payload_root)
        && !root_zero(r->sequence_root)
        && memcmp(r->action_descriptor_root, r->ag1_action_root, 32) == 0;
}

int axi_gateway_v1_request_digest(const axi_gateway_request *r, uint8_t out[32])
{
    uint8_t name_hash[32];
    uint8_t bytes[sizeof(AXI_GATEWAY_V1_DOMAIN) + 4u + 32u * 8u];
    uint8_t *p = bytes;
    if (!out || !request_valid(r)) return -1;
    axi_sha256(r->action_name, strlen(r->action_name), name_hash);
    memcpy(p, AXI_GATEWAY_V1_DOMAIN, sizeof(AXI_GATEWAY_V1_DOMAIN));
    p += sizeof(AXI_GATEWAY_V1_DOMAIN);
    p = wr_u32(p, (uint32_t)strlen(r->action_name));
    memcpy(p, name_hash, 32); p += 32;
    memcpy(p, r->request_id, 32); p += 32;
    memcpy(p, r->principal_root, 32); p += 32;
    memcpy(p, r->admission_root, 32); p += 32;
    memcpy(p, r->action_descriptor_root, 32); p += 32;
    memcpy(p, r->ag1_action_root, 32); p += 32;
    memcpy(p, r->payload_root, 32); p += 32;
    memcpy(p, r->sequence_root, 32); p += 32;
    axi_sha256(bytes, (size_t)(p - bytes), out);
    return 0;
}

int axi_gateway_v1_admit(axi_gateway_idempotency_state *state,
                         const axi_gateway_request *request,
                         uint8_t digest_out[32])
{
    uint8_t digest[32];
    size_t i;
    if (!state || state->n > AXI_GATEWAY_V1_MAX_RECORDS
            || axi_gateway_v1_request_digest(request, digest) != 0)
        return AXI_GATEWAY_REFUSED;
    for (i = 0; i < state->n; i++) {
        if (memcmp(state->request_id[i], request->request_id, 32) != 0) continue;
        if (memcmp(state->digest[i], digest, 32) == 0) {
            if (digest_out) memcpy(digest_out, digest, 32);
            return AXI_GATEWAY_DUPLICATE;
        }
        return AXI_GATEWAY_REFUSED;
    }
    if (state->n >= AXI_GATEWAY_V1_MAX_RECORDS) return AXI_GATEWAY_REFUSED;
    memcpy(state->request_id[state->n], request->request_id, 32);
    memcpy(state->digest[state->n], digest, 32);
    state->n++;
    if (digest_out) memcpy(digest_out, digest, 32);
    return AXI_GATEWAY_NEW;
}
