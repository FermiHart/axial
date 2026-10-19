#include "axi_extdec_v1.h"

#include "axi_hash.h"

#include <string.h>

static int root_zero(const uint8_t root[32])
{
    size_t i;
    for (i = 0; i < 32; i++) if (root[i] != 0) return 0;
    return 1;
}

static int adapter_valid(uint8_t adapter)
{
    return adapter == AXI_EXTDEC_OPA || adapter == AXI_EXTDEC_CEDAR
        || adapter == AXI_EXTDEC_CEL || adapter == AXI_EXTDEC_JSON_SCHEMA
        || adapter == AXI_EXTDEC_OCC;
}

static int verdict_valid(uint8_t verdict)
{
    return verdict == AXI_EXTDEC_ALLOW || verdict == AXI_EXTDEC_DENY
        || verdict == AXI_EXTDEC_UNPROVEN;
}

static int fact_valid(const axi_extdec_v1_fact *f)
{
    return f && adapter_valid(f->adapter_kind) && verdict_valid(f->verdict)
        && f->authenticated <= 1 && !root_zero(f->adapter_profile_root)
        && !root_zero(f->policy_root) && !root_zero(f->query_root)
        && !root_zero(f->input_root) && !root_zero(f->action_root)
        && !root_zero(f->native_result_root) && !root_zero(f->obligation_root);
}

int axi_extdec_v1_from_bool(axi_extdec_v1_fact *fact, uint8_t adapter_kind,
                            uint8_t authenticated,
                            const uint8_t adapter_profile_root[32],
                            const uint8_t policy_root[32],
                            const uint8_t query_root[32],
                            const uint8_t input_root[32],
                            const uint8_t action_root[32],
                            const uint8_t native_result_root[32],
                            const uint8_t obligation_root[32],
                            uint8_t has_bool, uint8_t bool_value)
{
    if (!fact || !adapter_profile_root || !policy_root || !query_root || !input_root
            || !action_root || !native_result_root || !obligation_root
            || !adapter_valid(adapter_kind) || authenticated > 1
            || has_bool > 1 || bool_value > 1)
        return -1;
    memset(fact, 0, sizeof *fact);
    fact->adapter_kind = adapter_kind;
    fact->authenticated = authenticated;
    fact->verdict = has_bool ? (bool_value ? AXI_EXTDEC_ALLOW : AXI_EXTDEC_DENY)
                             : AXI_EXTDEC_UNPROVEN;
    memcpy(fact->adapter_profile_root, adapter_profile_root, 32);
    memcpy(fact->policy_root, policy_root, 32);
    memcpy(fact->query_root, query_root, 32);
    memcpy(fact->input_root, input_root, 32);
    memcpy(fact->action_root, action_root, 32);
    memcpy(fact->native_result_root, native_result_root, 32);
    memcpy(fact->obligation_root, obligation_root, 32);
    return fact_valid(fact) ? 0 : -1;
}

int axi_extdec_v1_root(const axi_extdec_v1_fact *f, uint8_t out[32])
{
    uint8_t bytes[sizeof(AXI_EXTDEC_V1_DOMAIN) + 3u + 32u * 7u];
    uint8_t *p = bytes;
    if (!out || !fact_valid(f)) return -1;
    memcpy(p, AXI_EXTDEC_V1_DOMAIN, sizeof(AXI_EXTDEC_V1_DOMAIN));
    p += sizeof(AXI_EXTDEC_V1_DOMAIN);
    *p++ = f->adapter_kind;
    *p++ = f->verdict;
    *p++ = f->authenticated;
    memcpy(p, f->adapter_profile_root, 32); p += 32;
    memcpy(p, f->policy_root, 32); p += 32;
    memcpy(p, f->query_root, 32); p += 32;
    memcpy(p, f->input_root, 32); p += 32;
    memcpy(p, f->action_root, 32); p += 32;
    memcpy(p, f->native_result_root, 32); p += 32;
    memcpy(p, f->obligation_root, 32); p += 32;
    axi_sha256(bytes, (size_t)(p - bytes), out);
    return 0;
}

int axi_extdec_v1_allows_narrowing(const axi_extdec_v1_fact *f,
                                   const uint8_t local_action_root[32],
                                   const uint8_t local_obligation_root[32])
{
    if (!fact_valid(f) || !local_action_root || !local_obligation_root
            || f->verdict != AXI_EXTDEC_ALLOW || !f->authenticated
            || memcmp(f->action_root, local_action_root, 32) != 0
            || memcmp(f->obligation_root, local_obligation_root, 32) != 0)
        return -1;
    return 0;
}
