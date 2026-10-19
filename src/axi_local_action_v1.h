/* ADR-059 / AXI-INV-184: pure action identity, not admission or effect authority. */
#ifndef AXI_LOCAL_ACTION_V1_H
#define AXI_LOCAL_ACTION_V1_H

#include <stddef.h>
#include <stdint.h>

#define AXI_LOCAL_ACTION_V1_MAX_BYTES 4096u
#define AXI_LOCAL_ACTION_V1_SCHEMA "AXV2-ACTION-v1"
#define AXI_LOCAL_ACTION_V1_INVALID (-1)
#define AXI_LOCAL_ACTION_V1_CAPACITY (-2)

typedef struct {
    uint64_t device, inode, size, mtime_ns;
    uint8_t sha256[32];
} axi_local_previous_v1;

typedef struct {
    uint8_t deployment[16], boot[16];
    uint32_t uid, executor_uid;
    uint8_t policy_binary[32], policy_module[32], policy_producer[32], policy_iface[32];
    uint64_t resource_device, resource_inode;
    uint8_t has_previous;
    axi_local_previous_v1 previous;
    uint64_t payload_size;
    uint8_t payload_sha256[32], trust_snapshot_root[32];
    uint64_t fuel, workspace, ttl_ns, not_before, not_after;
} axi_local_action_v1;

typedef struct {
    uint8_t action[32], principal[32], policy[32], resource[32], budget[32];
} axi_local_action_roots_v1;

/* Private C interface; no installed ABI promise. Callers supply live, stable
 * objects/spans. No heap, clock, filesystem, signing, spend or effect callback.
 * The fixed literal fields of ADR-059 are implicit in the typed structure.
 * has_previous is 0/1; inactive previous fields must be zero (padding ignored).
 * Hex/UUID bytes identify data; zero digests do not establish trust or authority.
 *
 * Decode requires exact canonical JSON (no whitespace, escapes, extras or
 * trailing newline). It validates the complete JSON before typed extraction.
 * Success returns 0, failure INVALID; *out stays unchanged on failure.
 * Encode returns the positive byte length, or INVALID/CAPACITY. No NUL is
 * appended. Output stays unchanged on failure. Encoder/decoder stage their
 * result, allowing input/output byte overlap when all spans are valid.
 * Roots returns 0/INVALID; output stays unchanged on failure and must not
 * overlap the input typed object. Hashes bind data, not truth of caller facts. */
int axi_local_action_v1_decode(axi_local_action_v1 *out, const void *bytes, size_t len);
int axi_local_action_v1_encode(const axi_local_action_v1 *action, void *out, size_t capacity);
int axi_local_action_v1_roots(const axi_local_action_v1 *action, axi_local_action_roots_v1 *out);

#endif
