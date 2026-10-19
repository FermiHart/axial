/* ADR-020 Phase A candidate only. This is not a frozen or installed ABI. */
#ifndef AXI_EMBED_V1_H
#define AXI_EMBED_V1_H

#include <stddef.h>
#include <stdint.h>

#ifndef AXI_EMBED_V1_API
#define AXI_EMBED_V1_API
#endif

#ifndef AXI_EMBED_V1_CALL
#define AXI_EMBED_V1_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define AXI_EMBED_V1_ABI_VERSION 1u

typedef struct axi_embed_v1_context axi_embed_v1_context;

typedef uint32_t axi_embed_v1_status;
#define AXI_EMBED_V1_STATUS_OK                 0u
#define AXI_EMBED_V1_STATUS_INVALID_ARGUMENT   1u
#define AXI_EMBED_V1_STATUS_ABI_MISMATCH       2u
#define AXI_EMBED_V1_STATUS_ADMISSION_REFUSED  3u
#define AXI_EMBED_V1_STATUS_OUT_OF_MEMORY      4u

typedef uint32_t axi_embed_v1_admission;
#define AXI_EMBED_V1_ADMIT_SIGNATURE_VALID 1u
#define AXI_EMBED_V1_ADMIT_CHECKED         2u

typedef uint32_t axi_embed_v1_outcome_kind;
#define AXI_EMBED_V1_OUTCOME_VALUE             1u
#define AXI_EMBED_V1_OUTCOME_ALLOW             2u
#define AXI_EMBED_V1_OUTCOME_DENY              3u
#define AXI_EMBED_V1_OUTCOME_TRAP              4u
#define AXI_EMBED_V1_OUTCOME_REFUSED           5u
#define AXI_EMBED_V1_OUTCOME_BUFFER_TOO_SMALL  6u

typedef uint32_t axi_embed_v1_value_kind;
#define AXI_EMBED_V1_VALUE_UNIT   1u
#define AXI_EMBED_V1_VALUE_U64    2u
#define AXI_EMBED_V1_VALUE_I64    3u
#define AXI_EMBED_V1_VALUE_F64    4u
#define AXI_EMBED_V1_VALUE_BOOL   5u
#define AXI_EMBED_V1_VALUE_STR    6u
#define AXI_EMBED_V1_VALUE_BYTES  7u
#define AXI_EMBED_V1_VALUE_ERROR  8u
#define AXI_EMBED_V1_VALUE_UNION  9u

typedef uint32_t axi_embed_v1_payload_kind;
#define AXI_EMBED_V1_PAYLOAD_UNIT   1u
#define AXI_EMBED_V1_PAYLOAD_U64    2u
#define AXI_EMBED_V1_PAYLOAD_I64    3u
#define AXI_EMBED_V1_PAYLOAD_F64    4u
#define AXI_EMBED_V1_PAYLOAD_BOOL   5u
#define AXI_EMBED_V1_PAYLOAD_STR    6u
#define AXI_EMBED_V1_PAYLOAD_BYTES  7u
#define AXI_EMBED_V1_PAYLOAD_ERROR  8u

#define AXI_EMBED_V1_OUTCOME_F_FUEL_EXHAUSTED 1u

typedef uint32_t axi_embed_v1_phase;
#define AXI_EMBED_V1_PHASE_ARGUMENT   1u
#define AXI_EMBED_V1_PHASE_ADMISSION  2u
#define AXI_EMBED_V1_PHASE_PREFLIGHT  3u
#define AXI_EMBED_V1_PHASE_EXECUTION  4u
#define AXI_EMBED_V1_PHASE_OUTPUT     5u

#define AXI_EMBED_V1_NO_OFFSET UINT64_MAX
#define AXI_EMBED_V1_DIAG_SCHEMA_VERSION 1u

/* Phase A leaf hypothesis; Phase B may change it. Extensible records carry size. */
typedef struct {
    const uint8_t *data;
    uint64_t len;
} axi_embed_v1_bytes;

typedef struct {
    uint8_t *data;
    uint64_t capacity;
} axi_embed_v1_buffer;

typedef struct {
    uint32_t kind;
    uint32_t payload_kind;
    uint32_t tag;
    uint32_t flags;
    uint64_t bits;
    axi_embed_v1_bytes payload;
    axi_embed_v1_bytes atom;
    uint64_t reserved[2];
} axi_embed_v1_value;

typedef struct {
    uint32_t schema_version;
    char code[12];
    uint32_t phase;
    uint32_t reserved0;
    uint64_t offset;
    char message[160];
    char repair[160];
    uint64_t reserved[2];
} axi_embed_v1_diag;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    axi_embed_v1_diag *entries;
    uint64_t capacity;
    uint64_t count;
    uint64_t dropped;
    uint64_t reserved[2];
} axi_embed_v1_diag_buffer;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t admission_profile;
    uint32_t flags;
    axi_embed_v1_bytes module;
    uint8_t trusted_producer_pk[32];
    uint64_t reserved[2];
} axi_embed_v1_context_options;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    axi_embed_v1_bytes cell;
    uint8_t expected_iface_hash[32];
    const axi_embed_v1_value *args;
    uint64_t argc;
    uint64_t fuel_limit;
    axi_embed_v1_buffer workspace;
    uint64_t reserved[2];
} axi_embed_v1_eval_request;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t kind;
    uint32_t flags;
    axi_embed_v1_value value;
    uint64_t fuel_requested;
    uint64_t fuel_effective;
    uint64_t fuel_used;
    uint64_t workspace_used;
    uint64_t workspace_required;
    uint64_t reserved[2];
} axi_embed_v1_outcome;

AXI_EMBED_V1_API uint32_t AXI_EMBED_V1_CALL axi_embed_v1_abi_version(void);
AXI_EMBED_V1_API axi_embed_v1_status AXI_EMBED_V1_CALL axi_embed_v1_context_create(
    const axi_embed_v1_context_options *options,
    axi_embed_v1_context **out,
    axi_embed_v1_diag_buffer *diags);
AXI_EMBED_V1_API void AXI_EMBED_V1_CALL axi_embed_v1_context_destroy(
    axi_embed_v1_context *context);
AXI_EMBED_V1_API axi_embed_v1_status AXI_EMBED_V1_CALL axi_embed_v1_eval(
    const axi_embed_v1_context *context,
    const axi_embed_v1_eval_request *request,
    axi_embed_v1_outcome *outcome,
    axi_embed_v1_diag_buffer *diags);

#ifdef __cplusplus
}
#endif

#endif /* AXI_EMBED_V1_H */
