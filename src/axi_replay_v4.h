/* axial - isolated ADR-018 CA16 replay envelope.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * The codec does not invoke the VM, dispatch effects, or grant authority.
 * The CA16 admission adapter at the end reuses the trusted AXB v7 decoder to
 * derive artifact identity; it never maintains a second AXB parser.
 *
 * Body wire form (all integer widths are unsigned big-endian):
 *   "AXR4" | u32 version=4
 *   binding
 *   u32 effect_count | effect*
 *   terminal
 * The body is followed by exactly one 104-byte trailer:
 *   "AXRS" | u32 version=1 | recorder_pk[32] | recorder_sig[64]
 * The recorder signs the domain-separated SHA-256 of the exact body.  The
 * recorder key is a separate trust anchor from binding.producer_pk.
 */
#ifndef AXI_REPLAY_V4_H
#define AXI_REPLAY_V4_H

#include <stddef.h>
#include <stdint.h>

#include "axi_contract.h"
#include "axi_replay.h"

#define AXI_REPLAY_V4_BODY_MAGIC        "AXR4"
#define AXI_REPLAY_V4_BODY_MAGIC_BYTES  4u
#define AXI_REPLAY_V4_VERSION           4u
#define AXI_REPLAY_V4_SIG_MAGIC         "AXRS"
#define AXI_REPLAY_V4_SIG_VERSION       1u
#define AXI_REPLAY_V4_SIG_TRAILER       104u
#define AXI_REPLAY_V4_RECORDER_DOMAIN   "AXI-REPLAY-RECORDER-v4"

#define AXI_REPLAY_V4_MAX_ARGS          16u
#define AXI_REPLAY_V4_MAX_ARG_BYTES     1024u
#define AXI_REPLAY_V4_MAX_GRANTS        32u
#define AXI_REPLAY_V4_MAX_TERMINAL      1024u
#define AXI_REPLAY_V4_MAX_EFFECTS       10000u
#define AXI_REPLAY_V4_MAX_ENCODED       (16u * 1024u * 1024u)

/* Stable replay wire kinds.  Values 1..10 deliberately match the frozen
 * contract-manifest type IDs, but this codec does not depend on that parser. */
#define AXI_REPLAY_V4_KIND_U64          1u
#define AXI_REPLAY_V4_KIND_I64          2u
#define AXI_REPLAY_V4_KIND_F64          3u
#define AXI_REPLAY_V4_KIND_BOOL         4u
#define AXI_REPLAY_V4_KIND_STR          5u
#define AXI_REPLAY_V4_KIND_BYTES        6u
#define AXI_REPLAY_V4_KIND_JSON         7u
#define AXI_REPLAY_V4_KIND_DECISION     8u
#define AXI_REPLAY_V4_KIND_OK           9u
#define AXI_REPLAY_V4_KIND_CAP          10u
#define AXI_REPLAY_V4_KIND_ERR          11u

/* ERR terminal bytes: u32be atom_len | atom | u32be payload_len | payload.
 * The atom is matched byte-for-byte against the signed manifest error set;
 * both lengths must consume output_len exactly. */
#define AXI_REPLAY_V4_ERR_FRAME_FIXED    8u
#define AXI_REPLAY_V4_ERR_ATOM_MAX       63u

#define AXI_REPLAY_V4_TAG_NONE          UINT32_MAX

#define AXI_REPLAY_V4_RESULT_BYTES      1u
#define AXI_REPLAY_V4_RESULT_SCALAR_I64 2u

/* These values intentionally match the effect journal's terminal states
 * without importing the effect plane into this isolated codec. */
#define AXI_REPLAY_V4_JOURNAL_PARTIAL   3u
#define AXI_REPLAY_V4_JOURNAL_COMMITTED 4u
#define AXI_REPLAY_V4_JOURNAL_FAILED    5u

typedef struct {
    uint8_t kind;
    uint32_t len;
    uint8_t bytes[AXI_REPLAY_V4_MAX_ARG_BYTES];
} axi_replay_v4_arg;

typedef struct {
    uint8_t body_root[32];
    uint8_t producer_pk[32];
    uint32_t cell_index;
    char cell_name[AXI_CAPNAME];
    uint8_t iface_hash[32];
    uint8_t cell_body_hash[32];
    uint64_t operator_budget;
    uint32_t nargs;
    axi_replay_v4_arg args[AXI_REPLAY_V4_MAX_ARGS];
    uint32_t ngrants;
    char grants[AXI_REPLAY_V4_MAX_GRANTS][AXI_CAPNAME];
} axi_replay_v4_binding;

/* Invocation-owned facts. Artifact identity is deliberately absent: the
 * signed-v7 door below rederives it from admitted AXBS bytes. */
typedef struct {
    uint32_t cell_index;
    uint64_t operator_budget;
    uint32_t nargs;
    axi_replay_v4_arg args[AXI_REPLAY_V4_MAX_ARGS];
    uint32_t ngrants;
    char grants[AXI_REPLAY_V4_MAX_GRANTS][AXI_CAPNAME];
} axi_replay_v4_invocation;

typedef struct {
    uint8_t output_kind;
    uint32_t output_tag; /* zero-based return arm, or TAG_NONE for a scalar */
    uint32_t output_len;
    uint8_t output[AXI_REPLAY_V4_MAX_TERMINAL];
    uint64_t total_fuel;
    uint8_t trace_root[32];
    uint8_t ledger_tip[32];
    uint8_t journal_tip[32];
    uint8_t journal_state; /* PARTIAL, COMMITTED or FAILED */
} axi_replay_v4_terminal;

typedef struct {
    axi_replay_v4_binding binding;
    axi_replay effects; /* owned deep copy, ready in AXI_REPLAY_REPLAY mode */
    axi_replay_v4_terminal terminal;
    uint8_t recorder_pk[32];
} axi_replay_v4_episode;

#define AXI_REPLAY_V4_BINDING_LOCAL_BYTES \
    ((size_t)sizeof(axi_replay_v4_binding))
#define AXI_REPLAY_V4_EPISODE_LOCAL_BYTES \
    ((size_t)sizeof(axi_replay_v4_episode))
#define AXI_REPLAY_V4_RESULT_CONTRACT_LOCAL_BYTES 1048u

void axi_replay_v4_episode_init(axi_replay_v4_episode *episode);
/* The account must outlive the episode. NULL selects legacy allocation. */
void axi_replay_v4_episode_init_accounted(axi_replay_v4_episode *episode,
                                          axi_mem_account *account);
void axi_replay_v4_episode_free(axi_replay_v4_episode *episode);

/* Return zero only for canonical, bounded values. */
int axi_replay_v4_binding_verify(const axi_replay_v4_binding *binding);
int axi_replay_v4_terminal_verify(const axi_replay_v4_terminal *terminal);

/* Caller-owned outputs are changed only on success.  decode_trusted verifies
 * framing, explicit recorder trust, and the signature before parsing the body,
 * then requires the decoded binding to equal expected byte-for-byte by field. */
int axi_replay_v4_encode_signed(const axi_replay_v4_binding *binding,
                                const axi_replay *effects,
                                const axi_replay_v4_terminal *terminal,
                                const uint8_t recorder_seed[32],
                                uint8_t **out, size_t *out_len);
/* On success the returned buffer is owned by account. Pair it with
 * axi_replay_v4_buffer_release(account, buffer); NULL selects legacy malloc. */
int axi_replay_v4_encode_signed_accounted(
    const axi_replay_v4_binding *binding,
    const axi_replay *effects,
    const axi_replay_v4_terminal *terminal,
    const uint8_t recorder_seed[32],
    axi_mem_account *account,
    uint8_t **out, size_t *out_len);
int axi_replay_v4_buffer_release(axi_mem_account *account, uint8_t *buffer);
int axi_replay_v4_decode_trusted(axi_replay_v4_episode *out,
                                 const uint8_t *bytes, size_t len,
                                 const axi_replay_v4_binding *expected,
                                 const uint8_t recorder_pk[32]);
/* Decoded effect records use account and are released by episode_free. The
 * account must outlive the episode; NULL selects the legacy path. */
int axi_replay_v4_decode_trusted_accounted(
    axi_replay_v4_episode *out,
    const uint8_t *bytes, size_t len,
    const axi_replay_v4_binding *expected,
    const uint8_t recorder_pk[32],
    axi_mem_account *account);

/* INV-428 / AXI-INV-138: the v7 route never accepts artifact identity copied
 * into a caller-built binding. It admits the exact signed AXB v7 first, then
 * derives body, producer, cell and contract hashes. Outputs are fail-atomic. */
int axi_replay_v4_binding_from_signed_v7(
    axi_replay_v4_binding *out,
    const uint8_t *artifact, size_t artifact_len,
    const uint8_t producer_pk[32],
    const axi_replay_v4_invocation *invocation);
/* These adapters consume a model already returned by trusted v7 admission.
 * producer_pk remains an external trust anchor and must match body.sig_pk;
 * the model must remain alive for the duration of the call. They do not decode
 * or authenticate artifact bytes a second time. */
int axi_replay_v4_binding_from_admitted_v7(
    axi_replay_v4_binding *out,
    const axb_contract_mod *model,
    const uint8_t producer_pk[32],
    const axi_replay_v4_invocation *invocation);
int axi_replay_v4_binding_from_admitted_v7_accounted(
    axi_replay_v4_binding *out,
    const axb_contract_mod *model,
    const uint8_t producer_pk[32],
    const axi_replay_v4_invocation *invocation,
    axi_mem_account *account);
int axi_replay_v4_decode_signed_v7_trusted(
    axi_replay_v4_episode *out,
    const uint8_t *bytes, size_t len,
    const uint8_t *artifact, size_t artifact_len,
    const uint8_t producer_pk[32],
    const axi_replay_v4_invocation *invocation,
    const uint8_t recorder_pk[32]);
int axi_replay_v4_decode_admitted_v7_trusted(
    axi_replay_v4_episode *out,
    const uint8_t *bytes, size_t len,
    const axb_contract_mod *model,
    const uint8_t producer_pk[32],
    const axi_replay_v4_invocation *invocation,
    const uint8_t recorder_pk[32]);
int axi_replay_v4_decode_admitted_v7_trusted_accounted(
    axi_replay_v4_episode *out,
    const uint8_t *bytes, size_t len,
    const axb_contract_mod *model,
    const uint8_t producer_pk[32],
    const axi_replay_v4_invocation *invocation,
    const uint8_t recorder_pk[32],
    axi_mem_account *account);

#endif /* AXI_REPLAY_V4_H */
