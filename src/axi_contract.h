/* axial - production AXS contract-v1 profile for CA16/CA17/CA18.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * Writer, loader and runtime preserve this model as one signed AXB v7 body.
 * CA17 derivation and CA18 checked-seal identities remain separate from root.
 */
#ifndef AXI_CONTRACT_H
#define AXI_CONTRACT_H

#include "axi_arena.h"
#include "axi_bc.h"

#define AXB_CONTRACT_VERSION AXB_VERSION
#define AXB_CONTRACT_MAX_BYTES (1024u * 1024u)
#define AXPC_MAGIC "AXPC"
#define AXPC_VERSION 1u
#define AXPC_MATURITY_CHECKED 1u
#define AXPC_RESULT_BOOL 4u
#define AXPC_VERDICT_TRUE 1u
#define AXPC_MAX_BYTES (16u * 1024u)
#define AXPC_MAX_LAWS 64u
#define AXPC_MAX_AGGREGATE_FUEL 1000000ull
#define AXPC_FIXED_BYTES 128u

typedef struct {
    uint8_t src_hash[32];
    uint8_t ir_hash[32];
    uint8_t compiler_hash[32];
    uint8_t body_hash[32];
} axb_derivation;

typedef struct {
    uint32_t cell_index;
    axb_mstr name;
    uint8_t iface_hash[32];
    uint8_t body_hash[32];
    uint64_t budget;
    uint64_t fuel_used;
    uint32_t result_kind;
    uint32_t verdict;
} axb_seal_law;

typedef struct {
    int present;
    uint32_t version;
    uint32_t maturity;
    uint8_t subject_root[32];
    uint8_t checker_protocol_id[32];
    uint8_t checker_semantics_root[32];
    uint64_t aggregate_budget;
    uint64_t aggregate_fuel_used;
    uint32_t law_count;
    axb_seal_law laws[AXPC_MAX_LAWS];
} axb_seal_certificate;

typedef struct {
    axb_derivation derivation;
    axb_seal_certificate seal;
    axb_mod body;
    axb_manifest *manifest; /* parallel to body.cells */
    uint32_t nmanifest;
    axi_arena arena;
    int body_arena_owned;
} axb_contract_mod;

int axb_contract_v1_parse(const char *src, size_t len,
                          axb_contract_mod *out);
char *axb_contract_v1_render(const axb_contract_mod *m, size_t *out_len);
int axb_contract_v1_verify(const axb_contract_mod *m);
int axb_contract_v1_verify_accounted(const axb_contract_mod *m,
                                     axi_mem_account *account);
/* Exact v7 codecs. Caller-owned outputs remain unchanged on refusal. */
int axb_contract_v7_encode(const axb_contract_mod *m,
                           uint8_t **out, size_t *out_len);
int axb_contract_v7_decode(axb_contract_mod *out,
                           const uint8_t *bytes, size_t len);
/* A non-NULL account must outlive the successfully decoded model. */
int axb_contract_v7_decode_accounted(axb_contract_mod *out,
                                     const uint8_t *bytes, size_t len,
                                     axi_mem_account *account);
int axb_contract_v7_encode_signed(const axb_contract_mod *m,
                                  const uint8_t seed[32],
                                  uint8_t **out, size_t *out_len);
int axb_contract_v7_decode_trusted(axb_contract_mod *out,
                                   const uint8_t *bytes, size_t len,
                                   const uint8_t trusted_pk[32]);
int axb_contract_v7_decode_trusted_accounted(
    axb_contract_mod *out, const uint8_t *bytes, size_t len,
    const uint8_t trusted_pk[32], axi_mem_account *account);
int axb_contract_v7_write_signed(const axb_contract_mod *m,
                                 const uint8_t seed[32], const char *path);
int axb_contract_v7_load_trusted(axb_contract_mod *out, const char *path,
                                 const uint8_t trusted_pk[32]);
/* Read, authenticate and decode one immutable path snapshot. All caller-owned
 * outputs remain unchanged on refusal. */
int axb_contract_v7_load_trusted_snapshot(
    axb_contract_mod *out, uint8_t **snapshot, size_t *snapshot_len,
    const char *path, const uint8_t trusted_pk[32]);
/* Account must outlive the returned model and snapshot. Release an accounted
 * snapshot with axi_mem_free(account, snapshot); legacy snapshots use free(). */
int axb_contract_v7_load_trusted_snapshot_accounted(
    axb_contract_mod *out, uint8_t **snapshot, size_t *snapshot_len,
    const char *path, const uint8_t trusted_pk[32],
    axi_mem_account *account);
void axb_checker_protocol_id(uint8_t out[32]);
void axb_checker_semantics_root(uint8_t out[32]);
int axb_contract_seal_subject_root(const axb_contract_mod *m, uint8_t out[32]);
int axb_contract_seal_subject_root_accounted(const axb_contract_mod *m,
                                              uint8_t out[32],
                                              axi_mem_account *account);
int axb_contract_seal_verify(const axb_contract_mod *m, int execute);
int axb_contract_seal_verify_accounted(const axb_contract_mod *m, int execute,
                                        axi_mem_account *account);
int axb_contract_v1_write_signed_text(const char *src, size_t len,
                                      const char *source_path,
                                      const char *out_path,
                                      const char *signing_key_path);
int cmd_asm_contract_signed(const char *in, const char *out_path,
                             const char *signing_key_path);
int cmd_migrate_contract_v5(const char *legacy_path, const char *source_path,
                            const char *out_path,
                            const char *signing_key_path);
int cmd_seal_contract_signed(const char *in, const char *out_path,
                             const char *signing_key_path);
int cmd_dis_contract_trusted(const char *path, const char *trusted_key_path);
int cmd_inspect_contract_trusted(const char *path,
                                 const char *trusted_key_path);
int cmd_verify_contract_trusted(const char *path,
                                const char *trusted_key_path);
int cmd_check_seal_contract_trusted(const char *path,
                                    const char *trusted_key_path);
int cmd_bind_contract_trusted(const char *path, const char *source_path,
                              const char *trusted_key_path);
void axb_contract_mod_free(axb_contract_mod *m);

#endif /* AXI_CONTRACT_H */
