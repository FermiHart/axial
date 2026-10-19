/* axial — register VM public surface (M4 embed API). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 */
#ifndef AXI_VM_H
#define AXI_VM_H

#include "axi_bc.h"
#include "axi_builtin.h"
#include "axi_contract.h"
#include "axi_effect.h"

/* Exact run_contract_cell_diag_for_invocation public-to-private window. */
#define AXI_VM_INVOCATION_ARGS_SCRATCH_BYTES 1408u

/* Run one cell with the given arguments. Returns 1 on a value, 0 on trap.
 * *fuel_used is written with the spent fuel. */
int axi_vm_run_cell(const axb_mod *m, uint32_t ci,
                    const axi_vval *args, uint8_t argc,
                    axi_vval *out, uint64_t fuel_budget,
                     uint64_t *fuel_used,
                     const axi_grants *grants, void *sink);
int axi_vm_run_cell_diag(const axb_mod *m, uint32_t ci,
                         const axi_vval *args, uint8_t argc,
                         axi_vval *out, uint64_t fuel_budget,
                         uint64_t *fuel_used,
                          const axi_grants *grants, void *sink,
                          axi_diags *diags);
/* INV-389 / AXI-INV-128: the common production runtime door consumes the
 * complete model produced by exact trusted-v7 admission. */
int axi_vm_run_contract_cell_diag(const axb_contract_mod *m, uint32_t ci,
                                  const axi_vval *args, uint8_t argc,
                                  axi_vval *out, uint64_t fuel_budget,
                                  uint64_t *fuel_used,
                                   const axi_grants *grants, void *sink,
                                   axi_diags *diags);
/* AX30: internal source ABI, NOT the ratified public embed-v1 header.
 * One owner retains decoded results until copy-out or invocation destruction.
 * Initialize to zero. Borrowed input/model bytes still require their owner.
 * Direct legacy VM doors refuse escaping computed bytes without an owner. */
typedef struct axi_vm_output_storage {
    char *bytes;
    axi_mem_account *account;
} axi_vm_output_storage;
void axi_vm_output_storage_release(axi_vm_output_storage *storage);
int axi_vm_run_contract_cell_preverified_pure_scoped_diag(
    const axb_contract_mod *m, uint32_t ci,
    const axi_vval *args, uint8_t argc, axi_vval *out,
    uint64_t fuel_budget, uint64_t *fuel_used, int *fuel_exhausted,
    axi_diags *diags, axi_vm_output_storage *storage);

/* CA19 private door: context creation already verified immutable pure state.
 * It preserves an exact zero budget and performs no model-verifier allocation. */
int axi_vm_run_contract_cell_preverified_pure_diag(
    const axb_contract_mod *m, uint32_t ci,
    const axi_vval *args, uint8_t argc, axi_vval *out,
    uint64_t fuel_budget, uint64_t *fuel_used, int *fuel_exhausted,
    axi_diags *diags);
/* CA21 internal staging door. It is not part of either public embed ABI. */
int axi_vm_run_contract_cell_preverified_accounted_diag(
    const axb_contract_mod *m, uint32_t ci,
    const axi_vval *args, uint8_t argc, axi_vval *out,
    uint64_t fuel_budget, uint64_t *fuel_used, int *fuel_exhausted,
    axi_diags *diags, axi_mem_account *mem_account);
int cmd_run_contract_trusted(const char *path, const char *cell,
                             const char *trusted_key_path,
                             int argc, char **argv);
int cmd_replay_contract_trusted(const char *replay_path, const char *path,
                                const char *cell,
                                const char *trusted_key_path,
                                const char *recorder_key_path,
                                int argc, char **argv);
/* Render one manifest-admitted result without publishing partial bytes.
 * Caller owns *out on success; outputs remain unchanged on refusal. */
int axi_vm_contract_result_cli_render(const axb_manifest *manifest,
                                       const axi_vval *value,
                                       char **out, size_t *out_len);
/* On accounted success, *out is owned by account and must be released with
 * axi_mem_free(account, *out). A NULL account preserves legacy ownership. */
int axi_vm_contract_result_cli_render_accounted(
    const axb_manifest *manifest, const axi_vval *value,
    axi_mem_account *account, char **out, size_t *out_len);

/* Internal CA21 manifest probe. These are source ABI only, not embed-v1.
 * fixed_charge is the single retained reservation for options plus command. */
typedef struct axi_vm_cli_account_manifest {
    size_t options;
    size_t command;
    size_t fixed_charge;
    size_t json_scratch;
} axi_vm_cli_account_manifest;
int axi_vm_cli_account_manifest_probe(int replay,
                                      axi_vm_cli_account_manifest *out);

/* AXI-INV-129: CAP values belong to one model-bound, one-shot invocation.
 * create snapshots model+grants. Concurrent runs may race for the one winner;
 * callers must join every cap/run operation before destroy (normal C lifetime). */
typedef struct axi_vm_contract_invocation axi_vm_contract_invocation;
int axi_vm_contract_invocation_create(const axb_contract_mod *m,
                                      const axi_grants *grants,
                                      axi_vm_contract_invocation **out);
int axi_vm_contract_invocation_cap(const axi_vm_contract_invocation *inv,
                                   const char *atom, axi_vval *out);
int axi_vm_contract_invocation_run_diag(axi_vm_contract_invocation *inv,
                                        uint32_t ci,
                                        const axi_vval *args, uint8_t argc,
                                        axi_vval *out, uint64_t fuel_budget,
                                        uint64_t *fuel_used, void *sink,
                                        axi_diags *diags);
void axi_vm_contract_invocation_destroy(axi_vm_contract_invocation *inv);

#endif /* AXI_VM_H */
