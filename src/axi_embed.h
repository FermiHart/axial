/* axial — embed API for hosts (M4). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * Hosts (jash) load a sealed module once and evaluate its `decide` cell many
 * times. This surface hides the VM internals while preserving the axial
 * guarantees: fuel ceiling, cap grants, deterministic eval.
 */
#ifndef AXI_EMBED_H
#define AXI_EMBED_H

#include <stdint.h>
#include <stddef.h>
#include "axi_bc.h"
#include "axi_builtin.h"
#include "axi_contract.h"
#include "axi_effect.h"
#include "axi.h"

typedef struct axi_vm_ctx axi_vm_ctx;
typedef struct axi_vm_ctx axi_vm_v7_ctx;

/* Diagnostic ownership: the caller owns `diags`, initializes it with
 * axi_diags_init(), and may reuse it after the call. Embed functions append
 * fixed-size cells and never retain pointers into the diagnostic set. */

/* Load a signed module from bytes and create a VM context. trusted_pk is the
 * host-configured trust anchor, never a key learned from the module. Unsigned,
 * invalidly signed and foreign-key modules return NULL. */
axi_vm_ctx *axi_vm_create(const uint8_t *module_bytes, size_t len,
                          const uint8_t trusted_pk[32],
                          const axi_grants *grants, void *sink,
                          axi_diags *diags);

/* Tear down a context and free all associated state. */
void axi_vm_destroy(axi_vm_ctx *ctx);

/* Evaluate a policy verdict cell by name with a JSON string argument.
 *
 * Returns:
 *   0  = cell returned bool true (allow); *output_json is "true"
 *   1  = cell returned bool false (deny); *output_json is "false"
 *   -1 = trap (fuel exhaustion, cap violation, non-bool result, etc.)
 *
 * Refusal leaves output_json, output_len and fuel_used unchanged. A -1 return
 * appends a typed diagnostic when `diags` is non-NULL.
 */
int axi_vm_eval(axi_vm_ctx *ctx, const char *cell_name,
                const char *input_json, size_t input_len,
                char **output_json, size_t *output_len,
                uint64_t *fuel_used, axi_diags *diags);

/* Inspect a trusted signed-v7 module without running it. trusted_pk is an
 * external host trust anchor. Success writes a malloc-owned JSON metadata blob;
 * refusal leaves both outputs unchanged. */
int axi_vm_inspect(const uint8_t *module_bytes, size_t len,
                   const uint8_t trusted_pk[32],
                   char **meta_json, size_t *meta_len, axi_diags *diags);

/* Isolated AXB v7 embed door. Admission requires an AXBS signature rooted in
 * the host-provided trusted_pk; no key is learned from the artifact. */
typedef struct axi_vm_v7_invocation axi_vm_v7_invocation;

/* Success publishes a new context through out. Refusal, including OOM, leaves
 * caller-owned state unchanged. Grants are snapshotted; NULL means empty. */
int axi_vm_v7_create_trusted(const uint8_t *module_bytes, size_t len,
                             const uint8_t trusted_pk[32],
                             const axi_grants *grants, void *sink,
                             axi_vm_v7_ctx **out, axi_diags *diags);
void axi_vm_v7_destroy(axi_vm_v7_ctx *ctx);

/* Each invocation is model-bound and one-shot. CAPs minted by one invocation
 * are invalid in every other invocation, including another context/model. */
int axi_vm_v7_invocation_create(const axi_vm_v7_ctx *ctx,
                                axi_vm_v7_invocation **out,
                                axi_diags *diags);
int axi_vm_v7_invocation_cap(const axi_vm_v7_invocation *inv,
                             const char *atom, axi_vval *out,
                             axi_diags *diags);
int axi_vm_v7_invocation_eval(axi_vm_v7_invocation *inv,
                              const char *cell_name,
                              const uint8_t expected_iface_hash[32],
                              const axi_vval *args, uint8_t argc,
                              axi_vval *out, uint64_t fuel_budget,
                              uint64_t *fuel_used, axi_diags *diags);
/* Borrowed payloads remain valid only while invocation and context live. */
void axi_vm_v7_invocation_destroy(axi_vm_v7_invocation *inv);

/* Convenience evaluation consumes a fresh invocation. CAP parameters require
 * the explicit lifecycle above. Since the invocation dies before return, only
 * pointer-free values are published; use explicit lifecycle for borrowed
 * str/bytes/error results. Refusal leaves out and fuel_used unchanged. */
int axi_vm_v7_eval(axi_vm_v7_ctx *ctx, const char *cell_name,
                   const uint8_t expected_iface_hash[32],
                   const axi_vval *args, uint8_t argc,
                   axi_vval *out, uint64_t fuel_budget,
                   uint64_t *fuel_used, axi_diags *diags);

/* Trusted inspection never executes the model. The successful text output is
 * malloc-owned by the caller; refusal leaves both outputs unchanged. */
int axi_vm_v7_inspect_trusted(const uint8_t *module_bytes, size_t len,
                              const uint8_t trusted_pk[32],
                              char **contract_text, size_t *contract_len,
                              axi_diags *diags);

#endif /* AXI_EMBED_H */
