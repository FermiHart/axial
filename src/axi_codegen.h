/* axial — minimal axial source → .axs codegen (M3). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * v0 scope: enough to compile a policy cell that uses json.get,
 * fs.path_under, simple arithmetic and if/ret.
 */
#ifndef AXI_CODEGEN_H
#define AXI_CODEGEN_H

#include <stddef.h>
#include "axi_ast.h"

/* Generate canonical .axs assembly text from a parse-green, type-green unit.
 * Caller frees the returned string. *out_len is set to strlen (without NUL). */
char *axi_codegen(const axi_node *unit, size_t *out_len);
/* Isolated CA16 profile. The normal compile path remains legacy AXS/AXB v5. */
char *axi_codegen_contract_v1(const axi_node *unit, size_t *out_len);

#endif /* AXI_CODEGEN_H */
