/* axial — capability inference engine (ADR-007). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * Infers required capabilities from cell body AST.
 * Walks the AST and collects all effectful operations.
 */
#ifndef AXI_CAP_INFER_H
#define AXI_CAP_INFER_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "axi_ast.h"
#include "axi_cap_table.h"

#define AXI_INFERRED_CAP_MAX 32

typedef struct {
    axi_cap_kind caps[AXI_INFERRED_CAP_MAX];
    const axi_node *sites[AXI_INFERRED_CAP_MAX]; /* first use site per cap */
    int n;
} axi_cap_set;

/* Cap parameter binding passed to the inferencer */
typedef struct {
    const char *name;
    size_t namelen;
    axi_cap_kind kind;
} axi_cap_binding;

typedef struct {
    const axi_cap_binding *bindings;
    int nbindings;
} axi_cap_infer_env;

typedef struct {
    axi_cap_set caps;
    axi_cap_set uses;  /* same as caps in v0: 1:1 mapping */
    int pure;          /* 1 if inferred_pure (no caps) */
} axi_cap_infer_result;

/* Initialize empty result */
void axi_cap_infer_init(axi_cap_infer_result *r);

/* Main inference entry point: walk cell body AST and populate result.
 * env->bindings maps cap parameter names to kinds; pass NULL/0 if none.
 * Returns 0 on success, -1 on error (diags populated). */
int axi_cap_infer(const axi_node *cell_body, const axi_cap_infer_env *env,
                  axi_diags *ds, axi_cap_infer_result *out);

/* Utility: add a capability to set (deduplicated) */
int axi_cap_set_add(axi_cap_set *s, axi_cap_kind k, const axi_node *site);

/* Utility: merge two cap sets (s1 |= s2) */
void axi_cap_set_merge(axi_cap_set *s1, const axi_cap_set *s2);

/* Utility: check if cap set is empty */
int axi_cap_set_empty(const axi_cap_set *s);

/* Utility: test membership */
int axi_cap_set_has(const axi_cap_set *s, axi_cap_kind k);

/* Print cap set for debugging */
void axi_cap_set_print(const axi_cap_set *s, FILE *out);

#endif /* AXI_CAP_INFER_H */