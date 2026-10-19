/* axial — interface projection (W15). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * A cell's INTERFACE is a projection of its contract: name, positional
 * parameters, return union, error set, capability set, fuel envelope,
 * purity and laws. Nothing about the body. It is derived, never written
 * by hand — a hand-written header is a promise that can lie.
 *
 * Two identities, on purpose (AXI-INV-022):
 *   content hash — changes when ANY byte of the code changes;
 *   interface hash — changes only when the CONTRACT changes.
 * The pair answers, mechanically, the question every agent (and every
 * human) guesses at with semver: "did I break my callers?"
 *
 * Python/Lua cannot answer it at all: importing a module to inspect it
 * RUNS it, and its "interface" is whatever the dict happens to hold at
 * that instant. Here the interface is a pure function of the source and
 * it is comparable byte-for-byte.
 */
#ifndef AXI_IFACE_H
#define AXI_IFACE_H

#include <stdio.h>
#include "axi_ast.h"
#include "axi_bc.h"

struct axi_arena;

/* CA16 producer projection. unit must have passed axi_type_check with zero
 * diagnostics: that pass owns transitive capability closure. Contract facts
 * and iface_hash are derived from the same model as axi_iface_render;
 * body_hash remains zero until bytecode exists. Strings in out are arena-owned. */
int axi_iface_manifest_v1(const axi_node *unit,
                          const char *cell_name, size_t cell_name_len,
                          axb_manifest *out, struct axi_arena *arena);
/* Rederive W15 identity from parsed manifest facts; hashes are never text. */
int axi_manifest_iface_hash_v1(const char *cell_name,
                               const axb_manifest *manifest,
                               uint8_t out[32]);
int axi_manifest_iface_hash_v1_accounted(const char *cell_name,
                                         const axb_manifest *manifest,
                                         uint8_t out[32],
                                         axi_mem_account *account);

/* Canonical interface text of a unit (caller frees). THIS text is the
 * contract; its SHA-256 is the interface identity. */
char *axi_iface_render(const axi_node *unit);

/* Machine projection, same facts, same order (caller frees). */
char *axi_iface_json(const axi_node *unit);

/* Directional verdict: may `nw` replace `old` for every existing caller?
 * Reasons are written to `out` (text or JSON).
 * Returns 0 = identical, 1 = compatible (narrowing), 2 = breaking. */
int axi_iface_diff(const axi_node *old, const axi_node *nw,
                   FILE *out, int json);

#endif /* AXI_IFACE_H */
