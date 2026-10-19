/* axial — policy builtins runtime (M3). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * Builtins are deterministic policy computations called through OP_BUILTIN.
 * They may classify a policy capability, but they never touch the host; every
 * world-facing operation belongs to OP_EFF. In particular, fs.path_under is a
 * lexical predicate, not proof of filesystem/symlink containment. AXI-INV-077.
 */
#ifndef AXI_BUILTIN_H
#define AXI_BUILTIN_H

#include <stddef.h>
#include <stdint.h>
#include "axi_bc.h"
#include "axi_cap_table.h"

#ifndef AXI_CAPNAME
#define AXI_CAPNAME 64
#endif

/* Value kind shared with the VM. */
/* INV-419 / AXI-INV-129: public values name CAP and tagged returns instead of
 * relying on enum casts or scalar arm guessing. */
typedef enum {
    VB_UNIT, VB_U64, VB_I64, VB_F64, VB_BOOL, VB_STR, VB_BYTES, VB_ERR,
    VB_CAP, VB_UNION
} axi_vkind;

#define AXI_ERROR_PAYLOAD_MAX 65536u

typedef struct {
    axi_vkind kind;
    uint8_t tag;       /* VB_UNION: zero-based manifest return arm */
    axi_vkind payload_kind; /* VB_UNION payload; nested unions are refused */
    uint32_t cap_slot;       /* VB_CAP: invocation-local grant slot */
    uint64_t cap_generation; /* VB_CAP: one-shot invocation generation */
    uint8_t cap_proof[32];   /* VB_CAP: invocation-secret-bound authenticator */
    char cap_atom[AXI_CAPNAME]; /* VB_CAP: inline atom survives value copies */
    uint64_t bits;   /* u64/i64/f64 raw bits */
    const char *s;   /* str/bytes/error payload (borrowed or arena-owned) */
    uint32_t slen;
    const char *atom; /* VB_ERR canonical atom; CAP uses cap_atom inline */
    uint32_t atom_len;
} axi_vval;

/* Builtin metadata. */
typedef struct {
    const char *name;
    int arity;
    axi_cap_kind cap;   /* CAP_NONE for pure builtins (e.g. json.get) */
    const char *cap_name; /* host-facing cap name for grant check */
} axi_builtin_info;

const axi_builtin_info *axi_builtin_lookup(const char *name, size_t len);

/* Internal CA21 manifest probe. Pure builtins return zero unless their
 * invocation uses large automatic scratch. */
int axi_builtin_scratch_bytes(const char *name, size_t len, size_t *bytes);

/* Execute a builtin. args[0..arity-1] are inputs; out is written on success.
 * Returns 0 on success, -1 on failure with *errmsg set. */
int axi_builtin_exec(const char *name, const axi_vval *args, int arity,
                     axi_vval *out, const char **errmsg,
                     char *json_scratch, size_t json_scratch_cap);

#endif /* AXI_BUILTIN_H */
