/* axial — AXB bytecode format (W08). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * One truth: this table feeds the assembler, the disassembler and the
 * VM (W09). A byte that is not described here does not exist.
 *
 * Container (all little-endian, length-prefixed, zero padding only):
 *   magic  "AXB0"            4 bytes
 *   u32    version           AXB_VERSION
 *   u32    ncells
 *   cell*  ncells entries
 * Cell entry:
 *   u32    name_len, name bytes (no NUL)
 *   u32    manifest_len, exact manifest-v1 bytes
 *   u32    nregs              registers used (<= AXB_MAX_REGS)
 *   u32    nconsts
 *   k*     nconsts entries:   u8 tag (KU64/KI64/KF64/KSTR/KERR),
 *                             u64 payload or u32 len + bytes
 *   u32    ncode              instruction words
 *   word*  ncode * 4 bytes:   op a b c
 *
 * Determinism law (gate-enforced): asm(dis(asm(x))) == asm(x) byte-equal.
 * Fuel column is RESERVED at birth: W10 fills costs, format never moves.
 */
#ifndef AXI_BC_H
#define AXI_BC_H

#include <stdint.h>
#include <stddef.h>
#include "axi_diag.h"
#include "axi_mem_account.h"

#define AXB_MAGIC     "AXB0"
#define AXB_ARCHIVE_VERSION 5u /* offline provenance/migration input only */
#define AXB_PREVIOUS_VERSION 6u /* reassemble from source; never load in prod */
#define AXB_VERSION   7u   /* signed contract + checked-seal production format */
#define AXB_MAX_REGS  256u
#define AXB_MAX_EFF   64u  /* W19: a module's declared authority fits on a screen */
#define AXB_MAX_BUILTIN 64u /* M3: a module's declared builtins fit on a screen */

/* INV-380 / AXI-INV-121: manifest-v1 bytes are frozen and bounded before AXB
 * consumes them. These values are wire IDs, not a C enum. */
#define AXB_MANIFEST_VERSION       1u
#define AXB_MANIFEST_MAX_BYTES     (16u * 1024u)
#define AXB_MANIFEST_MAX_PARAMS    16u
#define AXB_MANIFEST_MAX_RETURNS   16u
#define AXB_MANIFEST_MAX_ERRORS    16u
#define AXB_MANIFEST_MAX_CAPS      64u
#define AXB_MANIFEST_MAX_LAWS      64u
#define AXB_MANIFEST_MAX_NAME      63u
#define AXB_MANIFEST_MAX_LAW       4096u
#define AXB_MANIFEST_FLAG_PURE     1u
#define AXB_MANIFEST_FLAG_POLICY   2u
#define AXB_MANIFEST_FLAG_MASK     3u

#define AXB_MT_U64       1u
#define AXB_MT_I64       2u
#define AXB_MT_F64       3u
#define AXB_MT_BOOL      4u
#define AXB_MT_STR       5u
#define AXB_MT_BYTES     6u
#define AXB_MT_JSON      7u
#define AXB_MT_DECISION  8u
#define AXB_MT_OK        9u
#define AXB_MT_CAP       10u

/*            name    operands            fuel  doc                       */
#define AXB_OPCODES(X) \
    X(NOP,   "nop",   AXB_OPS_NONE,        1, "no operation")              \
    X(LDK,   "ldk",   AXB_OPS_RA_KBC,      1, "ra = consts[bc]")           \
    X(MOV,   "mov",   AXB_OPS_RA_RB,       1, "ra = rb")                   \
    X(ADD,   "add",   AXB_OPS_RA_RB_RC,    1, "ra = rb + rc")              \
    X(SUB,   "sub",   AXB_OPS_RA_RB_RC,    1, "ra = rb - rc")              \
    X(MUL,   "mul",   AXB_OPS_RA_RB_RC,    2, "ra = rb * rc")              \
    X(DIV,   "div",   AXB_OPS_RA_RB_RC,    4, "ra = rb / rc (checked)")    \
    X(MOD,   "mod",   AXB_OPS_RA_RB_RC,    4, "ra = rb % rc (int only)")   \
    X(NOT,   "not",   AXB_OPS_RA_RB,       1, "ra = !rb (bool only)")      \
    X(EQ,    "eq",    AXB_OPS_RA_RB_RC,    1, "ra = rb == rc")             \
    X(LT,    "lt",    AXB_OPS_RA_RB_RC,    1, "ra = rb < rc  /INV-002/")   \
    X(LE,    "le",    AXB_OPS_RA_RB_RC,    1, "ra = rb <= rc /INV-002/")   \
    X(JMP,   "jmp",   AXB_OPS_SBC,         1, "pc += sbc")                 \
    X(JF,    "jf",    AXB_OPS_RA_SBC,      1, "if !ra: pc += sbc")         \
    X(CALL,  "call",  AXB_OPS_RA_CB_IC,    4, "rA=base @cellB argcC; args rA.., result rA")\
    X(RET,   "ret",   AXB_OPS_RA,          1, "return ra")                 \
    X(UMAKE, "umake", AXB_OPS_RA_RB_RC,    1, "ra = union tag rb pay rc")  \
    X(UTAG,  "utag",  AXB_OPS_RA_RB,       1, "ra = tag(rb)")              \
    X(UPAY,  "upay",  AXB_OPS_RA_RB,       1, "ra = payload(rb)")          \
    X(UCHK,  "uchk",  AXB_OPS_RA_RB,       2, "the `?`: tag 0 unwraps to ra, else return rb") \
    X(EFF,   "eff",   AXB_OPS_RA_EB_RC,  100, "rA = eff @effB, payload rC")\
    X(BUILTIN, "builtin", AXB_OPS_RA_BB_RC, 8, "rA = builtin @builtinB, args rC..")\
    X(HALT,  "halt",  AXB_OPS_NONE,        1, "trap: fell off the cell")

typedef enum {
#define X(up, nm, ops, fuel, doc) OP_##up,
    AXB_OPCODES(X)
#undef X
    OP__COUNT
} axb_op;

typedef enum {
    AXB_OPS_NONE,     /* -            */
    AXB_OPS_RA,       /* rA           */
    AXB_OPS_RA_RB,    /* rA rB        */
    AXB_OPS_RA_RB_RC, /* rA rB rC     */
    AXB_OPS_RA_KBC,   /* rA k(b<<8|c) */
    AXB_OPS_RA_SBC,   /* rA ±(b<<8|c) */
    AXB_OPS_SBC,      /* ±(b<<8|c)    */
    AXB_OPS_RA_CB_IC, /* rA @cellB argcC (call window: Lua lesson) */
    AXB_OPS_RA_EB_RC, /* rA @effB rC — B indexes the module's declared
                       * authority, never a computed string: a reviewer can
                       * enumerate what the artifact may do /AXI-INV-036/ */
    AXB_OPS_RA_BB_RC  /* M3: rA @builtinB rC — args live at rC, rC+1, ... */
} axb_ops;

typedef enum { AXB_KU64 = 1, AXB_KI64, AXB_KF64, AXB_KSTR, AXB_KERR } axb_ktag;

typedef enum {
    AXB_COMPAT_UNSUPPORTED = 0,
    AXB_COMPAT_REASSEMBLE = 1,
    AXB_COMPAT_CURRENT = 2
} axb_compat;

/* CA20 support policy. Production loaders still accept CURRENT only. */
axb_compat axb_version_compat(uint32_t version);

typedef struct {
    const char *name;
    axb_ops     ops;
    uint8_t     fuel;   /* reserved column — W10 owns the numbers */
} axb_opinfo;

const axb_opinfo *axb_op_info(uint8_t op);   /* NULL if op >= OP__COUNT */
int axb_op_by_name(const char *nm, size_t len);  /* -1 if unknown */

/* ---- in-memory module (shared by asm/dis and the VM, W09) ----------- */
typedef struct {
    uint8_t  tag;        /* axb_ktag */
    uint64_t u;          /* KU64/KI64/KF64 payload (f64 = raw bits)   */
    char    *s;          /* KSTR/KERR bytes                            */
    uint32_t slen;
} axb_konst;

/* Decoded string pointers are owned by the arena passed to decode and remain
 * valid only until that arena is freed. Caller-built models may borrow bytes. */
typedef struct {
    const char *p;
    uint32_t    len;
} axb_mstr;

typedef struct {
    uint8_t  tag;
    axb_mstr name; /* present only for AXB_MT_CAP */
} axb_mtype;

typedef struct {
    axb_mstr  name;
    axb_mtype type;
} axb_mparam;

typedef struct {
    uint32_t version;
    uint32_t flags;
    uint64_t fuel_max;
    axb_mparam params[AXB_MANIFEST_MAX_PARAMS];
    uint32_t nparams;
    axb_mtype returns[AXB_MANIFEST_MAX_RETURNS];
    uint32_t nreturns;
    axb_mstr errors[AXB_MANIFEST_MAX_ERRORS];
    uint32_t nerrors;
    axb_mstr caps[AXB_MANIFEST_MAX_CAPS];
    uint32_t ncaps;
    axb_mstr laws[AXB_MANIFEST_MAX_LAWS];
    uint32_t nlaws;
    uint8_t iface_hash[32];
    uint8_t body_hash[32];
} axb_manifest;

typedef struct {
    char      *name;
    uint32_t   nregs;
    axb_konst *k;    uint32_t nk;
    uint32_t  *code; uint32_t nc;  /* word = op | a<<8 | b<<16 | c<<24 */
} axb_cell;

typedef struct {
    axb_cell *cells; uint32_t n;
    uint8_t   src_hash[32];   /* W14: SHA-256 of the exact .axs text this
                                 module was assembled from — the binding
                                 that makes bytecode answer "from what?".
                                 NOTE: this is a CLAIM the file makes about
                                 itself. At run time there is no source to
                                 check it against, so it is provenance, never
                                 identity /AXI-INV-062/. */

    /* W22: the root — SHA-256 of the body bytes the loader actually parsed.
     * The loader computes it; no caller may supply it, and no field in the
     * file can state it. This is what a witness (ledger, trace) is rooted in:
     * identity is what ran, not what the artifact says about itself. Excludes
     * the signature trailer, so signing a module does not rename the program
     * — "from whom" and "which program" are different questions. */
    uint8_t   root[32];       /* /AXI-INV-062/ */
    /* W19: the FIRST of two keys. The module names, in its own text, every
     * authority it may ever exercise. The host holds the second key (--cap).
     * A name absent here cannot be reached at runtime: no ambient authority,
     * and `axi iface` can print the whole list without running anything. */
    char     *eff[AXB_MAX_EFF]; uint32_t neff;

    /* M3: the module also names every builtin it may call. A builtin absent
     * here cannot be reached, and the runtime checks the corresponding cap. */
    char     *builtin[AXB_MAX_BUILTIN]; uint32_t nbuiltin;

    /* W21: `has_sig` is 0 or 1 — there is no "partly signed". body_len is where
     * the module ends and the trailer begins; it is what the signature covers,
     * so it is recorded rather than recomputed. Production admission requires
     * exactly one trusted trailer. Unsigned state exists only while building a
     * model or exercising an isolated development codec.
     *
     * Vocabulary (AXI-INV-041): in axial, `seal` means W12's prove-then-emit
     * — a cell does not seal without a green proof. Signing is a different
     * act by a different actor, so it gets a different word. One word, one
     * meaning; `axi seal` proves, `axi sign` attributes. */
    int       has_sig;
    size_t    body_len;
    uint8_t   sig_pk[32];
    uint8_t   sig_sig[64];
    axi_mem_account *builder_account; /* Private builder ownership, never serialized. */
} axb_mod;

int axb_mod_eff_index(const axb_mod *m, const char *name);  /* -1 if undeclared */
int axb_mod_builtin_index(const axb_mod *m, const char *name); /* -1 if undeclared */

struct axi_arena;                                  /* W11: see axi_arena.h */
/* Manifest-v1 is embedded in every production AXB cell. */
int  axb_manifest_v1_verify(const axb_manifest *m);
int  axb_manifest_v1_encode(const axb_manifest *m, uint8_t *out, size_t cap,
                            size_t *out_len);
/* On success all string pointers in out are arena-owned. On failure out is
 * zeroed, though the arena may retain allocations until its normal teardown. */
int  axb_manifest_v1_decode(axb_manifest *out, const uint8_t *bytes, size_t len,
                            struct axi_arena *arena);
/* CA16 phase 3: one canonical cell encoder feeds cell body identity. */
int  axb_cell_body_hash_v1(const axb_cell *cell, uint8_t out[32]);
int  axb_cell_body_hash_v1_accounted(const axb_cell *cell, uint8_t out[32],
                                      axi_mem_account *account);
char *axb_mod_dis_text(const axb_mod *m, size_t *out_len);
char *axb_mod_dis_text_bounded(const axb_mod *m, size_t max, size_t *out_len);
/* Account-owned results must be released with axi_mem_free(account, result).
 * A NULL account selects the legacy malloc/free ownership class. */
char *axb_mod_dis_text_bounded_accounted(const axb_mod *m, size_t max,
                                         size_t *out_len,
                                         axi_mem_account *account);
int  axb_mod_read(axb_mod *m, const uint8_t *p, size_t len, const char *path, struct axi_arena *ar);
int  axb_mod_read_diag(axb_mod *m, const uint8_t *p, size_t len,
                       const char *path, struct axi_arena *ar,
                       axi_diags *diags);
int  axb_mod_verify(const axb_mod *m, const char *path, axi_diags *diags);
int axb_asm_text_accounted(const char *src, size_t n, const char *path,
                            axb_mod *m, axi_mem_account *account);
void axb_mod_free(axb_mod *m);                     /* builder modules only */
int  axb_mod_load(axb_mod *m, const char *path, struct axi_arena *ar);

/* AXI-CA17: stable compiler identity and executable-body provenance. This hash
 * uses the frozen AXB v5 executable framing and is intentionally distinct from
 * axb_mod.root, which is the exact unsigned production container identity. */
void axb_compiler_hash(uint8_t out[32]);
void axb_artifact_abi_id(uint8_t out[32]);
int  axb_mod_body_hash(const axb_mod *m, uint8_t out[32]);
int  axb_mod_body_hash_accounted(const axb_mod *m, uint8_t out[32],
                                  axi_mem_account *account);
/* CA20 migration identity excludes source provenance and manifests, but binds
 * every executable cell, constant, opcode, declared effect and builtin. */
int  axb_mod_semantic_hash_v1(const axb_mod *m, uint8_t out[32]);

/* Archival v5 writer retained for migration fixtures; production writers use
 * axb_contract_v7_write_signed(). */
int  axb_mod_write(const axb_mod *m, const char *path);
/* Publish complete artifact bytes through the shared temp/fsync/rename door.
 * This is also used by signed replay evidence. */
int  axb_atomic_publish_bytes(const uint8_t *bytes, size_t len,
                               const char *path);
typedef enum {
    AXB_PUBLISH_NOT_COMMITTED = 0,
    AXB_PUBLISH_COMMITTED = 1,
    AXB_PUBLISH_COMMIT_AMBIGUOUS = 2,
    AXB_PUBLISH_CONFLICT = 3
} axb_publish_state;
typedef struct {
    axb_publish_state state;
    uint8_t intended_root[32];
    uint8_t predecessor_root[32];
    int had_predecessor;
} axb_publish_result;
int  axb_atomic_publish_bytes_result(const uint8_t *bytes, size_t len,
                                     const char *path,
                                     axb_publish_result *result);
int  axb_atomic_recover_bytes(const uint8_t *bytes, size_t len,
                              const char *path,
                              const axb_publish_result *previous,
                              axb_publish_state *state);
int  axb_atomic_publish_bytes_accounted(const uint8_t *bytes, size_t len,
                                        const char *path,
                                        axi_mem_account *account);

/* W12: assemble .axs TEXT into a builder module (the one door; cmd_asm
 * and the seal runner share it). 0 = ok; diags went to stderr. */
int  axb_asm_text(const char *src, size_t n, const char *path, axb_mod *m);

int cmd_bind(const char *mod_path, const char *src_path);

/* W12: run a zero-arg law cell to a verdict on the SAME VM as everything
 * else. Returns 0 = ran to a value (*is_true says whether it is bool true),
 * 1 = trapped (AXI-R diag already on stderr), 2 = no such cell. */
int  axi_vm_prove(const axb_mod *m, const char *cell, uint64_t fuel,
                  int *is_true);

#endif /* AXI_BC_H */
