/* axial — register VM core (W09). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * Determinism doctrine:
 *   - registers are born zeroed (UNIT); caller garbage never leaks into
 *     a callee frame — the call window copies argc values, nothing else;
 *   - every wrong move is a trap AXI-R0xx with a fix, never UB: adding
 *     a bool to a str is a diagnostic, not a nasal demon;
 *   - u64/i64 wrap (computed unsigned, INV-002); div-by-zero traps;
 *   - eff (W19) opens four locks in order — declared, granted, done, filed —
 *     and a run with no --cap is a pure run: the world is opt-in, always.
 *   - fuel (W10): every op charges its table cost against a budget
 *     (default 1_000_000, --fuel N). Exhaustion is a VERDICT (AXI-R008),
 *     not a crash — deterministic by construction, sealed by golden.
 */
#include "axi_bc.h"
#include "axi_vm.h"
#include "axi_alloc.h"
#include "axi_arena.h"
#include "axi_aer1.h"
#include "axi_mem_account.h"
#include "axi_trace.h"
#include "axi_u64.h"
#include "axi_effect.h"
#include "axi_builtin.h"
#include "axi_contract.h"
#include "axi_coverage_v1.h"
#include "axi_hash.h"
#include "axi_json.h"
#include "axi_replay.h"
#include "axi_replay_v4.h"
#include "axi_sign.h"
#include "axi_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "axi_osif.h"   /* AXI-INV-064: one door for the streams */

enum {
    VK_UNIT, VK_U64, VK_I64, VK_F64, VK_BOOL, VK_STR, VK_ERR, VK_UNION,
    VK_BYTES, VK_CAP
};
typedef struct {
    uint8_t  kind;    /* VK_* */
    uint8_t  aux;     /* union tag */
    /* INV-322 / AXI-INV-104: a union carries the payload's KIND too —
     * without it, upay cannot return str bytes as str. */
    uint8_t  pay_kind;
    uint32_t cap_slot;
    uint64_t cap_generation;
    uint8_t cap_proof[32];
    uint64_t bits;    /* scalar payload / f64 raw bits */
    const char *s;    /* VK_STR/VK_ERR bytes (borrowed or const table) */
    uint32_t slen;
    const char *atom;
    uint32_t atom_len;
} vval;
typedef char vm_invocation_args_scratch_probe[
    sizeof(vval[16]) == AXI_VM_INVOCATION_ARGS_SCRATCH_BYTES ? 1 : -1];

#define VM_FUEL_DEFAULT 1000000u     /* fail-closed: a budget always exists */
#define VM_MEM_DEFAULT  (1u << 20)   /* W11: memory is budgeted like fuel */
#define VM_EFFECT_CALLS_DEFAULT 1024u
#define VM_EFFECT_BYTES_DEFAULT (16u << 20)
#define VM_EFFECT_HANDLES_DEFAULT 64u
#define VM_EFFECT_CHILDREN_DEFAULT 64u
#define VM_DEADLINE_NS_DEFAULT 30000000000ull
/* CA13: the VM includes only the runtime-safe axi_diag.h (through axi_bc.h),
 * not the compiler front end. One width is now shared instead of restated. */
#define VM_MAX_DEPTH    256          /* call depth: deterministic wall */

typedef struct {
    const axb_mod *m;
    const axb_manifest *manifest; /* NULL keeps the production v5 semantics. */
    const char *mod_path;      /* needed by proc.Spawn to re-exec the module */
    const char *trusted_key_path; /* explicit trust inherited by proc.Spawn */
    uint64_t fuel_budget;
    uint64_t fuel_used;
    int trapped;
    axi_trace *tr;    /* W17: NULL = off; a witness costs nothing unasked */
    /* W19 — the effect plane. All three are NULL for a pure run, and a pure
     * run is the default: an interpreter that can reach the world by default
     * has already lost the argument. A NULL grant set is not "no policy", it
     * is the empty policy, and the empty policy refuses everything. */
    const axi_grants *grants;   /* what the OPERATOR authorised (--cap)     */
    uint64_t cap_generation;    /* one model-bound invocation generation     */
    const uint8_t *cap_secret;  /* NULL outside the one-shot invocation API  */
    axi_ledger      *led;       /* where every effect that HAPPENED is filed */
    axi_effect_journal *journal;/* honest PREPARED/ATTEMPTED/terminal states */
    void            *sink;      /* the world's handle (FILE* for io.Write)   */
    /* MOAT-4 — deterministic replay. NULL = off. When set, host effects are
     * either recorded or mocked, never real. */
    axi_replay      *replay;
    axi_diags       *diags;    /* embed sink; NULL keeps CLI stderr rendering */
    axi_mem_account *mem_account;
    axi_resource_envelope *resources;
    vval            *reg_slab;
    size_t           reg_slab_count;
    size_t           reg_slab_used;
    int              json_scratch_reserved;
    char            *json_scratch; /* INV-704: owned per context, no TLS */
    size_t           json_used; /* AX30: decoded values never overwrite live predecessors */
} vm;

typedef struct {
    const axb_cell *cell;
    uint64_t frame_ceiling;
    int local_fuel_limit;
    uint32_t nregs;
} vm_frame;

struct axi_vm_contract_invocation {
    axb_contract_mod owned_model;
    const axb_contract_mod *model;
    axi_grants grants;
    uint8_t secret[32];
    uint64_t generation;
    uint32_t consumed;
    axi_mem_account *account;
    axi_vm_output_storage output_storage;
};

static void secure_zero(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

void axi_vm_output_storage_release(axi_vm_output_storage *storage)
{
    if (!storage || !storage->bytes) return;
    if (storage->account) (void)axi_mem_free(storage->account, storage->bytes);
    else free(storage->bytes);
    storage->bytes = NULL;
    storage->account = NULL;
}

static int vm_result_uses_scratch(const vm *V, const axi_vval *v)
{
    uintptr_t p = (uintptr_t)v->s, base = (uintptr_t)V->json_scratch;
    return V->json_scratch && p >= base && p - base < AXI_JSON_SCRATCH_SIZE;
}

static void vm_plain_scratch_free(vm *V)
{
    if (V->json_scratch) free(V->json_scratch);
    V->json_scratch = NULL;
}

static vval VUNIT(void) { vval v; memset(&v, 0, sizeof v); return v; }

/* Return by value: callers may publish over the union's own register. */
static vval union_payload(const vval *value)
{
    vval payload = VUNIT();
    payload.kind = value->pay_kind;
    payload.bits = value->bits;
    payload.s = value->s;
    payload.slen = value->slen;
    payload.atom = value->atom;
    payload.atom_len = value->atom_len;
    return payload;
}

static int bytes_equal(const char *a, uint32_t alen,
                        const char *b, uint32_t blen)
{
    return alen == blen && (alen == 0 || (a && b && memcmp(a, b, alen) == 0));
}

/* Equality uses the same closed kind for a scalar and a union payload. A
 * union's arm and payload kind are part of its value, as are error payloads. */
static int value_equal(const vval *x, const vval *y)
{
    uint8_t kind = x->kind;
    if (kind != y->kind) return 0;
    if (kind == VK_UNION) {
        if (x->aux != y->aux || x->pay_kind != y->pay_kind) return 0;
        kind = x->pay_kind;
    }
    switch (kind) {
    case VK_STR: case VK_BYTES:
        return bytes_equal(x->s, x->slen, y->s, y->slen);
    case VK_ERR:
        return bytes_equal(x->atom, x->atom_len, y->atom, y->atom_len)
            && bytes_equal(x->s, x->slen, y->s, y->slen);
    case VK_CAP:
        return x->cap_generation == y->cap_generation
            && x->cap_slot == y->cap_slot
            && memcmp(x->cap_proof, y->cap_proof, sizeof x->cap_proof) == 0
            && bytes_equal(x->atom, x->atom_len, y->atom, y->atom_len);
    case VK_F64: {
        double a, b;
        memcpy(&a, &x->bits, sizeof a);
        memcpy(&b, &y->bits, sizeof b);
        return a == b;
    }
    case VK_UNIT: case VK_U64: case VK_I64: case VK_BOOL:
        return x->bits == y->bits;
    default:
        return 0;
    }
}

static void vtrap(vm *V, const axb_cell *c, uint32_t pc, const char *code,
                   const char *msg, const char *fix) {
    if (V->diags)
        axi_diag_add(V->diags, code, 0, 0, 0, msg, fix);
    else
        fprintf(AXI_ERR, "%s %s:%u: %s | fix: %s\n",
                code, c->name, pc, msg, fix);
    V->trapped = 1;
    /* W17: a deterministic refusal is part of the history. Sealing the trap
     * code into the chain is what will let AXI-P2 (W18) prove that fuel
     * exhaustion dies the SAME way twice, instead of merely dying. */
    if (V->tr) axi_trace_verdict(V->tr, code);
}

static int run_cell(vm *V, uint32_t ci, vval *args, uint8_t argc,
                    vval *ret, uint32_t depth, uint64_t parent_ceiling);
static int run_cell_accounted(vm *V, uint32_t ci, const vval *args,
                              size_t args_offset, int args_in_slab,
                              uint8_t argc, vval *ret, uint32_t depth,
                              uint64_t parent_ceiling);

static uint64_t canonical_f64_bits(uint64_t bits)
{
    if ((bits & UINT64_C(0x7ff0000000000000))
            == UINT64_C(0x7ff0000000000000)
            && (bits & UINT64_C(0x000fffffffffffff)) != 0)
        return UINT64_C(0x7ff8000000000000);
    return bits == UINT64_C(0x8000000000000000) ? 0 : bits;
}

/* INV-388 / AXI-INV-127: public and VM kinds are separate ABIs. Numeric casts
 * once aliased VB_BYTES to VK_ERR and VB_ERR to VK_UNION. */
static int public_to_vm(const axi_vval *in, vval *out)
{
    /* INV-423 / AXI-INV-133: value conversion preserves exact atom/payload,
     * CAP identity and union kind; it never narrows a hostile value. */
    uint8_t payload_kind = VK_UNIT;
    if (!in || !out) return 0;
    *out = VUNIT();
    switch (in->kind) {
    case VB_UNIT: out->kind = VK_UNIT; break;
    case VB_U64:  out->kind = VK_U64; break;
    case VB_I64:  out->kind = VK_I64; break;
    case VB_F64:  out->kind = VK_F64; break;
    case VB_BOOL:
        if (in->bits > 1) return 0;
        out->kind = VK_BOOL;
        break;
    case VB_STR:  out->kind = VK_STR; break;
    case VB_BYTES: out->kind = VK_BYTES; break;
    case VB_ERR:
        out->kind = VK_ERR;
        out->atom = in->atom ? in->atom : in->s;
        out->atom_len = in->atom ? in->atom_len : in->slen;
        if (!out->atom || out->atom_len == 0
                || in->slen > AXI_ERROR_PAYLOAD_MAX
                || (in->slen && !in->s)) return 0;
        break;
    case VB_CAP:
        if (in->atom_len == 0 || in->atom_len >= AXI_CAPNAME
                || memchr(in->cap_atom, '\0', in->atom_len)) return 0;
        out->kind = VK_CAP;
        out->cap_slot = in->cap_slot;
        out->cap_generation = in->cap_generation;
        memcpy(out->cap_proof, in->cap_proof, sizeof out->cap_proof);
        out->atom = in->cap_atom;
        out->atom_len = in->atom_len;
        break;
    case VB_UNION:
        {
            axi_vval public_payload = *in;
            vval payload;
            if (in->payload_kind == VB_CAP || in->payload_kind == VB_UNION)
                return 0;
            public_payload.kind = in->payload_kind;
            if (!public_to_vm(&public_payload, &payload)) return 0;
            payload_kind = payload.kind;
        }
        out->kind = VK_UNION;
        out->aux = in->tag;
        out->pay_kind = payload_kind;
        out->atom = in->atom;
        out->atom_len = in->atom_len;
        break;
    default: return 0;
    }
    if ((out->kind == VK_STR || out->kind == VK_BYTES)
            && !in->s) return 0;
    out->bits = in->bits;
    if (out->kind == VK_F64
            || (out->kind == VK_UNION && out->pay_kind == VK_F64))
        out->bits = canonical_f64_bits(out->bits);
    out->s = in->s;
    out->slen = in->slen;
    return 1;
}

static int vm_to_public(const vval *in, axi_vval *out, int legacy_error_shape)
{
    axi_vkind kind;
    axi_vkind payload_kind = VB_UNIT;
    if (!in || !out) return 0;
    memset(out, 0, sizeof *out);
    switch (in->kind) {
    case VK_UNIT: kind = VB_UNIT; break;
    case VK_U64:  kind = VB_U64; break;
    case VK_I64:  kind = VB_I64; break;
    case VK_F64:  kind = VB_F64; break;
    case VK_BOOL:
        if (in->bits > 1) return 0;
        kind = VB_BOOL;
        break;
    case VK_STR:  kind = VB_STR; break;
    case VK_BYTES: kind = VB_BYTES; break;
    case VK_ERR:  kind = VB_ERR; break;
    case VK_CAP:  kind = VB_CAP; break;
    case VK_UNION:
        switch (in->pay_kind) {
        case VK_UNIT: payload_kind = VB_UNIT; break;
        case VK_U64: payload_kind = VB_U64; break;
        case VK_I64: payload_kind = VB_I64; break;
        case VK_F64: payload_kind = VB_F64; break;
        case VK_BOOL: payload_kind = VB_BOOL; break;
        case VK_STR: payload_kind = VB_STR; break;
        case VK_BYTES: payload_kind = VB_BYTES; break;
        case VK_ERR: payload_kind = VB_ERR; break;
        default: return 0;
        }
        kind = VB_UNION;
        break;
    default: return 0;
    }
    out->kind = kind;
    out->tag = in->aux;
    out->payload_kind = payload_kind;
    out->cap_slot = in->cap_slot;
    out->cap_generation = in->cap_generation;
    memcpy(out->cap_proof, in->cap_proof, sizeof out->cap_proof);
    out->bits = in->bits;
    out->s = in->s;
    out->slen = in->slen;
    out->atom = in->atom;
    out->atom_len = in->atom_len;
    if (in->kind == VK_ERR) {
        if (!out->atom) {
            out->atom = in->s;
            out->atom_len = in->slen;
        }
        /* Preserve the current v5 shape only when no distinct payload exists. */
        if (legacy_error_shape && !out->s) {
            out->s = out->atom;
            out->slen = out->atom_len;
        }
    } else if (in->kind == VK_CAP && in->atom
            && in->atom_len < AXI_CAPNAME) {
        memcpy(out->cap_atom, in->atom, in->atom_len);
        out->cap_atom[in->atom_len] = '\0';
        out->atom = NULL;
    }
    return 1;
}

static int manifest_type_matches(const axb_mtype *type, const vval *value)
{
    if (!type || !value) return 0;
    switch (type->tag) {
    case AXB_MT_U64: return value->kind == VK_U64;
    case AXB_MT_I64: return value->kind == VK_I64;
    case AXB_MT_F64: return value->kind == VK_F64;
    case AXB_MT_BOOL: return value->kind == VK_BOOL && value->bits <= 1;
    case AXB_MT_STR: return value->kind == VK_STR;
    case AXB_MT_BYTES: return value->kind == VK_BYTES;
    case AXB_MT_JSON:
        return value->kind == VK_STR && value->s
            && axi_json_validate(value->s, value->slen) == 0;
    case AXB_MT_DECISION: return value->kind == VK_BOOL && value->bits <= 1;
    case AXB_MT_OK: return value->kind == VK_UNIT;
    case AXB_MT_CAP:
        return value->kind == VK_CAP && value->atom
            && value->atom_len == type->name.len
            && memcmp(value->atom, type->name.p, type->name.len) == 0;
    default: return 0;
    }
}

static int contract_runtime_supported(const axb_contract_mod *m)
{
    uint32_t i;
    for (i = 0; i < m->nmanifest; i++) {
        const axb_manifest *manifest = &m->manifest[i];
        if (manifest->nreturns == 0 && manifest->nerrors == 0) return 0;
    }
    return 1;
}

static int manifest_error_matches(const axb_manifest *manifest,
                                  const vval *value)
{
    uint32_t i;
    const char *atom;
    uint32_t len;
    if (!manifest || !value || value->kind != VK_ERR) return 0;
    atom = value->atom ? value->atom : value->s;
    len = value->atom ? value->atom_len : value->slen;
    if (!atom || len == 0) return 0;
    for (i = 0; i < manifest->nerrors; i++)
        if (manifest->errors[i].len == len
                && memcmp(manifest->errors[i].p, atom, len) == 0) return 1;
    return 0;
}

static void cap_proof_v1(const uint8_t secret[32], const uint8_t root[32],
                         uint32_t slot, const char *atom, uint32_t atom_len,
                         uint8_t out[32])
{
    static const uint8_t domain[] = "AXI-CAP-v1";
    uint8_t message[sizeof domain + 32 + 4 + AXI_CAPNAME];
    uint8_t inner[64 + sizeof message], outer[96], digest[32];
    size_t off = 0;
    size_t i;
    memcpy(message + off, domain, sizeof domain); off += sizeof domain;
    memcpy(message + off, root, 32); off += 32;
    message[off++] = (uint8_t)slot;
    message[off++] = (uint8_t)(slot >> 8);
    message[off++] = (uint8_t)(slot >> 16);
    message[off++] = (uint8_t)(slot >> 24);
    if (atom && atom_len <= AXI_CAPNAME) {
        memcpy(message + off, atom, atom_len);
        off += atom_len;
    }
    for (i = 0; i < 64; i++) {
        uint8_t key = i < 32 ? secret[i] : 0;
        inner[i] = key ^ 0x36u;
        outer[i] = key ^ 0x5cu;
    }
    memcpy(inner + 64, message, off);
    axi_sha256(inner, 64 + off, digest);
    memcpy(outer + 64, digest, sizeof digest);
    axi_sha256(outer, sizeof outer, out);
    secure_zero(message, sizeof message);
    secure_zero(inner, sizeof inner);
    secure_zero(outer, sizeof outer);
    secure_zero(digest, sizeof digest);
}

static int contract_return_ok(vm *V, const axb_cell *cell, uint32_t pc,
                               const vval *value)
{
    /* INV-419 / AXI-INV-129: errors name a declared atom; multiple return
     * arms require a tagged value and never guess from the payload kind. */
    const axb_manifest *manifest;
    uint32_t i;
    if (!V->manifest) return 1;
    manifest = &V->manifest[cell - V->m->cells];
    if (value->kind == VK_ERR) {
        if (manifest_error_matches(manifest, value)) return 1;
        goto refused;
    }
    if (manifest->nreturns > 1) {
        vval payload;
        if (value->kind != VK_UNION || value->aux >= manifest->nreturns)
            goto refused;
        payload = VUNIT();
        payload.kind = value->pay_kind;
        payload.bits = value->bits;
        payload.s = value->s;
        payload.slen = value->slen;
        payload.atom = value->atom;
        payload.atom_len = value->atom_len;
        if (manifest_type_matches(&manifest->returns[value->aux], &payload))
            return 1;
        goto refused;
    }
    for (i = 0; i < manifest->nreturns; i++)
        if (manifest_type_matches(&manifest->returns[i], value)) return 1;
refused:
    vtrap(V, cell, pc, "AXI-R025",
          "returned value does not match the cell contract",
          "return one of the manifest types; error atoms require the error set");
    return 0;
}

static int arith(vm *V, const axb_cell *c, uint32_t pc, uint8_t op,
                 const vval *x, const vval *y, vval *out) {
    if (x->kind != y->kind ||
        (x->kind != VK_U64 && x->kind != VK_I64 && x->kind != VK_F64)) {
        vtrap(V, c, pc, "AXI-R004", "arith needs two numbers of one kind",
              "no coercion at runtime either: convert in source");
        return 0;
    }
    if (x->kind == VK_F64) {
        double a, b, r;
        memcpy(&a, &x->bits, 8); memcpy(&b, &y->bits, 8);
        switch (op) {
        case OP_ADD: r = a + b; break;
        case OP_SUB: r = a - b; break;
        case OP_MUL: r = a * b; break;
        case OP_DIV: r = a / b; break;   /* IEEE: inf/nan are values */
        default:
            vtrap(V, c, pc, "AXI-R005", "mod is not defined on f64",
                  "use u64/i64, or wait for the stdlib cell (W21)");
            return 0;
        }
        /* Destination registers may alias either input. Publish only after
         * both operands have been consumed, including a divisor of zero. */
        *out = *x;
        memcpy(&out->bits, &r, 8);
        out->bits = canonical_f64_bits(out->bits);
        return 1;
    }
    uint64_t a = x->bits, b = y->bits, r = 0;
    if ((op == OP_DIV || op == OP_MOD) && b == 0) {
        vtrap(V, c, pc, "AXI-R003", "division by zero",
              "guard the divisor; `?` unions carry the miss (W13)");
        return 0;
    }
    switch (op) {                        /* unsigned = defined wrap */
    case OP_ADD: r = a + b; break;
    case OP_SUB: r = a - b; break;
    case OP_MUL: r = a * b; break;
    case OP_DIV:
        if (x->kind == VK_I64) {
            int64_t sa = (int64_t)a, sb = (int64_t)b;
            if (sa == INT64_MIN && sb == -1) r = a;   /* defined: wraps */
            else r = (uint64_t)(sa / sb);
        } else r = a / b;
        break;
    case OP_MOD:
        if (x->kind == VK_I64) {
            int64_t sa = (int64_t)a, sb = (int64_t)b;
            if (sa == INT64_MIN && sb == -1) r = 0;
            else r = (uint64_t)(sa % sb);
        } else r = a % b;
        break;
    }
    *out = *x;
    out->bits = r;
    return 1;
}

static int vcmp_lt(vm *V, const axb_cell *c, uint32_t pc,
                   const vval *x, const vval *y, int or_eq, vval *out) {
    if (x->kind != y->kind ||
        (x->kind != VK_U64 && x->kind != VK_I64 && x->kind != VK_F64)) {
        vtrap(V, c, pc, "AXI-R004", "order needs two numbers of one kind",
              "no coercion at runtime either: convert in source");
        return 0;
    }
    int lt, eq = (x->bits == y->bits);
    if (x->kind == VK_I64)      lt = (int64_t)x->bits < (int64_t)y->bits;
    else if (x->kind == VK_F64) {
        double a, b; memcpy(&a, &x->bits, 8); memcpy(&b, &y->bits, 8);
        lt = a < b; eq = (a == b);       /* NaN: !lt && !eq — total refusal below */
    }
    else lt = x->bits < y->bits;         /* INV-002: unsigned cmp stays unsigned */
    memset(out, 0, sizeof *out);
    out->kind = VK_BOOL;
    out->bits = or_eq ? (uint64_t)(lt || eq) : (uint64_t)lt;
    return 1;
}

static int run_cell_prepare(vm *V, uint32_t ci, const vval *args,
                            uint8_t argc, uint32_t depth,
                            uint64_t parent_ceiling, vm_frame *frame)
{
    const axb_cell *c = &V->m->cells[ci];
    uint64_t declared_ceiling = UINT64_MAX;
    uint32_t nr = c->nregs ? c->nregs : 1;
    frame->cell = c;
    frame->frame_ceiling = parent_ceiling;
    frame->local_fuel_limit = 0;
    frame->nregs = nr;
    if (depth > VM_MAX_DEPTH) {
        vtrap(V, c, 0, "AXI-R006", "call depth over 256",
              "recursion needs a ledger, not a bigger stack (W10 fuel)");
        return 0;
    }
    if (nr > AXB_MAX_REGS) {
        vtrap(V, c, 0, "AXI-R002", "cell register count exceeds the VM limit",
              "reassemble from verified source; nregs may not exceed 256");
        return 0;
    }
    if (V->manifest) {
        const axb_manifest *manifest = &V->manifest[ci];
        if (argc != manifest->nparams) {
            vtrap(V, c, 0, "AXI-R024",
                  "argument count does not match the cell contract",
                  "pass exactly the parameters declared by the callee manifest");
            return 0;
        }
        if (nr < manifest->nparams) {
            vtrap(V, c, 0, "AXI-R024",
                  "declared arguments do not fit the callee register frame",
                  "raise nregs or reduce the manifest parameter list");
            return 0;
        }
        for (uint32_t i = 0; i < manifest->nparams; i++) {
            int cap_ok = 1;
            if (manifest->params[i].type.tag == AXB_MT_CAP) {
                uint8_t proof[32];
                cap_ok = V->grants && V->cap_secret
                    && args[i].cap_generation == V->cap_generation
                    && axi_grants_cap_matches(V->grants, args[i].cap_slot,
                                              args[i].atom, args[i].atom_len);
                if (cap_ok) {
                    cap_proof_v1(V->cap_secret, V->m->root,
                                 args[i].cap_slot, args[i].atom,
                                 args[i].atom_len, proof);
                    cap_ok = memcmp(proof, args[i].cap_proof,
                                    sizeof proof) == 0;
                    secure_zero(proof, sizeof proof);
                }
            }
            if (!manifest_type_matches(&manifest->params[i].type, &args[i])
                    || !cap_ok) {
                vtrap(V, c, 0, "AXI-R025",
                      "argument value does not match the cell contract",
                      "pass the exact declared kind; coercion and truthiness do not exist");
                return 0;
            }
        }
        declared_ceiling = manifest->fuel_max > UINT64_MAX - V->fuel_used
            ? UINT64_MAX : V->fuel_used + manifest->fuel_max;
        if (declared_ceiling <= frame->frame_ceiling) {
            frame->frame_ceiling = declared_ceiling;
            frame->local_fuel_limit = 1;
        }
    }
    return 1;
}

static int run_cell_execute(vm *V, uint32_t ci, vval *reg, vval *ret,
                            uint32_t depth, size_t reg_offset,
                            const vm_frame *frame);

static int run_cell_unaccounted(vm *V, uint32_t ci, const vval *args,
                                uint8_t argc, vval *ret, uint32_t depth,
                                uint64_t parent_ceiling)
{
    vm_frame frame;
    vval reg[AXB_MAX_REGS];
    uint32_t i;
    if (!run_cell_prepare(V, ci, args, argc, depth, parent_ceiling, &frame))
        return 0;
    for (i = 0; i < frame.nregs; i++) reg[i] = VUNIT();
    for (i = 0; i < argc && i < frame.nregs; i++) reg[i] = args[i];
    return run_cell_execute(V, ci, reg, ret, depth, 0, &frame);
}

#define VM_REG_SLAB_MAX_COUNT \
    (((size_t)VM_MAX_DEPTH + 1u) * (size_t)AXB_MAX_REGS)

static int vm_reg_slab_refuse(vm *V, const axb_cell *cell,
                              axi_mem_failure_cause cause, size_t request)
{
    const char *message = "VM register slab size is not representable";
    if (V->mem_account) {
        V->mem_account->failure = cause;
        V->mem_account->failed_request = request;
    }
    if (cause == AXI_MEM_QUOTA_EXCEEDED)
        message = "memory quota exhausted before VM frame entry";
    else if (cause == AXI_MEM_HOST_OUT_OF_MEMORY)
        message = "host memory refused the VM register slab";
    else if (cause == AXI_MEM_ACCOUNT_CORRUPTION)
        message = "VM register slab ownership is corrupt";
    vtrap(V, cell, 0, "AXI-R012", message,
          "raise the explicit invocation limit or reduce register depth");
    return 0;
}

static int vm_reg_slab_push(vm *V, const axb_cell *cell, uint32_t nregs,
                            size_t *offset)
{
    size_t required, capacity, bytes;
    vval *grown;
    if (!V->mem_account || !offset || V->reg_slab_used > VM_REG_SLAB_MAX_COUNT
            || (size_t)nregs > VM_REG_SLAB_MAX_COUNT - V->reg_slab_used)
        return vm_reg_slab_refuse(V, cell, AXI_MEM_SIZE_OVERFLOW,
                                  (size_t)-1);
    required = V->reg_slab_used + (size_t)nregs;
    capacity = V->reg_slab_count;
    if (required > capacity) {
        if (capacity == 0) capacity = AXB_MAX_REGS;
        while (capacity < required) {
            if (capacity > VM_REG_SLAB_MAX_COUNT / 2u) {
                capacity = VM_REG_SLAB_MAX_COUNT;
                break;
            }
            capacity *= 2u;
        }
        if (capacity < required || capacity > (size_t)-1 / sizeof(vval))
            return vm_reg_slab_refuse(V, cell, AXI_MEM_SIZE_OVERFLOW,
                                      (size_t)-1);
        bytes = capacity * sizeof(vval);
        grown = (vval *)axi_mem_realloc(V->mem_account, V->reg_slab, bytes);
        if (!grown)
            return vm_reg_slab_refuse(V, cell, V->mem_account->failure,
                                      V->mem_account->failed_request);
        V->reg_slab = grown;
        V->reg_slab_count = capacity;
    }
    *offset = V->reg_slab_used;
    memset(V->reg_slab + *offset, 0, (size_t)nregs * sizeof(vval));
    V->reg_slab_used = required;
    return 1;
}

static int vm_json_scratch_reserve(vm *V, const axb_cell *cell, uint32_t pc)
{
    const char *message = "memory quota exhausted before JSON scratch use";
    if (V->json_scratch) return 1;
    /* INV-704: the scratch bytes are owned invocation memory, never
     * thread-local storage. With an account the alloc IS the charge
     * (axi_mem_alloc reserves size + header in one; no double-charge);
     * the pure embed path has no account, so plain owned malloc serves
     * this one invocation and is freed with the register slab. */
    if (V->mem_account) {
        V->json_scratch = axi_mem_alloc(V->mem_account, AXI_JSON_SCRATCH_SIZE);
        if (V->json_scratch) {
            V->json_scratch_reserved = 1;
            return 1;
        }
        if (V->mem_account->failure == AXI_MEM_HOST_OUT_OF_MEMORY)
            message = "host memory refused JSON scratch accounting";
        else if (V->mem_account->failure == AXI_MEM_SIZE_OVERFLOW)
            message = "JSON scratch accounting size overflowed";
        else if (V->mem_account->failure == AXI_MEM_ACCOUNT_CORRUPTION)
            message = "JSON scratch accounting is corrupt";
    } else {
        V->json_scratch = axi_malloc(AXI_JSON_SCRATCH_SIZE);
        if (V->json_scratch) return 1;
        message = "host memory refused the pure-embed JSON scratch";
    }
    vtrap(V, cell, pc, "AXI-R012", message,
          "raise the explicit invocation limit or avoid json.get");
    return 0;
}

static void vm_mem_failure_set(axi_mem_account *account,
                               axi_mem_failure_cause cause, size_t request)
{
    if (!account) return;
    account->failure = cause;
    account->failed_request = request;
    if (account->denied_failure == AXI_MEM_FAILURE_NONE) {
        account->denied_failure = cause;
        account->denied_request = request;
    }
}

static int vm_builtin_scratch_reserve(vm *V, const axb_cell *cell, uint32_t pc,
                                      const char *name, size_t *bytes,
                                      int *reserved)
{
    const char *message = "memory quota exhausted before builtin scratch use";
    *bytes = 0;
    *reserved = 0;
    if (axi_builtin_scratch_bytes(name, strlen(name), bytes) != 0) {
        vm_mem_failure_set(V->mem_account, AXI_MEM_SIZE_OVERFLOW, (size_t)-1);
        message = "builtin scratch accounting size overflowed";
        goto refused;
    }
    if (!V->mem_account || *bytes == 0) return 1;
    if (axi_mem_reserve(V->mem_account, *bytes)) {
        *reserved = 1;
        return 1;
    }
    if (V->mem_account->failure == AXI_MEM_HOST_OUT_OF_MEMORY)
        message = "host memory refused builtin scratch accounting";
    else if (V->mem_account->failure == AXI_MEM_SIZE_OVERFLOW)
        message = "builtin scratch accounting size overflowed";
    else if (V->mem_account->failure == AXI_MEM_ACCOUNT_CORRUPTION)
        message = "builtin scratch accounting is corrupt";
refused:
    vtrap(V, cell, pc, "AXI-R012", message,
          "raise the explicit invocation limit or avoid this builtin");
    return 0;
}

static int vm_builtin_scratch_release(vm *V, const axb_cell *cell, uint32_t pc,
                                      size_t bytes, int reserved)
{
    if (!reserved) return 1;
    if (axi_mem_release(V->mem_account, bytes)) return 1;
    vtrap(V, cell, pc, "AXI-R012", "builtin scratch release is corrupt",
          "discard the invocation and inspect AXI-MEM-ACCOUNT-v1 ownership");
    return 0;
}

static int run_cell_accounted(vm *V, uint32_t ci, const vval *args,
                              size_t args_offset, int args_in_slab,
                              uint8_t argc, vval *ret, uint32_t depth,
                              uint64_t parent_ceiling)
{
    vm_frame frame;
    size_t offset = 0, copy_count;
    int ok;
    if (args_in_slab) {
        if (args_offset > V->reg_slab_used
                || (size_t)argc > V->reg_slab_used - args_offset)
            return vm_reg_slab_refuse(V, &V->m->cells[ci],
                                      AXI_MEM_ACCOUNT_CORRUPTION, 0);
        args = V->reg_slab + args_offset;
    }
    if (!run_cell_prepare(V, ci, args, argc, depth, parent_ceiling, &frame))
        return 0;
    if (!vm_reg_slab_push(V, frame.cell, frame.nregs, &offset)) return 0;
    copy_count = argc < frame.nregs ? argc : frame.nregs;
    if (copy_count) {
        if (args_in_slab)
            memmove(V->reg_slab + offset, V->reg_slab + args_offset,
                    copy_count * sizeof(vval));
        else
            memcpy(V->reg_slab + offset, args, copy_count * sizeof(vval));
    }
    ok = run_cell_execute(V, ci, V->reg_slab + offset, ret, depth, offset,
                          &frame);
    V->reg_slab_used = offset;
    return ok;
}

static int run_cell(vm *V, uint32_t ci, vval *args, uint8_t argc,
                    vval *ret, uint32_t depth, uint64_t parent_ceiling)
{
    if (V->mem_account)
        return run_cell_accounted(V, ci, args, 0, 0, argc, ret, depth,
                                  parent_ceiling);
    return run_cell_unaccounted(V, ci, args, argc, ret, depth,
                                parent_ceiling);
}

static int run_cell_execute(vm *V, uint32_t ci, vval *reg, vval *ret,
                            uint32_t depth, size_t reg_offset,
                            const vm_frame *frame)
{
    const axb_cell *c = frame->cell;
    uint64_t frame_ceiling = frame->frame_ceiling;
    int local_fuel_limit = frame->local_fuel_limit;
    uint32_t nr = frame->nregs;

    uint32_t pc = 0;
    for (;;) {
        if (pc >= c->nc) {
            vtrap(V, c, pc, "AXI-R001", "control fell off the end of the cell",
                  "every path must ret");
            return 0;
        }
        uint32_t w = c->code[pc];
        uint8_t op = (uint8_t)w, a = (uint8_t)(w >> 8),
                b = (uint8_t)(w >> 16), cc = (uint8_t)(w >> 24);
        uint16_t bc16 = (uint16_t)(b << 8 | cc);
        const axb_opinfo *oi = axb_op_info(op);
        {   /* W18 — fuel first, and a cell never spends what it does not have.
             * The charge is checked BEFORE it is applied (cost > remaining,
             * written as a subtraction so no u64 can wrap): the ledger is
             * therefore never above the ceiling, not even for the instant of
             * the fatal op, and `--fuel-report` cannot print a number the
             * budget never authorised. The trapping op does NOT run and is NOT
             * charged — charging for work not done was a ledger that lied in
             * the one direction a ledger must never lie. /AXI-INV-033/ */
            uint64_t cost = oi ? oi->fuel : 1;
            if (V->fuel_used > frame_ceiling
                    || cost > frame_ceiling - V->fuel_used) {
                char msg[AXI_DIAG_MSG], fix[AXI_DIAG_MSG];
                snprintf(msg, sizeof msg,
                         "fuel exhausted: spent %llu of %llu, next op needs %llu",
                         (unsigned long long)V->fuel_used,
                          (unsigned long long)frame_ceiling,
                          (unsigned long long)cost);
                if (V->manifest && local_fuel_limit)
                    snprintf(fix, sizeof fix,
                             "contract fuel_max is a hard frame ceiling; make the cell cheaper or revise its source contract");
                else if (V->manifest)
                    snprintf(fix, sizeof fix,
                             "an operator or caller ceiling is tighter; raise that outer budget or make the cell cheaper");
                else
                    snprintf(fix, sizeof fix,
                             "exhaustion is a verdict, not an error: --fuel %llu is the smallest budget that reaches this op, or make the cell cheaper",
                             (unsigned long long)(V->fuel_used + cost));
                vtrap(V, c, pc, "AXI-R008", msg, fix);
                V->trapped = 2;
                return 0;
            }
            V->fuel_used += cost;
        }
        if (a >= nr || (oi && oi->ops >= AXB_OPS_RA_RB
                        && oi->ops <= AXB_OPS_RA_RB_RC
                        && (b >= nr || (oi->ops == AXB_OPS_RA_RB_RC && cc >= nr)))) {
            vtrap(V, c, pc, "AXI-R002", "register outside the cell's nregs",
                  "the assembler trusts nregs=; raise it or fix the code");
            return 0;
        }
        /* W17 — one link per instruction, taken at the TOP of the loop so no
         * instruction can escape it: jmp and a taken jf `continue`, and a
         * witness placed after the switch would miss exactly the branches
         * that decide the history. The record carries the whole live register
         * window, so the pre-state of step n+1 IS the post-state of step n:
         * every state transition is witnessed, with `ret`'s own record
         * carrying the returned value. /AXI-INV-029/ */
        if (V->tr) {
            axi_trace_step_begin(V->tr, ci, pc, op, V->fuel_used, nr);
            for (uint32_t i = 0; i < nr; i++)
                axi_trace_val(V->tr, reg[i].kind, reg[i].aux, reg[i].pay_kind,
                              reg[i].bits, reg[i].s, reg[i].slen);
            axi_trace_step_end(V->tr);
            /* INV-309 / AXI-INV-096: evidence allocation fails before the
             * opcode, especially before OP_EFF can touch the world. */
            if (V->tr->oom) {
                vtrap(V, c, pc, "AXI-R017", "trace step cannot be recorded",
                      "rerun with enough host memory to preserve evidence");
                return 0;
            }
        }
        switch (op) {
        case OP_NOP: break;
        case OP_LDK: {
            if (bc16 >= c->nk) {
                vtrap(V, c, pc, "AXI-R002", "const index out of range",
                      "reassemble from .axs; do not edit binaries");
                return 0;
            }
            const axb_konst *k = &c->k[bc16];
            vval v = VUNIT();
            switch (k->tag) {
            case AXB_KU64: v.kind = VK_U64; v.bits = k->u; break;
            case AXB_KI64: v.kind = VK_I64; v.bits = k->u; break;
            case AXB_KF64:
                v.kind = VK_F64;
                v.bits = canonical_f64_bits(k->u);
                break;
            case AXB_KSTR: v.kind = VK_STR; v.s = k->s; v.slen = k->slen; break;
            case AXB_KERR:
                v.kind = VK_ERR; v.atom = k->s; v.atom_len = k->slen;
                break;
            }
            reg[a] = v;
            break;
        }
        case OP_MOV: reg[a] = reg[b]; break;
        case OP_ADD: case OP_SUB: case OP_MUL: case OP_DIV: case OP_MOD:
            if (!arith(V, c, pc, op, &reg[b], &reg[cc], &reg[a])) return 0;
            break;
        case OP_EQ: {
            int eq = value_equal(&reg[b], &reg[cc]);
            reg[a] = VUNIT(); reg[a].kind = VK_BOOL; reg[a].bits = (uint64_t)eq;
            break;
        }
        case OP_LT: if (!vcmp_lt(V, c, pc, &reg[b], &reg[cc], 0, &reg[a])) return 0; break;
        case OP_LE: if (!vcmp_lt(V, c, pc, &reg[b], &reg[cc], 1, &reg[a])) return 0; break;
        case OP_NOT:
            if (reg[b].kind != VK_BOOL) {
                vtrap(V, c, pc, "AXI-R004", "not needs a bool",
                      "truthiness does not exist here (G5)");
                return 0;
            }
            reg[a] = reg[b]; reg[a].bits = !reg[b].bits;
            break;
        case OP_JMP: pc = (uint32_t)((int32_t)pc + (int16_t)bc16); continue;
        case OP_JF:
            if (reg[a].kind != VK_BOOL) {
                vtrap(V, c, pc, "AXI-R004", "jf needs a bool",
                      "truthiness does not exist here (G5)");
                return 0;
            }
            if (!reg[a].bits) { pc = (uint32_t)((int32_t)pc + (int16_t)bc16); continue; }
            break;
        case OP_UMAKE: {
            vval result;
            if (reg[b].kind != VK_U64) {
                vtrap(V, c, pc, "AXI-R004", "union tag must be u64",
                      "umake rDST rTAG rPAYLOAD");
                return 0;
            }
            if (reg[b].bits > UINT8_MAX) {
                vtrap(V, c, pc, "AXI-R004", "union tag exceeds the wire ABI",
                      "use a zero-based tag in the range 0..255");
                return 0;
            }
            /* INV-322 / AXI-INV-104: the v0 payload subset is closed —
             * unit/u64/i64/f64/bool/str. A nested union would need a second
             * pay_kind this value cannot carry; refuse, never squash. */
            switch (reg[cc].kind) {
            case VK_UNIT: case VK_U64: case VK_I64:
            case VK_F64: case VK_BOOL: case VK_STR: case VK_BYTES: case VK_ERR:
                break;
            default:
                vtrap(V, c, pc, "AXI-R004", "union payload outside the v0 subset",
                      "payloads are unit/u64/i64/f64/bool/str; nested unions do not exist");
                return 0;
            }
            result = VUNIT(); result.kind = VK_UNION;
            result.aux  = (uint8_t)reg[b].bits;
            result.pay_kind = reg[cc].kind;
            result.bits = reg[cc].bits;
            result.s    = reg[cc].s;
            result.slen = reg[cc].slen;
            result.atom = reg[cc].atom;
            result.atom_len = reg[cc].atom_len;
            reg[a] = result;
            break;
        }
        case OP_UTAG: {
            uint8_t tag;
            if (reg[b].kind != VK_UNION) {
                vtrap(V, c, pc, "AXI-R004", "utag needs a union",
                      "only unions carry a tag");
                return 0;
            }
            tag = reg[b].aux;
            reg[a] = VUNIT(); reg[a].kind = VK_U64; reg[a].bits = tag;
            break;
        }
        case OP_UPAY:
            if (reg[b].kind != VK_UNION) {
                vtrap(V, c, pc, "AXI-R004", "upay needs a union",
                      "only unions carry a payload");
                return 0;
            }
            /* INV-322 / AXI-INV-104: value AND kind come back bit-exact. */
            reg[a] = union_payload(&reg[b]);
            break;
        case OP_UCHK:
            /* W13 — the `?` in one deterministic step: tag 0 (ok/some)
             * unwraps the payload into ra; any other tag returns the
             * union AS the cell's result (propagation, not exception). */
            if (reg[b].kind != VK_UNION) {
                vtrap(V, c, pc, "AXI-R004", "uchk needs a union",
                      "`?` only judges result/opt unions (T014 is the static twin)");
                return 0;
            }
            if (reg[b].aux != 0) {
                if (!contract_return_ok(V, c, pc, &reg[b])) return 0;
                *ret = reg[b]; return 1;
            }
            reg[a] = union_payload(&reg[b]);
            break;
        case OP_CALL: {
            if (b >= V->m->n) {
                vtrap(V, c, pc, "AXI-R002", "call to a cell index out of range",
                      "reassemble from .axs; do not edit binaries");
                return 0;
            }
            if (a + (uint32_t)cc > nr) {
                vtrap(V, c, pc, "AXI-R002", "call window past nregs",
                      "args live at rBASE..rBASE+argc-1");
                return 0;
            }
            vval out;
            if (V->mem_account) {
                if ((size_t)a > (size_t)-1 - reg_offset)
                    return vm_reg_slab_refuse(V, c, AXI_MEM_SIZE_OVERFLOW,
                                              (size_t)-1);
                if (!run_cell_accounted(V, b, NULL, reg_offset + (size_t)a, 1,
                                        cc, &out, depth + 1, frame_ceiling))
                    return 0;
                reg = V->reg_slab + reg_offset;
            } else if (!run_cell(V, b, &reg[a], cc, &out, depth + 1,
                                 frame_ceiling)) {
                return 0;
            }
            reg[a] = out;
            break;
        }
        case OP_RET:
            if (!contract_return_ok(V, c, pc, &reg[a])) return 0;
            *ret = reg[a]; return 1;
        case OP_EFF: {
            axi_resource_vector resource_reserved = {0};
            axi_resource_vector resource_actual = {0};
            axi_resource_result resource_result = AXI_RESOURCE_OK;
            /* W19 — the only place in this program where the world is touched.
             * Four locks, in this order, and every one of them must open:
             *
             *   1. DECLARED   the module named this authority (b indexes its
             *                 own .eff table — an index with no declaration is
             *                 a broken module, not an effect) /AXI-INV-036/
             *   2. GRANTED    the operator authorised that exact name /036/
             *   3. DONE       the host function ran and reported success
             *   4. RECORDED   the row is appended AFTER success, so the ledger
             *                 says what happened, not what was tried /039/
             *
             * Locks 1 and 2 are two different people agreeing (author and
             * operator); that is why neither alone can open the door. The
             * checker (W07) already refused undeclared effects at compile
             * time — this is the LAST door, and it re-asks every question,
             * because a bytecode that arrived without its source must still
             * be unable to lie. /AXI-INV-037/ */
            if (b >= V->m->neff) {
                vtrap(V, c, pc, "AXI-R002", "effect index past the module's declared authority",
                      "reassemble from .axs; do not edit binaries");
                return 0;
            }
            const char *ename = V->m->eff[b];
            /* 2. THE OPERATOR'S KEY. No grant set at all is the empty grant
             * set: a run that was never told it could touch the world does
             * not get to discover that it can. */
            if (!V->grants || !axi_grants_has(V->grants, ename)) {
                vtrap(V, c, pc, "AXI-R007", "effect declared but not granted",
                      "authorise it explicitly: axi run … --cap <Name.Verb>");
                return 0;
            }
            const axi_host_eff *he = axi_host_eff_find(ename);
            if (!he) {
                vtrap(V, c, pc, "AXI-R014", "granted effect has no host implementation",
                      "`axi caps` lists what this build can actually do");
                return 0;
            }
            /* AXI-INV-077 / INV-282: embed and CLI share the same last door.
             * Without a ledger, refuse before the host call rather than touch
             * the world and discover afterward that no receipt can be filed. */
            if (!V->led) {
                vtrap(V, c, pc, "AXI-R017", "effect has no ledger context",
                      "provide an accountable runner; embed defaults to pure policy");
                return 0;
            }
            if (axi_ledger_prepare(V->led) != 0) {
                vtrap(V, c, pc, "AXI-R017", "ledger row cannot be reserved",
                      "an effect without durable evidence is refused");
                return 0;
            }
            /* the payload is bytes. A str is the only thing that crosses the
             * door in W19, because a digest of "some object" is a digest of
             * nothing a reviewer can re-derive. */
            if (reg[cc].kind != VK_STR) {
                vtrap(V, c, pc, "AXI-R015", "effect payload is not a str",
                      "an effect carries bytes a reviewer can re-hash");
                return 0;
            }
            const void *pay = reg[cc].s;
            size_t      plen = reg[cc].slen;
            if (V->resources) {
                resource_reserved.calls = 1;
                resource_reserved.input_bytes = (uint64_t)plen;
                if (strcmp(ename, "fs.Read") == 0)
                    resource_reserved.output_bytes = 65536u;
                else if (strcmp(ename, "net.Read") == 0)
                    resource_reserved.output_bytes = 4096u;
                else if (strcmp(ename, "crypto.Hash") == 0)
                    resource_reserved.output_bytes = 64u;
                if (strcmp(ename, "net.Connect") == 0)
                    resource_reserved.handles = 1;
                if (strcmp(ename, "proc.Spawn") == 0
                        || strcmp(ename, "fs.Write") == 0
                        || strcmp(ename, "net.Connect") == 0)
                    resource_reserved.children = 1;
                resource_result = axi_resource_reserve(
                    V->resources, &resource_reserved);
                if (resource_result != AXI_RESOURCE_OK) {
                    vtrap(V, c, pc, "AXI-R026", axi_resource_result_name(resource_result),
                          "raise the matching invocation ceiling or shorten the operation");
                    return 0;
                }
            }
            int         fuel_exhausted = 0;
            axi_host_eff_ctx hectx = {
                .sink           = V->sink,
                .grants         = V->grants,
                .led            = V->led,
                .journal        = V->journal,
                .m              = V->m,
                .mod_path       = V->mod_path,
                .trusted_key_path = V->trusted_key_path,
                .fuel_budget    = frame_ceiling,
                .fuel_used      = &V->fuel_used,
                .fuel_exhausted = &fuel_exhausted,
                .replay         = V->replay,
                .cell_name      = c->name,
                .account        = V->mem_account,
                .resources      = V->resources,
            };
            long        wrote = he->fn(&hectx, pay, plen);
            if (V->resources) {
                resource_actual.calls = 1;
                resource_actual.input_bytes = (uint64_t)plen;
                resource_actual.output_bytes = wrote >= 0
                    ? (uint64_t)hectx.result_len : 0;
                resource_actual.handles = wrote >= 0
                    ? resource_reserved.handles : 0;
                resource_actual.children = strcmp(ename, "proc.Spawn") == 0
                    ? resource_reserved.children : 0;
                resource_result = axi_resource_commit(
                    V->resources, &resource_reserved, &resource_actual);
                if (resource_result == AXI_RESOURCE_CORRUPT) {
                    vtrap(V, c, pc, "AXI-R026", "resource accounting is corrupt",
                          "discard the invocation and inspect the effect accounting door");
                    return 0;
                }
                if (wrote >= 0 && strcmp(ename, "net.Close") == 0
                        && axi_resource_handle_closed(V->resources)
                           == AXI_RESOURCE_CORRUPT) {
                    vtrap(V, c, pc, "AXI-R026", "closed handle was not live",
                          "discard the invocation and inspect handle accounting");
                    return 0;
                }
            }
            if (fuel_exhausted) {
                vtrap(V, c, pc, "AXI-R008", "fuel exhausted in a spawned process",
                      "the child inherited the parent's budget and spent it all");
                V->trapped = 2;
                return 0;
            }
            if (wrote < 0) {
                /* rule 4: a failed effect leaves no row. The verdict carries
                 * it, and the verdict is sealed into the trace like any
                 * other refusal — the history stays complete. */
                vtrap(V, c, pc, "AXI-R016", "the host refused the effect",
                      "the world said no; that is an answer, not a bug");
                return 0;
            }
            /* 4. THE ROW. If the effect happened and could NOT be filed, the
             * instrument has lost the only thing it sells. It does not
             * continue and hope: the ledger marks itself incomplete (oom) and
             * this invocation dies. Under-recording is the one direction this
             * ledger is never allowed to fail in. /AXI-INV-038/
             * Some effects (net.Read/Write) override the digest to record the
             * bytes that actually crossed the wire, not the handle syntax. */
            int led_ok;
            if (hectx.record_digest) {
                led_ok = axi_ledger_append_digest(V->led, ename, c->name,
                                                  hectx.record_digest,
                                                  hectx.record_nbytes) == 0;
            } else {
                led_ok = axi_ledger_append(V->led, ename, c->name, pay, plen) == 0;
            }
            if (!V->led || !led_ok) {
                vtrap(V, c, pc, "AXI-R017", "the effect happened and could not be recorded",
                      "an unrecordable effect is a refused effect; rerun with more host memory");
                return 0;
            }
            if (hectx.evidence_failed) {
                vtrap(V, c, pc, "AXI-R019",
                      "host effect committed but replay evidence failed",
                      "treat the action as committed and repair the evidence sink");
                return 0;
            }
            reg[a] = VUNIT();
            if (hectx.has_result) {
                reg[a].kind = VK_STR;
                reg[a].s    = hectx.result;
                reg[a].slen = (uint32_t)hectx.result_len;
            } else {
                reg[a].kind = VK_U64;
                reg[a].bits = (uint64_t)wrote;   /* bytes that crossed the door */
            }
            break;
        }
        case OP_BUILTIN: {
            /* M3: policy builtins are the guarded interface to host services.
             * Like EFF, the module must declare the builtin and (for impure
             * builtins) the operator must grant the matching capability. */
            if (b >= V->m->nbuiltin) {
                vtrap(V, c, pc, "AXI-R002", "builtin index past the module's declared builtins",
                      "reassemble from .axs; do not edit binaries");
                return 0;
            }
            const char *bname = V->m->builtin[b];
            const axi_builtin_info *bi = axi_builtin_lookup(bname, strlen(bname));
            if (!bi) {
                vtrap(V, c, pc, "AXI-R014", "declared builtin has no host implementation",
                      "`axi caps` lists what this build can actually do");
                return 0;
            }
            if (bi->cap != CAP_NONE) {
                if (!V->grants || !axi_grants_has(V->grants, bi->cap_name)) {
                    vtrap(V, c, pc, "AXI-R007", "builtin declared but not granted",
                          "authorise it explicitly: axi run … --cap <Name>");
                    return 0;
                }
            }
            if (cc + (uint32_t)bi->arity > nr) {
                vtrap(V, c, pc, "AXI-R002", "builtin argument window past nregs",
                      "raise nregs or pass fewer arguments");
                return 0;
            }
            if (strncmp(bname, "json.", 5) == 0
                    && !vm_json_scratch_reserve(V, c, pc)) return 0;
            axi_vval bargs[4], bout;
            memset(&bout, 0, sizeof bout);
            const char *errmsg = NULL;
            size_t builtin_scratch = 0;
            int builtin_scratch_reserved = 0;
            int builtin_rc;
            for (int i = 0; i < bi->arity; i++) {
                vval *v = &reg[cc + i];
                if (!vm_to_public(v, &bargs[i], 1)) {
                    vtrap(V, c, pc, "AXI-R004",
                          "builtin argument has no public value representation",
                          "unwrap unions before crossing the builtin boundary");
                    return 0;
                }
            }
            if (!vm_builtin_scratch_reserve(V, c, pc, bname,
                                            &builtin_scratch,
                                            &builtin_scratch_reserved))
                return 0;
            builtin_rc = axi_builtin_exec(bname, bargs, bi->arity, &bout,
                                          &errmsg, V->json_scratch
                                              ? V->json_scratch + V->json_used : NULL,
                                          V->json_scratch
                                              ? AXI_JSON_SCRATCH_SIZE - V->json_used : 0);
            if (!vm_builtin_scratch_release(V, c, pc, builtin_scratch,
                                            builtin_scratch_reserved))
                return 0;
            if (builtin_rc != 0) {
                char m[AXI_DIAG_MSG];
                snprintf(m, sizeof m, "builtin %s failed: %s", bname, errmsg ? errmsg : "?");
                vtrap(V, c, pc, "AXI-R016", m,
                      "the host refused the builtin; check arguments and grants");
                return 0;
            }
            if (V->json_scratch && bout.s == V->json_scratch + V->json_used) {
                size_t used = bout.slen ? bout.slen : 1u;
                if (used > AXI_JSON_SCRATCH_SIZE - V->json_used) {
                    vtrap(V, c, pc, "AXI-R012", "decoded JSON lifetime arena exhausted",
                          "reduce decoded intermediate values per invocation");
                    return 0;
                }
                V->json_used += used;
            }
            if (!public_to_vm(&bout, &reg[a])) {
                vtrap(V, c, pc, "AXI-R004",
                      "builtin returned an invalid public value",
                      "return a closed axi_vkind with valid borrowed bytes");
                return 0;
            }
            break;
        }
        case OP_HALT:
            vtrap(V, c, pc, "AXI-R001", "halt reached",
                  "halt marks a path the compiler proved dead");
            return 0;
        default:
            vtrap(V, c, pc, "AXI-R000", "opcode not in the table",
                  "the opcode table in axi_bc.h is the whole truth");
            return 0;
        }
        pc++;
    }
}

static int decode_root_hex(const char *s, uint8_t out[32])
{
    if (!s || strlen(s) != 64) return -1;
    for (int i = 0; i < 32; i++) {
        unsigned v = 0;
        for (int j = 0; j < 2; j++) {
            unsigned char c = (unsigned char)s[i * 2 + j];
            unsigned d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else return -1;
            v = v * 16 + d;
        }
        out[i] = (uint8_t)v;
    }
    return 0;
}

/* ---- W12: proof runner ------------------------------------------------
 * One semantics: a law is judged by the SAME run_cell that judges bodies.
 * A separate evaluator would eventually disagree with the VM — that lie
 * is the Lua-family bug class this house refuses by construction. */
int axi_vm_prove(const axb_mod *m, const char *cellname, uint64_t fuel,
                  int *is_true) {
    uint32_t ci = m->n;
    if (axb_mod_verify(m, "<proof>", NULL) != 0) return 1;
    for (uint32_t i = 0; i < m->n; i++)
        if (strcmp(m->cells[i].name, cellname) == 0) { ci = i; break; }
    if (ci == m->n) return 2;
    {
        /* proofs are judged, not witnessed: a law's run is not history.
         * W19: no grants, no ledger, no sink — a law that needs to touch the
         * world to be true is not a law, and here it cannot even try. */
        vm V = { .m = m, .fuel_budget = fuel ? fuel : VM_FUEL_DEFAULT };
        vval out;
        int ok = run_cell(&V, ci, NULL, 0, &out, 0, V.fuel_budget);
        if (ok) *is_true = (out.kind == VK_BOOL && out.bits != 0);
        vm_plain_scratch_free(&V);
        if (!ok) return 1;
    }
    return 0;
}

/* ---- M4: embed API backend ------------------------------------------------
 * One entry point for hosts (jash) that need to run a cell with a JSON string
 * argument and get a value back. The VM internals stay hidden; only the
 * value kind crosses this boundary. */
static void vm_api_diag(axi_diags *diags, const char *code,
                        const char *msg, const char *fix)
{
    if (diags) axi_diag_add(diags, code, 0, 0, 0, msg, fix);
    else fprintf(AXI_ERR, "%s %s | fix: %s\n", code, msg, fix);
}

int axi_vm_run_cell_diag(const axb_mod *m, uint32_t ci,
                         const axi_vval *args, uint8_t argc,
                         axi_vval *out, uint64_t fuel_budget,
                         uint64_t *fuel_used,
                         const axi_grants *grants, void *sink,
                         axi_diags *diags)
{
    vm V = { .m = m,
             .fuel_budget = fuel_budget ? fuel_budget : VM_FUEL_DEFAULT,
             .grants = grants, .sink = sink, .diags = diags };
    vval a[16], ret;
    if (fuel_used) *fuel_used = 0;
    if (!m || !out || (argc && !args)) {
        vm_api_diag(diags, "AXI-E001", "invalid direct VM call arguments",
                    "provide module, output and every declared argument");
        return 0;
    }
    if (axb_mod_verify(m, "<embed-vm>", diags) != 0) return 0;
    if (ci >= m->n) {
        vm_api_diag(diags, "AXI-E002", "policy cell index does not exist",
                    "inspect the module and request a declared cell");
        return 0;
    }
    if (argc > 16) {
        vm_api_diag(diags, "AXI-E001",
                    "embed call has more than 16 arguments",
                    "the v0 call window carries at most 16 arguments");
        return 0;
    }
    for (int i = 0; i < argc; i++) {
        if (!public_to_vm(&args[i], &a[i])) {
            vm_api_diag(diags, "AXI-E001", "invalid public VM value",
                        "use a closed axi_vkind and valid borrowed byte storage");
            return 0;
        }
    }
    int ok = run_cell(&V, ci, a, argc, &ret, 0, V.fuel_budget);
    if (ok) {
        axi_vval published;
        if (!vm_to_public(&ret, &published, 1)) {
            vtrap(&V, &m->cells[ci], m->cells[ci].nc, "AXI-R004",
                  "VM result has no public value representation",
                  "unwrap unions before crossing the embed boundary");
            ok = 0;
        } else if (vm_result_uses_scratch(&V, &published)) {
            vm_api_diag(diags, "AXI-R025", "computed byte result needs an invocation owner",
                        "use an owned invocation or the scoped private embed door");
            ok = 0;
        } else {
            *out = published;
        }
    }
    vm_plain_scratch_free(&V);
    if (fuel_used) *fuel_used = V.fuel_used;
    return ok;
}

/* INV-389 / AXI-INV-128: every production invocation consumes the complete
 * model returned by exact trusted-v7 admission. */
static int run_contract_cell_diag_for_invocation(
                                  const axb_contract_mod *m, uint32_t ci,
                                  const axi_vval *args, uint8_t argc,
                                  axi_vval *out, uint64_t fuel_budget,
                                  uint64_t *fuel_used, int *fuel_exhausted,
                                  const axi_grants *grants, void *sink,
                                  axi_diags *diags, uint64_t cap_generation,
                                   const uint8_t *cap_secret,
                                   const char *mod_path,
                                   const char *trusted_key_path,
                                    axi_ledger *ledger,
                                     axi_effect_journal *journal,
                                     axi_replay *replay, axi_trace *trace,
                                     int preverified, int exact_fuel,
                                      axi_mem_account *mem_account,
                                      axi_resource_envelope *resources,
                                      axi_vm_output_storage *storage)
{
    vm V;
    vval a[16], ret;
    uint64_t budget = exact_fuel ? fuel_budget
                                 : (fuel_budget ? fuel_budget : VM_FUEL_DEFAULT);
    int args_reserved = 0;
    int ok = 0;
    memset(&V, 0, sizeof V);
    if (fuel_used) *fuel_used = 0;
    if (fuel_exhausted) *fuel_exhausted = 0;
    if (!m || !out || argc > 16 || (argc && !args)
            || (storage && (storage->bytes || storage->account))) {
        vm_api_diag(diags, "AXI-E001", "invalid contract VM call arguments",
                    "provide a verified model, output and at most 16 arguments");
        return 0;
    }
    if (trace && mem_account) {
        size_t max_string = 0, per_value, scratch;
        uint32_t max_regs = 0;
        for (uint32_t i = 0; i < m->body.n; i++) {
            const axb_cell *cell = &m->body.cells[i];
            if (cell->nregs > max_regs) max_regs = cell->nregs;
            for (uint32_t j = 0; j < cell->nk; j++)
                if ((cell->k[j].tag == AXB_KSTR || cell->k[j].tag == AXB_KERR)
                        && cell->k[j].slen > max_string)
                    max_string = cell->k[j].slen;
        }
        for (uint32_t i = 0; i < m->body.neff; i++) {
            size_t possible = 0;
            if (strcmp(m->body.eff[i], "fs.Read") == 0) possible = 65536u;
            else if (strcmp(m->body.eff[i], "net.Read") == 0) possible = 4096u;
            if (possible > max_string) max_string = possible;
        }
        for (uint32_t i = 0; i < argc; i++)
            if ((args[i].kind == VB_STR || args[i].kind == VB_BYTES)
                    && args[i].slen > max_string)
                max_string = args[i].slen;
        /* INV-505 / AXI-INV-155: one conservative reservation precedes the
         * first opcode; sealed trace scratch can never allocate in dispatch. */
        if (max_string > (size_t)-1 - 15u
                || max_regs > ((size_t)-1 - 21u) / (15u + max_string)) {
            (void)axi_mem_alloc(mem_account, (size_t)-1);
            vm_api_diag(diags, "AXI-R012", "trace scratch size overflows",
                        "reduce the admitted register or string bounds");
            return 0;
        }
        per_value = 15u + max_string;
        scratch = 21u + (size_t)max_regs * per_value;
        if (!axi_trace_prepare(trace, scratch)) {
            vm_api_diag(diags, "AXI-R012",
                        "memory quota exhausted before trace execution",
                        "raise the invocation limit or disable trace evidence");
            return 0;
        }
    }
    if (mem_account
            && !axi_mem_reserve(mem_account, sizeof a)) {
        vm_api_diag(diags, "AXI-R012",
                    "memory quota exhausted before VM argument conversion",
                    "raise the explicit invocation limit or reduce arguments");
        return 0;
    }
    args_reserved = mem_account != NULL;
    if (!preverified && axb_contract_v1_verify(m) != 0) {
        vm_api_diag(diags, "AXI-R025", "contract model failed verification",
                    "decode or build one complete model before execution");
        goto done;
    }
    if (ci >= m->body.n) {
        vm_api_diag(diags, "AXI-E002", "contract cell index does not exist",
                    "inspect the contract and request a declared cell");
        goto done;
    }
    if (!contract_runtime_supported(m)) {
        vm_api_diag(diags, "AXI-R025",
                     "contract uses an unsupported runtime value shape",
                     "use the closed CAP, error and single-level tagged-return ABI");
        goto done;
    }
    for (int i = 0; i < argc; i++) {
        if (!public_to_vm(&args[i], &a[i])) {
            vm_api_diag(diags, "AXI-R025", "invalid contract argument value",
                        "use the exact declared kind and valid borrowed byte storage");
            goto done;
        }
    }
    if (m->manifest[ci].fuel_max < budget) budget = m->manifest[ci].fuel_max;
    V.m = &m->body;
    V.manifest = m->manifest;
    V.fuel_budget = budget;
    V.grants = grants;
    V.cap_generation = cap_generation;
    V.cap_secret = cap_secret;
    V.sink = sink;
    V.mod_path = mod_path;
    V.trusted_key_path = trusted_key_path;
    V.led = ledger;
    V.journal = journal;
    V.replay = replay;
    V.tr = trace;
    V.diags = diags;
    V.mem_account = mem_account;
    V.resources = resources;
    ok = run_cell(&V, ci, a, argc, &ret, 0, budget);
    if (ok) {
        axi_vval published;
        if (!vm_to_public(&ret, &published, 0)) {
            vtrap(&V, &m->body.cells[ci], m->body.cells[ci].nc, "AXI-R025",
                  "contract result has no public value representation",
                  "return one of the closed manifest scalar kinds");
            ok = 0;
        } else if (!storage && vm_result_uses_scratch(&V, &published)) {
            vm_api_diag(diags, "AXI-R025", "computed byte result needs an invocation owner",
                        "use an owned invocation or the scoped private embed door");
            ok = 0;
        } else {
            *out = published;
        }
    }
done:
    /* AX30: preserve the arena through public copy-out. Scalar-only direct
     * callers free it here; no thread-local storage, leak or dangling result. */
    if (V.json_scratch && storage && ok && vm_result_uses_scratch(&V, out)) {
        storage->bytes = V.json_scratch;
        storage->account = V.mem_account;
        V.json_scratch = NULL;
        V.json_scratch_reserved = 0;
    }
    if (V.json_scratch && !mem_account) vm_plain_scratch_free(&V);
    if (V.reg_slab || V.json_scratch_reserved || args_reserved) {
        axi_mem_failure_cause failure = mem_account->failure;
        size_t failed_request = mem_account->failed_request;
        axi_mem_failure_cause denied_failure = mem_account->denied_failure;
        size_t denied_request = mem_account->denied_request;
        int cleanup_ok = 1;
        if (V.reg_slab && !axi_mem_free(mem_account, V.reg_slab))
            cleanup_ok = 0;
        V.reg_slab = NULL;
        V.reg_slab_count = 0;
        V.reg_slab_used = 0;
        /* INV-704: the scratch bytes were owned by this invocation; the
         * account-owned alloc frees through the account, the pure-embed
         * malloc through the process heap. Both end after the register
         * slab. */
        if (V.json_scratch) {
            if (V.json_scratch_reserved) {
                if (!axi_mem_free(mem_account, V.json_scratch))
                    cleanup_ok = 0;
            } else {
                free(V.json_scratch);
            }
        }
        V.json_scratch = NULL;
        V.json_scratch_reserved = 0;
        if (args_reserved && !axi_mem_release(mem_account, sizeof a))
            cleanup_ok = 0;
        args_reserved = 0;
        if (cleanup_ok && failure != AXI_MEM_FAILURE_NONE) {
            mem_account->failure = failure;
            mem_account->failed_request = failed_request;
            mem_account->denied_failure = denied_failure;
            mem_account->denied_request = denied_request;
        }
        if (!cleanup_ok) {
            if (V.m && ci < V.m->n)
                vtrap(&V, &m->body.cells[ci], m->body.cells[ci].nc,
                      "AXI-R012", "VM memory-account cleanup is corrupt",
                      "discard the invocation and inspect AXI-MEM-ACCOUNT-v1 ownership");
            else
                vm_api_diag(diags, "AXI-R012",
                            "VM memory-account cleanup is corrupt",
                            "discard the invocation and inspect AXI-MEM-ACCOUNT-v1 ownership");
            ok = 0;
        }
    }
    if (fuel_used) *fuel_used = V.fuel_used;
    if (fuel_exhausted) *fuel_exhausted = V.trapped == 2;
    return ok;
}

int axi_vm_run_contract_cell_diag(const axb_contract_mod *m, uint32_t ci,
                                  const axi_vval *args, uint8_t argc,
                                  axi_vval *out, uint64_t fuel_budget,
                                  uint64_t *fuel_used,
                                  const axi_grants *grants, void *sink,
                                  axi_diags *diags)
{
    return run_contract_cell_diag_for_invocation(m, ci, args, argc, out,
                                                  fuel_budget, fuel_used, NULL,
                                                   grants, sink, diags, 0, NULL,
                                                   NULL, NULL, NULL, NULL, NULL,
                                                   NULL, 0, 0, NULL, NULL, NULL);
}

int axi_vm_run_contract_cell_preverified_pure_diag(
    const axb_contract_mod *m, uint32_t ci,
    const axi_vval *args, uint8_t argc, axi_vval *out,
    uint64_t fuel_budget, uint64_t *fuel_used, int *fuel_exhausted,
    axi_diags *diags)
{
    return run_contract_cell_diag_for_invocation(
        m, ci, args, argc, out, fuel_budget, fuel_used, fuel_exhausted,
        NULL, NULL, diags, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        1, 1, NULL, NULL, NULL);
}

int axi_vm_run_contract_cell_preverified_pure_scoped_diag(
    const axb_contract_mod *m, uint32_t ci,
    const axi_vval *args, uint8_t argc, axi_vval *out,
    uint64_t fuel_budget, uint64_t *fuel_used, int *fuel_exhausted,
    axi_diags *diags, axi_vm_output_storage *storage)
{
    if (!storage) return 0;
    return run_contract_cell_diag_for_invocation(
        m, ci, args, argc, out, fuel_budget, fuel_used, fuel_exhausted,
        NULL, NULL, diags, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        1, 1, NULL, NULL, storage);
}

int axi_vm_run_contract_cell_preverified_accounted_diag(
    const axb_contract_mod *m, uint32_t ci,
    const axi_vval *args, uint8_t argc, axi_vval *out,
    uint64_t fuel_budget, uint64_t *fuel_used, int *fuel_exhausted,
    axi_diags *diags, axi_mem_account *mem_account)
{
    if (!mem_account) {
        vm_api_diag(diags, "AXI-E001", "accounted VM call has no memory account",
                    "provide one invocation-owned AXI-MEM-ACCOUNT-v1 account");
        return 0;
    }
    return run_contract_cell_diag_for_invocation(
        m, ci, args, argc, out, fuel_budget, fuel_used, fuel_exhausted,
        NULL, NULL, diags, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        1, 1, mem_account, NULL, NULL);
}

static uint64_t invocation_generation_next(void)
{
    static uint64_t next_generation;
    uint64_t generation;
    generation = __atomic_add_fetch(&next_generation, 1u, __ATOMIC_RELAXED);
    if (generation == 0)
        generation = __atomic_add_fetch(&next_generation, 1u,
                                         __ATOMIC_RELAXED);
    return generation;
}

int axi_vm_contract_invocation_create(const axb_contract_mod *m,
                                      const axi_grants *grants,
                                      axi_vm_contract_invocation **out)
{
    axi_vm_contract_invocation *inv;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (!m || !grants || !out || axb_contract_v1_verify(m) != 0
            || axi_grants_verify(grants) != 0) return -1;
    inv = axi_calloc(1, sizeof *inv);
    if (!inv) return -1;
    if (axb_contract_v7_encode(m, &wire, &wire_len) != 0
            || axb_contract_v7_decode(&inv->owned_model, wire, wire_len) != 0
            || axi_platform_random(inv->secret, sizeof inv->secret) != 0) {
        free(wire);
        axb_contract_mod_free(&inv->owned_model);
        secure_zero(inv, sizeof *inv);
        free(inv);
        return -1;
    }
    free(wire);
    inv->model = &inv->owned_model;
    inv->grants = *grants;
    inv->generation = invocation_generation_next();
    *out = inv;
    return 0;
}

/* Trusted CLI admission already owns and verified the immutable model. This
 * constructor owns only invocation state and shallow-borrows that model. */
static int cli_contract_invocation_create_borrowed_accounted(
    const axb_contract_mod *model, const axi_grants *grants,
    axi_mem_account *account, axi_vm_contract_invocation **out)
{
    axi_vm_contract_invocation *inv;
    if (!model || !grants || !account || !out
            || axi_grants_verify(grants) != 0) return -1;
    inv = (axi_vm_contract_invocation *)axi_mem_calloc(account, 1, sizeof *inv);
    if (!inv) return -1;
    inv->model = model;
    inv->grants = *grants;
    inv->generation = invocation_generation_next();
    inv->account = account;
    if (axi_platform_random(inv->secret, sizeof inv->secret) != 0) {
        secure_zero(inv, sizeof *inv);
        (void)axi_mem_free(account, inv);
        return -1;
    }
    *out = inv;
    return 0;
}

int axi_vm_contract_invocation_cap(const axi_vm_contract_invocation *inv,
                                   const char *atom, axi_vval *out)
{
    uint32_t slot;
    size_t len;
    int rc = -1;
    if (!inv || !atom || !out) return -1;
    if (__atomic_load_n(&inv->consumed, __ATOMIC_ACQUIRE) != 0
            || axi_grants_cap_slot(&inv->grants, atom, &slot) != 0) goto done;
    len = strlen(atom);
    if (len == 0 || len >= AXI_CAPNAME) goto done;
    memset(out, 0, sizeof *out);
    out->kind = VB_CAP;
    out->cap_slot = slot;
    out->cap_generation = inv->generation;
    memcpy(out->cap_atom, inv->grants.name[slot], len + 1);
    out->atom_len = (uint32_t)len;
    cap_proof_v1(inv->secret, inv->model->body.root, slot, out->cap_atom,
                 out->atom_len, out->cap_proof);
    rc = 0;
done:
    return rc;
}

int axi_vm_contract_invocation_run_diag(axi_vm_contract_invocation *inv,
                                        uint32_t ci,
                                        const axi_vval *args, uint8_t argc,
                                        axi_vval *out, uint64_t fuel_budget,
                                        uint64_t *fuel_used, void *sink,
                                        axi_diags *diags)
{
    int rc;
    if (fuel_used) *fuel_used = 0;
    if (!inv) {
        vm_api_diag(diags, "AXI-R025", "contract invocation is absent or spent",
                    "create one invocation, mint its CAP values, and run it once");
        return 0;
    }
    if (__atomic_exchange_n(&inv->consumed, 1u, __ATOMIC_ACQ_REL) != 0) {
        vm_api_diag(diags, "AXI-R025", "contract invocation is absent or spent",
                    "create one invocation, mint its CAP values, and run it once");
        return 0;
    }
    rc = run_contract_cell_diag_for_invocation(
        inv->model, ci, args, argc, out, fuel_budget, fuel_used,
        NULL, &inv->grants, sink, diags, inv->generation, inv->secret,
        NULL, NULL, NULL, NULL, NULL, NULL, 0, 0, NULL, NULL, &inv->output_storage);
    return rc;
}

static int cli_hex_u64(const char *text, uint64_t *out)
{
    uint64_t value = 0;
    if (!out || !text || !*text || text[0] == '-' || text[0] == '+') return 0;
    for (; *text; text++) {
        unsigned digit;
        if (*text >= '0' && *text <= '9') digit = (unsigned)(*text - '0');
        else if (*text >= 'a' && *text <= 'f')
            digit = (unsigned)(*text - 'a') + 10u;
        else if (*text >= 'A' && *text <= 'F')
            digit = (unsigned)(*text - 'A') + 10u;
        else return 0;
        if (value > (UINT64_MAX - digit) / 16u) return 0;
        value = value * 16u + digit;
    }
    *out = value;
    return 1;
}

static int cli_i64(const char *text, uint64_t *out)
{
    uint64_t magnitude = 0;
    uint64_t limit;
    int negative = 0;
    if (!out || !text || !*text || text[0] == '+') return 0;
    if (*text == '-') { negative = 1; text++; }
    if (!*text) return 0;
    limit = negative ? (uint64_t)INT64_MAX + 1u : (uint64_t)INT64_MAX;
    for (; *text; text++) {
        unsigned digit;
        if (*text < '0' || *text > '9') return 0;
        digit = (unsigned)(*text - '0');
        if (magnitude > (limit - digit) / 10u) return 0;
        magnitude = magnitude * 10u + digit;
    }
    *out = negative ? UINT64_C(0) - magnitude : magnitude;
    return 1;
}

static int cli_contract_value(const axb_mtype *type, const char *text,
                              axi_vval *out)
{
    size_t len;
    memset(out, 0, sizeof *out);
    if (!type || !text) return 0;
    len = strlen(text);
    if (len > UINT32_MAX) return 0;
    switch (type->tag) {
    case AXB_MT_U64:
        out->kind = VB_U64;
        return axi_u64_parse(text, len, AXI_U64_ZERO_PERMITTED,
                             &out->bits) == AXI_U64_OK;
    case AXB_MT_I64:
        out->kind = VB_I64;
        return cli_i64(text, &out->bits);
    case AXB_MT_F64:
        out->kind = VB_F64;
        return len <= 16 && cli_hex_u64(text, &out->bits);
    case AXB_MT_BOOL:
    case AXB_MT_DECISION:
        out->kind = VB_BOOL;
        if (strcmp(text, "true") == 0) { out->bits = 1; return 1; }
        if (strcmp(text, "false") == 0) return 1;
        return 0;
    case AXB_MT_STR:
        out->kind = VB_STR; out->s = text; out->slen = (uint32_t)len;
        return 1;
    case AXB_MT_JSON:
        /* INV-323 / AXI-INV-105: JSON crosses the CLI through the one total
         * validator; malformed prefixes never become runtime strings.
         * INV-476 / AXI-INV-145: the trusted-v7 door keeps the typed cause
         * instead of a generic argument mismatch. */
        out->kind = VB_STR; out->s = text; out->slen = (uint32_t)len;
        if (axi_json_validate(text, len) != 0) {
            fprintf(AXI_ERR, "AXI-R025 invalid JSON document | fix: "
                    "the whole document must parse as JSON\n");
            return 0;
        }
        return 1;
    case AXB_MT_BYTES:
        out->kind = VB_BYTES; out->s = text; out->slen = (uint32_t)len;
        return 1;
    default:
        return 0;
    }
}

/* INV-428 / AXI-INV-138: run and replay derive one canonical invocation from
 * exactly-consumed options before signed evidence is admitted or emitted. */
typedef struct {
    char *p;
    size_t n, cap;
    int failed;
} cli_result_buf;

static void cli_result_raw(cli_result_buf *b, const char *bytes, size_t len)
{
    if (b->failed || b->n > b->cap || len > b->cap - b->n) {
        b->failed = 1;
        return;
    }
    memcpy(b->p + b->n, bytes, len);
    b->n += len;
}

static void cli_result_str(cli_result_buf *b, const char *text)
{
    cli_result_raw(b, text, strlen(text));
}

static void cli_result_u64(cli_result_buf *b, uint64_t value)
{
    char number[32];
    int n = snprintf(number, sizeof number, "%llu",
                     (unsigned long long)value);
    if (n < 0 || (size_t)n >= sizeof number) b->failed = 1;
    else cli_result_raw(b, number, (size_t)n);
}

static void cli_result_hex(cli_result_buf *b, const void *bytes, size_t len)
{
    static const char hex[] = "0123456789abcdef";
    const uint8_t *p = bytes;
    for (size_t i = 0; i < len && !b->failed; i++) {
        char pair[2] = {hex[p[i] >> 4], hex[p[i] & 15]};
        cli_result_raw(b, pair, sizeof pair);
    }
}

static const char *cli_result_type_name(uint8_t type)
{
    switch (type) {
    case AXB_MT_U64: return "u64";
    case AXB_MT_I64: return "i64";
    case AXB_MT_F64: return "f64";
    case AXB_MT_BOOL: return "bool";
    case AXB_MT_STR: return "str";
    case AXB_MT_BYTES: return "bytes";
    case AXB_MT_JSON: return "json";
    case AXB_MT_DECISION: return "decision";
    case AXB_MT_OK: return "ok";
    default: return NULL;
    }
}

static int cli_result_type_matches(uint8_t type, const axi_vval *value)
{
    if (!value) return 0;
    switch (type) {
    case AXB_MT_U64: return value->kind == VB_U64;
    case AXB_MT_I64: return value->kind == VB_I64;
    case AXB_MT_F64: return value->kind == VB_F64;
    case AXB_MT_BOOL:
    case AXB_MT_DECISION:
        return value->kind == VB_BOOL && value->bits <= 1;
    case AXB_MT_STR:
        return value->kind == VB_STR && (!value->slen || value->s);
    case AXB_MT_JSON:
        return value->kind == VB_STR && (!value->slen || value->s)
            && axi_json_validate(value->s, value->slen) == 0;
    case AXB_MT_BYTES:
        return value->kind == VB_BYTES && (!value->slen || value->s);
    case AXB_MT_OK: return value->kind == VB_UNIT;
    default: return 0;
    }
}

static int cli_result_error_ok(const axb_manifest *manifest,
                               const axi_vval *value)
{
    if (value->kind != VB_ERR || !value->atom || value->atom_len == 0
            || (value->slen && !value->s)) return 0;
    for (uint32_t i = 0; i < manifest->nerrors; i++)
        if (manifest->errors[i].len == value->atom_len
                && memcmp(manifest->errors[i].p, value->atom,
                          value->atom_len) == 0) return 1;
    return 0;
}

int axi_vm_contract_result_cli_render_accounted(
    const axb_manifest *manifest, const axi_vval *value,
    axi_mem_account *account, char **out, size_t *out_len)
{
    axi_vval payload;
    const char *name;
    uint8_t type = 0;
    uint32_t tag = 0;
    size_t binary_len = 0, cap;
    int tagged = 0;
    cli_result_buf b;
    if (!manifest || !value || !out || !out_len
            || axb_manifest_v1_verify(manifest) != 0) return 1;
    payload = *value;
    if (value->kind == VB_ERR) {
        size_t remaining;
        if (!cli_result_error_ok(manifest, value)) return 1;
        binary_len = (size_t)value->atom_len;
        remaining = (size_t)-1 - binary_len;
        if ((size_t)value->slen > remaining) return 1;
        binary_len += (size_t)value->slen;
    } else {
        if (value->kind == VB_UNION) {
            if (manifest->nreturns <= 1 || value->tag >= manifest->nreturns)
                return 1;
            tagged = 1;
            tag = value->tag;
            type = manifest->returns[tag].tag;
            payload.kind = value->payload_kind;
        } else {
            if (manifest->nreturns != 1) return 1;
            type = manifest->returns[0].tag;
        }
        name = cli_result_type_name(type);
        if (!name || !cli_result_type_matches(type, &payload)) return 1;
        if (payload.kind == VB_STR || payload.kind == VB_BYTES)
            binary_len = payload.slen;
    }
    if (binary_len > (AXB_CONTRACT_MAX_BYTES - 128u) / 2u
            || binary_len > ((size_t)-1 - 129u) / 2u) return 1;
    cap = 128u + binary_len * 2u;
    b.p = account ? axi_mem_alloc(account, cap + 1u) : axi_malloc(cap + 1u);
    if (!b.p) return 1;
    b.n = 0; b.cap = cap; b.failed = 0;
    if (tagged) {
        cli_result_str(&b, "union ");
        cli_result_u64(&b, tag);
        cli_result_str(&b, " ");
    }
    if (value->kind == VB_ERR) {
        cli_result_str(&b, "err ");
        cli_result_u64(&b, value->atom_len);
        cli_result_str(&b, " ");
        cli_result_hex(&b, value->atom, value->atom_len);
        cli_result_str(&b, " ");
        cli_result_u64(&b, value->slen);
        cli_result_str(&b, " ");
        cli_result_hex(&b, value->s, value->slen);
    } else {
        name = cli_result_type_name(type);
        cli_result_str(&b, name);
        if (type == AXB_MT_U64) {
            cli_result_str(&b, " "); cli_result_u64(&b, payload.bits);
        } else if (type == AXB_MT_I64) {
            cli_result_str(&b, " ");
            if (payload.bits >> 63) {
                cli_result_str(&b, "-");
                cli_result_u64(&b, UINT64_C(0) - payload.bits);
            } else cli_result_u64(&b, payload.bits);
        } else if (type == AXB_MT_F64) {
            uint8_t bits[8];
            for (int i = 0; i < 8; i++)
                bits[i] = (uint8_t)(payload.bits >> (56 - i * 8));
            cli_result_str(&b, " "); cli_result_hex(&b, bits, sizeof bits);
        } else if (type == AXB_MT_BOOL || type == AXB_MT_DECISION) {
            cli_result_str(&b, payload.bits ? " true" : " false");
        } else if (type != AXB_MT_OK) {
            cli_result_str(&b, " "); cli_result_u64(&b, payload.slen);
            cli_result_str(&b, " "); cli_result_hex(&b, payload.s, payload.slen);
        }
    }
    cli_result_str(&b, "\n");
    if (b.failed) {
        axi_mem_failure_cause failure = account ? account->failure
                                                : AXI_MEM_FAILURE_NONE;
        size_t failed_request = account ? account->failed_request : 0;
        int freed = account ? axi_mem_free(account, b.p) : (free(b.p), 1);
        if (account && freed && failure != AXI_MEM_FAILURE_NONE) {
            account->failure = failure;
            account->failed_request = failed_request;
        }
        return 1;
    }
    b.p[b.n] = '\0';
    *out = b.p;
    *out_len = b.n;
    return 0;
}

int axi_vm_contract_result_cli_render(const axb_manifest *manifest,
                                      const axi_vval *value,
                                      char **out, size_t *out_len)
{
    return axi_vm_contract_result_cli_render_accounted(
        manifest, value, NULL, out, out_len);
}

typedef struct {
    const char *positionals[AXB_MANIFEST_MAX_PARAMS];
    uint32_t npositionals;
    uint64_t budget;
    uint64_t mem_budget;
    axi_resource_vector resource_ceiling;
    uint64_t deadline_ms;
    uint64_t absolute_deadline_ns;
    int fuel_report;
    int mem_report;
    int trace;
    int ledger_report;
    const char *record_path;
    const char *recorder_key_path;
    const char *aer_path;
    const char *aer_key_path;
    const char *fs_root_path;
    int fuel_report_fd;
    int fs_root_fd;
    int have_absolute_deadline;
    int have_expected_root;
    uint8_t expected_root[32];
    char json[AXI_JSON_SCRATCH_SIZE];
    int have_json;
    uint32_t json_position;
    axi_grants grants;
} cli_contract_options;

typedef struct {
    axb_contract_mod model;
    axi_replay_v4_invocation replay_invocation;
    axi_replay_v4_binding binding;
    axi_replay_v4_terminal terminal;
    axi_vval args[AXB_MANIFEST_MAX_PARAMS];
    axi_vval output;
    axi_ledger ledger;
    axi_effect_journal journal;
    axi_replay replay;
    axi_trace trace;
    axi_resource_envelope resources;
    axi_aer1 aer;
    uint8_t aer_wire[AXI_AER1_SIGNED_SIZE];
    uint8_t producer_pk[32];
    uint8_t recorder_seed[32];
    uint8_t aer_seed[32];
} cli_run_fixed;

typedef struct {
    axb_contract_mod model;
    axi_replay_v4_invocation invocation;
    axi_replay_v4_episode episode;
    axi_vval args[AXB_MANIFEST_MAX_PARAMS];
    axi_vval output;
    axi_ledger ledger;
    axi_effect_journal journal;
    axi_trace trace;
    axi_resource_envelope resources;
    uint8_t producer_pk[32];
    uint8_t recorder_pk[32];
    uint8_t actual_output[AXI_REPLAY_V4_MAX_TERMINAL];
} cli_replay_fixed;

static int cli_resource_envelope_init(axi_resource_envelope *resources,
                                      const cli_contract_options *options)
{
    int ok = 0;
    uint64_t now_ns = axi_platform_monotonic_ns(NULL, &ok);
    uint64_t deadline_ns, duration_ns;
    if (!resources || !options || !ok)
        return 0;
    if (options->have_absolute_deadline) {
        deadline_ns = options->absolute_deadline_ns;
    } else {
        if (options->deadline_ms > UINT64_MAX / 1000000u) return 0;
        duration_ns = options->deadline_ms * 1000000u;
        if (now_ns > UINT64_MAX - duration_ns) return 0;
        deadline_ns = now_ns + duration_ns;
    }
    if (deadline_ns <= now_ns) return 0;
    axi_resource_envelope_init(resources, &options->resource_ceiling,
                                deadline_ns,
                                axi_platform_monotonic_ns, NULL);
    if (!axi_resource_envelope_valid(resources)) return 0;
    if (options->fs_root_path
            && axi_platform_fs_root_open(resources, options->fs_root_path) != 0)
        return 0;
    if (options->fs_root_fd >= 0
            && axi_platform_fs_root_adopt(resources, options->fs_root_fd) != 0)
        return 0;
    return 1;
}

typedef char cli_json_size_probe[
    sizeof(((cli_contract_options *)0)->json) == AXI_JSON_SCRATCH_SIZE ? 1 : -1];
typedef char cli_json_canonical_probe[
    AXI_JSON_SCRATCH_SIZE == 65536u ? 1 : -1];

static int cli_fixed_charge_size(size_t command_size, size_t *out)
{
    if (!out || command_size > (size_t)-1 - sizeof(cli_contract_options))
        return 0;
    *out = sizeof(cli_contract_options) + command_size;
    return 1;
}

int axi_vm_cli_account_manifest_probe(int replay,
                                      axi_vm_cli_account_manifest *out)
{
    size_t command;
    if (!out || (replay != 0 && replay != 1)) return -1;
    command = replay ? sizeof(cli_replay_fixed) : sizeof(cli_run_fixed);
    out->options = sizeof(cli_contract_options);
    out->command = command;
    out->json_scratch = AXI_JSON_SCRATCH_SIZE;
    return cli_fixed_charge_size(command, &out->fixed_charge) ? 0 : -1;
}

static int cli_replay_arg(const axb_mtype *type, const char *text,
                          axi_vval *value, axi_replay_v4_arg *wire);
static int cli_replay_output(const axb_manifest *manifest,
                             const axi_vval *value, uint8_t *kind,
                             uint32_t *tag,
                             uint8_t out[AXI_REPLAY_V4_MAX_TERMINAL],
                             uint32_t *len);

static void cli_contract_grants_sort(axi_grants *grants)
{
    int i, j;
    for (i = 1; i < grants->n; i++) {
        char name[AXI_CAPNAME];
        memcpy(name, grants->name[i], sizeof name);
        for (j = i; j > 0 && strcmp(grants->name[j - 1], name) > 0; j--)
            memcpy(grants->name[j], grants->name[j - 1], AXI_CAPNAME);
        memcpy(grants->name[j], name, AXI_CAPNAME);
    }
}

typedef enum {
    CLI_OPTIONS_INVALID = 0,
    CLI_OPTIONS_OK,
    CLI_OPTIONS_FUEL,
    CLI_OPTIONS_MEM,
    CLI_OPTIONS_RESOURCE,
    CLI_OPTIONS_CAP
} cli_options_status;

static cli_options_status cli_contract_options_parse(
                                       cli_contract_options *options,
                                       int argc, char **argv,
                                       int allow_record)
{
    int parsing = 1;
    int have_trusted = 0, have_fuel = 0, have_mem = 0;
    int have_calls = 0, have_input = 0, have_output = 0;
    int have_handles = 0, have_children = 0, have_deadline = 0;
    int have_record = 0, have_recorder = 0, have_aer = 0, have_aer_key = 0;
    int have_fs_root = 0;
    if (!options || argc < 0 || (argc && !argv)) return CLI_OPTIONS_INVALID;
    memset(options, 0, sizeof *options);
    options->fuel_report_fd = -1;
    options->fs_root_fd = -1;
    options->budget = VM_FUEL_DEFAULT;
    options->mem_budget = VM_MEM_DEFAULT;
    options->resource_ceiling.calls = VM_EFFECT_CALLS_DEFAULT;
    options->resource_ceiling.input_bytes = VM_EFFECT_BYTES_DEFAULT;
    options->resource_ceiling.output_bytes = VM_EFFECT_BYTES_DEFAULT;
    options->resource_ceiling.handles = VM_EFFECT_HANDLES_DEFAULT;
    options->resource_ceiling.children = VM_EFFECT_CHILDREN_DEFAULT;
    options->deadline_ms = VM_DEADLINE_NS_DEFAULT / 1000000u;
    axi_grants_init(&options->grants);
    for (int i = 0; i < argc; i++) {
        if (parsing && strcmp(argv[i], "--") == 0) {
            parsing = 0;
            continue;
        }
        if (!parsing) {
            if (options->npositionals >= AXB_MANIFEST_MAX_PARAMS)
                return CLI_OPTIONS_INVALID;
            options->positionals[options->npositionals++] = argv[i];
            continue;
        }
        if (strcmp(argv[i], "--trusted-key") == 0) {
            if (have_trusted || ++i >= argc || !argv[i][0])
                return CLI_OPTIONS_INVALID;
            have_trusted = 1;
            continue;
        }
        if (strcmp(argv[i], "--fs-root") == 0) {
            if (have_fs_root || ++i >= argc || !argv[i][0])
                return CLI_OPTIONS_INVALID;
            have_fs_root = 1;
            options->fs_root_path = argv[i];
            continue;
        }
        if (strcmp(argv[i], "--recorder-key") == 0) {
            if (have_recorder || ++i >= argc || !argv[i][0])
                return CLI_OPTIONS_INVALID;
            have_recorder = 1;
            options->recorder_key_path = argv[i];
            continue;
        }
        if (strcmp(argv[i], "--fuel") == 0) {
            if (have_fuel || ++i >= argc
                    || axi_u64_parse(argv[i], strlen(argv[i]),
                                     AXI_U64_POSITIVE_ONLY,
                                     &options->budget) != AXI_U64_OK)
                return CLI_OPTIONS_FUEL;
            have_fuel = 1;
            continue;
        }
        if (strcmp(argv[i], "--mem") == 0) {
            if (have_mem || ++i >= argc
                    || axi_u64_parse(argv[i], strlen(argv[i]),
                                     AXI_U64_POSITIVE_ONLY,
                                     &options->mem_budget) != AXI_U64_OK
                    || options->mem_budget > (uint64_t)SIZE_MAX)
                return CLI_OPTIONS_MEM;
            have_mem = 1;
            continue;
        }
#define PARSE_RESOURCE_OPTION(name, seen, field, policy) \
        if (strcmp(argv[i], name) == 0) { \
            if (seen || ++i >= argc \
                    || axi_u64_parse(argv[i], strlen(argv[i]), \
                                      policy, \
                                      &options->field) != AXI_U64_OK) \
                return CLI_OPTIONS_RESOURCE; \
            seen = 1; \
            continue; \
        }
        PARSE_RESOURCE_OPTION("--effect-calls", have_calls, resource_ceiling.calls,
                              AXI_U64_ZERO_PERMITTED)
        PARSE_RESOURCE_OPTION("--input-bytes", have_input, resource_ceiling.input_bytes,
                              AXI_U64_ZERO_PERMITTED)
        PARSE_RESOURCE_OPTION("--output-bytes", have_output, resource_ceiling.output_bytes,
                              AXI_U64_ZERO_PERMITTED)
        PARSE_RESOURCE_OPTION("--handles", have_handles, resource_ceiling.handles,
                              AXI_U64_ZERO_PERMITTED)
        PARSE_RESOURCE_OPTION("--children", have_children, resource_ceiling.children,
                              AXI_U64_ZERO_PERMITTED)
        PARSE_RESOURCE_OPTION("--deadline-ms", have_deadline, deadline_ms,
                              AXI_U64_POSITIVE_ONLY)
#undef PARSE_RESOURCE_OPTION
        if (strcmp(argv[i], "--cap") == 0) {
            if (++i >= argc || axi_grants_add(&options->grants, argv[i]) != 0)
                return CLI_OPTIONS_CAP;
            continue;
        }
        if (strcmp(argv[i], "--fuel-report") == 0) {
            if (options->fuel_report) return CLI_OPTIONS_INVALID;
            options->fuel_report = 1;
            continue;
        }
        if (strcmp(argv[i], "--_fuel-report-fd") == 0) {
            uint64_t fd;
            if (options->fuel_report_fd >= 0 || ++i >= argc
                    || axi_u64_parse(argv[i], strlen(argv[i]),
                                     AXI_U64_ZERO_PERMITTED,
                                     &fd) != AXI_U64_OK
                    || fd > 2147483647u)
                return CLI_OPTIONS_INVALID;
            options->fuel_report_fd = (int)fd;
            continue;
        }
        if (strcmp(argv[i], "--_deadline-ns") == 0) {
            if (options->have_absolute_deadline || ++i >= argc
                    || axi_u64_parse(argv[i], strlen(argv[i]),
                                     AXI_U64_POSITIVE_ONLY,
                                     &options->absolute_deadline_ns)
                       != AXI_U64_OK)
                return CLI_OPTIONS_INVALID;
            options->have_absolute_deadline = 1;
            continue;
        }
        if (strcmp(argv[i], "--_fs-root-fd") == 0) {
            uint64_t fd;
            if (options->fs_root_fd >= 0 || ++i >= argc
                    || axi_u64_parse(argv[i], strlen(argv[i]),
                                     AXI_U64_ZERO_PERMITTED, &fd) != AXI_U64_OK
                    || fd > 2147483647u)
                return CLI_OPTIONS_INVALID;
            options->fs_root_fd = (int)fd;
            continue;
        }
        if (strcmp(argv[i], "--_module-root") == 0) {
            if (options->have_expected_root || ++i >= argc
                    || decode_root_hex(argv[i], options->expected_root) != 0)
                return CLI_OPTIONS_INVALID;
            options->have_expected_root = 1;
            continue;
        }
        if (strcmp(argv[i], "--mem-report") == 0) {
            if (options->mem_report) return CLI_OPTIONS_INVALID;
            options->mem_report = 1;
            continue;
        }
        if (strcmp(argv[i], "--trace") == 0) {
            if (options->trace) return CLI_OPTIONS_INVALID;
            options->trace = 1;
            continue;
        }
        if (strcmp(argv[i], "--ledger") == 0) {
            if (options->ledger_report) return CLI_OPTIONS_INVALID;
            options->ledger_report = 1;
            continue;
        }
        if (strcmp(argv[i], "--ledger-json") == 0) {
            if (options->ledger_report) return CLI_OPTIONS_INVALID;
            options->ledger_report = 2;
            continue;
        }
        if (strcmp(argv[i], "--record") == 0) {
            if (!allow_record || have_record || ++i >= argc || !argv[i][0])
                return CLI_OPTIONS_INVALID;
            have_record = 1;
            options->record_path = argv[i];
            continue;
        }
        if (strcmp(argv[i], "--aer") == 0) {
            if (!allow_record || have_aer || ++i >= argc || !argv[i][0])
                return CLI_OPTIONS_INVALID;
            have_aer = 1;
            options->aer_path = argv[i];
            continue;
        }
        if (strcmp(argv[i], "--aer-key") == 0) {
            if (!allow_record || have_aer_key || ++i >= argc || !argv[i][0])
                return CLI_OPTIONS_INVALID;
            have_aer_key = 1;
            options->aer_key_path = argv[i];
            continue;
        }
        if (strcmp(argv[i], "--json") == 0) {
            if (options->have_json
                    || options->npositionals >= AXB_MANIFEST_MAX_PARAMS)
                return CLI_OPTIONS_INVALID;
            options->have_json = 1;
            options->json_position = options->npositionals;
            options->positionals[options->npositionals++] = NULL;
            continue;
        }
        if (strncmp(argv[i], "--", 2) == 0
                || options->npositionals >= AXB_MANIFEST_MAX_PARAMS)
            return CLI_OPTIONS_INVALID;
        options->positionals[options->npositionals++] = argv[i];
    }
    if (allow_record && (have_record != have_recorder))
        return CLI_OPTIONS_INVALID;
    if (allow_record && (have_aer != have_aer_key))
        return CLI_OPTIONS_INVALID;
    if (options->have_absolute_deadline
            && (options->fuel_report_fd < 0 || !options->have_expected_root))
        return CLI_OPTIONS_INVALID;
    if (options->fs_root_fd >= 0
            && (options->fuel_report_fd < 0 || !options->have_expected_root))
        return CLI_OPTIONS_INVALID;
    cli_contract_grants_sort(&options->grants);
    return CLI_OPTIONS_OK;
}

static int cli_contract_options_read_json(cli_contract_options *options)
{
    size_t n = 0;
    int ch;
    if (!options || !options->have_json) return 1;
    while (n + 1 < sizeof options->json && (ch = fgetc(AXI_IN)) != EOF)
        options->json[n++] = (char)ch;
    if (n + 1 == sizeof options->json) {
        /* INV-476 / AXI-INV-145: preserve the typed CA12 size refusal. */
        fprintf(AXI_ERR, "AXI-R010 --json payload exceeds %zu bytes\n",
                sizeof options->json - 1);
        return 0;
    }
    if (ferror(AXI_IN)) return 0;
    options->json[n] = '\0';
    options->positionals[options->json_position] = options->json;
    return 1;
}

static const char *cli_mem_failure_name(axi_mem_failure_cause cause)
{
    switch (cause) {
    case AXI_MEM_QUOTA_EXCEEDED: return "QUOTA_EXCEEDED";
    case AXI_MEM_HOST_OUT_OF_MEMORY: return "HOST_OUT_OF_MEMORY";
    case AXI_MEM_SIZE_OVERFLOW: return "SIZE_OVERFLOW";
    case AXI_MEM_ACCOUNT_CORRUPTION: return "ACCOUNT_CORRUPTION";
    default: return "NONE";
    }
}

static void cli_mem_denial_diag(const axi_mem_account *account)
{
    if (!account || account->denied_failure == AXI_MEM_FAILURE_NONE) return;
    fprintf(AXI_ERR,
            "AXI-R012 %s cause=%s limit=%zu live=%zu requested=%zu peak=%zu\n",
            AXI_MEM_ACCOUNT_PROTOCOL_ID,
            cli_mem_failure_name(account->denied_failure), account->limit,
            account->live, account->denied_request, account->peak);
}

static void cli_contract_options_diag(cli_options_status status,
                                      const char *command)
{
    if (status == CLI_OPTIONS_FUEL)
        fprintf(AXI_ERR, "AXI-R011 --fuel wants one canonical positive u64\n");
    else if (status == CLI_OPTIONS_MEM)
        fprintf(AXI_ERR, "AXI-R012 --mem wants one canonical positive u64 of bytes\n");
    else if (status == CLI_OPTIONS_RESOURCE)
        fprintf(AXI_ERR, "AXI-R026 resource ceilings want one canonical positive u64\n");
    else if (status == CLI_OPTIONS_CAP)
        fprintf(AXI_ERR, "AXI-R018 --cap wants distinct canonical authorities\n");
    else
        fprintf(AXI_ERR, "AXI-R025 invalid trusted-v7 %s option or argument\n",
                command);
}

static int cli_contract_prepare_args(const axb_manifest *manifest,
                                     const cli_contract_options *options,
                                     axi_vm_contract_invocation *run,
                                     axi_vval args[AXB_MANIFEST_MAX_PARAMS])
{
    uint32_t i;
    if (!manifest || !options || !run
            || options->npositionals != manifest->nparams) return 0;
    for (i = 0; i < manifest->nparams; i++) {
        const axb_mtype *type = &manifest->params[i].type;
        const char *text = options->positionals[i];
        if (type->tag != AXB_MT_CAP) {
            if (!cli_contract_value(type, text, &args[i])) return 0;
        } else if (strlen(text) != type->name.len
                || memcmp(text, type->name.p, type->name.len) != 0
                || axi_vm_contract_invocation_cap(run, text, &args[i]) != 0) {
            return 0;
        }
    }
    return 1;
}

static int cli_contract_invocation_run_accounted(
    axi_vm_contract_invocation *inv, uint32_t ci,
    const axi_vval *args, uint8_t argc, axi_vval *out,
    uint64_t fuel_budget, uint64_t *fuel_used, int *fuel_exhausted,
    void *sink, const char *mod_path, const char *trusted_key_path,
    axi_ledger *ledger, axi_effect_journal *journal, axi_replay *replay,
    axi_trace *trace, axi_mem_account *account,
    axi_resource_envelope *resources)
{
    if (!inv || !account || inv->account != account
            || __atomic_exchange_n(&inv->consumed, 1u,
                                   __ATOMIC_ACQ_REL) != 0) return 0;
    return run_contract_cell_diag_for_invocation(
        inv->model, ci, args, argc, out, fuel_budget, fuel_used,
        fuel_exhausted, &inv->grants, sink, NULL, inv->generation, inv->secret,
        mod_path, trusted_key_path, ledger, journal, replay, trace,
        1, 0, account, resources, &inv->output_storage);
}

static int cli_contract_replay_invocation(
    axi_replay_v4_invocation *invocation, const axb_manifest *manifest,
    uint32_t ci, const cli_contract_options *options,
    axi_vval args[AXB_MANIFEST_MAX_PARAMS])
{
    uint32_t i;
    if (!invocation || !manifest || !options
            || options->npositionals != manifest->nparams
            || options->grants.n > (int)AXI_REPLAY_V4_MAX_GRANTS) return 0;
    memset(invocation, 0, sizeof *invocation);
    invocation->cell_index = ci;
    invocation->operator_budget = options->budget;
    invocation->nargs = manifest->nparams;
    invocation->ngrants = (uint32_t)options->grants.n;
    for (i = 0; i < manifest->nparams; i++) {
        if (!cli_replay_arg(&manifest->params[i].type,
                            options->positionals[i], &args[i],
                            &invocation->args[i])) return 0;
    }
    for (i = 0; i < invocation->ngrants; i++)
        memcpy(invocation->grants[i], options->grants.name[i], AXI_CAPNAME);
    return 1;
}

static int cli_contract_trace_print(const axi_trace *trace)
{
    char hex[65];
    if (!trace || trace->oom || trace->steps == 0) {
        fprintf(AXI_ERR, "AXI-R013 the trace could not be recorded in full\n");
        return 0;
    }
    axi_trace_hex(trace, hex);
    fprintf(AXI_OUT, "TRACE %s steps=%llu\n", hex,
            (unsigned long long)trace->steps);
    return !ferror(AXI_OUT);
}

static void cli_contract_ledger_print(const axi_ledger *ledger, int format)
{
    char tip[65];
    if (!ledger || !format) return;
    axi_ledger_tip_hex(ledger, tip);
    if (format == 2) axi_ledger_print_json(ledger, AXI_OUT);
    else axi_ledger_print(ledger, AXI_OUT);
    fprintf(AXI_OUT, "LEDGER %s rows=%u\n", tip, ledger->n);
}

static void cli_aer_put64(uint8_t **p, uint64_t value)
{
    unsigned shift;
    for (shift = 64; shift != 0; shift -= 8)
        *(*p)++ = (uint8_t)(value >> (shift - 8));
}

static void cli_aer_domain_root(const char *domain, const void *bytes,
                                size_t len, uint8_t out[32])
{
    uint8_t buf[256];
    size_t domain_len = strlen(domain);
    if (domain_len > sizeof buf || len > sizeof buf - domain_len) {
        memset(out, 0, 32);
        return;
    }
    memcpy(buf, domain, domain_len);
    if (len) memcpy(buf + domain_len, bytes, len);
    axi_sha256(buf, domain_len + len, out);
}

static void cli_aer_budget_root(const cli_contract_options *options,
                                uint64_t fuel, uint8_t out[32])
{
    uint8_t bytes[9 * 8];
    uint8_t *p = bytes;
    cli_aer_put64(&p, options->budget);
    cli_aer_put64(&p, options->mem_budget);
    cli_aer_put64(&p, options->deadline_ms);
    cli_aer_put64(&p, fuel);
    cli_aer_put64(&p, options->resource_ceiling.calls);
    cli_aer_put64(&p, options->resource_ceiling.input_bytes);
    cli_aer_put64(&p, options->resource_ceiling.output_bytes);
    cli_aer_put64(&p, options->resource_ceiling.handles);
    cli_aer_put64(&p, options->resource_ceiling.children);
    cli_aer_domain_root("AXI-AER1-BUDGET-v1", bytes, sizeof bytes, out);
}

static int cli_aer_publish(cli_run_fixed *fixed,
                           const cli_contract_options *options,
                           uint64_t fuel, int successful)
{
    uint8_t terminal_state = 0;
    if (!fixed || !options || !options->aer_path) return 1;
    memset(&fixed->aer, 0, sizeof fixed->aer);
    if (successful && fixed->output.kind == VB_BOOL)
        fixed->aer.decision = fixed->output.bits ? AXI_AER1_DECISION_ALLOW
                                                 : AXI_AER1_DECISION_DENY;
    else fixed->aer.decision = AXI_AER1_DECISION_UNPROVEN;
    fixed->aer.attempt = fixed->resources.spent.calls
        ? AXI_AER1_ATTEMPT_ATTEMPTED : AXI_AER1_ATTEMPT_NOT_ATTEMPTED;
    if (fixed->journal.n)
        terminal_state = fixed->journal.row[fixed->journal.n - 1].state;
    if (!fixed->aer.attempt) fixed->aer.outcome = AXI_AER1_OUTCOME_NONE;
    else if (successful) fixed->aer.outcome = AXI_AER1_OUTCOME_COMMITTED;
    else if (terminal_state == AXI_JOURNAL_PARTIAL)
        fixed->aer.outcome = AXI_AER1_OUTCOME_PARTIAL;
    else fixed->aer.outcome = AXI_AER1_OUTCOME_FAILED;
    fixed->aer.evidence = !fixed->journal.oom
        && axi_effect_journal_verify(&fixed->journal) == 0
        && (!fixed->journal.n
            || !fixed->journal.row[fixed->journal.n - 1].evidence_failed);
    fixed->aer.coverage = fixed->aer.evidence && axi_coverage_v1_runtime_root(fixed->aer.coverage_root) == 0
        ? AXI_AER1_COVERAGE_PARTIAL : AXI_AER1_COVERAGE_UNKNOWN;
    fixed->aer.profile = AXI_AER1_PROFILE_DEV;
    fixed->aer.opacity = AXI_AER1_OPACITY_CLEAR;
    fixed->aer.maturity = AXI_AER1_MATURITY_TESTED;
    fixed->aer.has_artifact_root = 1;
    fixed->aer.has_policy_root = 1;
    if (fixed->aer.coverage != AXI_AER1_COVERAGE_UNKNOWN)
        fixed->aer.has_coverage_root = 1;
    cli_aer_domain_root("AXI-AER1-LOCAL-PRINCIPAL-v1", fixed->producer_pk,
                        sizeof fixed->producer_pk, fixed->aer.principal_root);
    memcpy(fixed->aer.artifact_root, fixed->model.body.root, 32);
    memcpy(fixed->aer.policy_root, fixed->model.body.root, 32);
    memcpy(fixed->aer.action_root, fixed->journal.tip, 32);
    cli_aer_budget_root(options, fuel, fixed->aer.budget_root);
    memcpy(fixed->aer.ledger_tip, fixed->ledger.tip, 32);
    memcpy(fixed->aer.journal_tip, fixed->journal.tip, 32);
    fixed->aer.fuel_used = fuel;
    fixed->aer.resources = fixed->resources.spent;
    return axi_aer1_encode_signed(&fixed->aer, fixed->aer_seed,
                                  fixed->aer_wire) == 0
        && axb_atomic_publish_bytes(fixed->aer_wire,
                                    sizeof fixed->aer_wire,
                                    options->aer_path) == 0;
}

int cmd_run_contract_trusted(const char *path, const char *cellname,
                             const char *trusted_key_path,
                             int argc, char **argv)
{
    cli_run_fixed fixed;
    axi_vm_contract_invocation *run = NULL;
    cli_contract_options options;
    axi_mem_account account;
    uint8_t *artifact = NULL, *episode = NULL;
    char *result_text = NULL;
    size_t artifact_len = 0, episode_len = 0, result_len = 0;
    size_t fixed_charge = 0, mem_peak = 0;
    uint64_t fuel = 0;
    uint32_t ci, i;
    int ok, fuel_exhausted = 0, fuel_report_ok = 1;
    int account_ready = 0, fixed_reserved = 0, mem_diag_printed = 0;
    int trace_ready = 0, trace_printed = 0, rc = 1;
    int aer_ready = 0, aer_published = 0;
    cli_options_status options_status;
    memset(&fixed, 0, sizeof fixed);
    options_status = cli_contract_options_parse(&options, argc, argv, 1);
    if (options_status != CLI_OPTIONS_OK) {
        cli_contract_options_diag(options_status, "run");
        goto done;
    }
    axi_mem_account_init(&account, (size_t)options.mem_budget);
    account_ready = 1;
    if (!cli_fixed_charge_size(sizeof fixed, &fixed_charge)
            || !axi_mem_reserve(&account, fixed_charge)) goto done;
    fixed_reserved = 1;
    if (!cli_contract_options_read_json(&options)) goto done;
    if (axi_trusted_pk_load(trusted_key_path, fixed.producer_pk) != 0) {
        fprintf(AXI_ERR, "AXI-N001 %s: trusted key must be one explicit "
                "32-byte raw public key\n", trusted_key_path ? trusted_key_path
                                                               : "<missing>");
        goto done;
    }
    if (axb_contract_v7_load_trusted_snapshot_accounted(
            &fixed.model, &artifact, &artifact_len, path, fixed.producer_pk,
            &account) != 0) {
        fprintf(AXI_ERR, "AXI-R025 %s: signed AXB v7 is not admitted by the "
                "selected trusted key\n", path ? path : "<missing>");
        goto done;
    }
    if (options.have_expected_root
            && memcmp(fixed.model.body.root, options.expected_root, 32) != 0) {
        fprintf(AXI_ERR, "AXI-R023 spawned module root changed | fix: run the "
                "exact artifact loaded by the parent\n");
        goto done;
    }
    ci = fixed.model.body.n;
    for (i = 0; i < fixed.model.body.n; i++)
        if (strcmp(fixed.model.body.cells[i].name, cellname) == 0) {
            ci = i; break;
        }
    if (ci == fixed.model.body.n) {
        fprintf(AXI_ERR, "AXI-R009 %s: no cell named `%s`\n", path, cellname);
        goto done;
    }
    if (options.npositionals != fixed.model.manifest[ci].nparams) {
        fprintf(AXI_ERR, "AXI-R025 %s: argument count does not match contract\n",
                cellname);
        goto done;
    }
    if (cli_contract_invocation_create_borrowed_accounted(
            &fixed.model, &options.grants, &account, &run) != 0) {
        fprintf(AXI_ERR, "AXI-R025 %s: cannot create contract invocation\n", path);
        goto done;
    }
    if (!cli_contract_prepare_args(&fixed.model.manifest[ci], &options,
                                   run, fixed.args)) {
        fprintf(AXI_ERR, "AXI-R025 %s: argument does not match contract or grant\n",
                cellname);
        goto done;
    }
    if (options.record_path) {
        if (!cli_contract_replay_invocation(
                &fixed.replay_invocation, &fixed.model.manifest[ci], ci,
                &options, fixed.args)
                || axi_replay_v4_binding_from_admitted_v7_accounted(
                    &fixed.binding, &fixed.model, fixed.producer_pk,
                    &fixed.replay_invocation, &account) != 0
                || axi_signing_seed_load(options.recorder_key_path,
                                         fixed.recorder_seed) != 0) {
            fprintf(AXI_ERR, "AXI-R025 signed replay binding is invalid\n");
            goto done;
        }
    }
    if (options.aer_path
            && axi_signing_seed_load(options.aer_key_path, fixed.aer_seed) != 0) {
        fprintf(AXI_ERR, "AXI-R025 AER signing key is invalid\n");
        goto done;
    }
    aer_ready = options.aer_path != NULL;
    axi_ledger_init_accounted(&fixed.ledger, fixed.model.body.root, &account);
    axi_effect_journal_init_accounted(&fixed.journal, fixed.model.body.root,
                                      &account);
    axi_replay_init_accounted(&fixed.replay, fixed.model.body.root, &account);
    if (!cli_resource_envelope_init(&fixed.resources, &options)) {
        fprintf(AXI_ERR, "AXI-R026 monotonic deadline unavailable\n");
        goto done;
    }
    if (options.record_path)
        axi_replay_set_mode(&fixed.replay, AXI_REPLAY_RECORD);
    if (options.trace) {
        axi_trace_init_accounted(&fixed.trace, fixed.model.body.root, &account);
        trace_ready = 1;
    }
    ok = cli_contract_invocation_run_accounted(
        run, ci, fixed.args, (uint8_t)options.npositionals, &fixed.output,
        options.budget, &fuel, &fuel_exhausted, AXI_OUT, path,
        trusted_key_path, &fixed.ledger, &fixed.journal,
        options.record_path ? &fixed.replay : NULL,
        trace_ready ? &fixed.trace : NULL, &account, &fixed.resources);
    if (options.fuel_report_fd >= 0) {
        axi_resource_vector child_report = fixed.resources.spent;
        child_report.handles = 0;
        if (axi_platform_report_fuel(options.fuel_report_fd, fuel,
                                     fuel_exhausted, &child_report) != 0) {
        fprintf(AXI_ERR, "AXI-R011 internal fuel report could not be written\n");
        fuel_report_ok = 0;
        }
    }
    if (trace_ready && ok) axi_trace_verdict(&fixed.trace, "ok");
    if (trace_ready && (fixed.trace.oom || fixed.trace.steps == 0)) {
        trace_printed = 1;
        (void)cli_contract_trace_print(&fixed.trace);
        goto publish_failure;
    }
    if (!ok || !fuel_report_ok || fixed.ledger.oom || fixed.journal.oom
            || fixed.replay.oom
            || axi_effect_journal_verify(&fixed.journal) != 0)
        goto publish_failure;
    if (axi_vm_contract_result_cli_render_accounted(
            &fixed.model.manifest[ci], &fixed.output, &account,
            &result_text, &result_len) != 0)
        goto publish_failure;
    if (options.record_path) {
        if (!cli_replay_output(&fixed.model.manifest[ci], &fixed.output,
                               &fixed.terminal.output_kind,
                               &fixed.terminal.output_tag,
                               fixed.terminal.output,
                               &fixed.terminal.output_len))
            goto publish_failure;
        fixed.terminal.total_fuel = fuel;
        fixed.terminal.journal_state = AXI_REPLAY_V4_JOURNAL_COMMITTED;
        memcpy(fixed.terminal.ledger_tip, fixed.ledger.tip,
               sizeof fixed.terminal.ledger_tip);
        memcpy(fixed.terminal.journal_tip, fixed.journal.tip,
               sizeof fixed.terminal.journal_tip);
        if (trace_ready)
            memcpy(fixed.terminal.trace_root, fixed.trace.h,
                   sizeof fixed.terminal.trace_root);
        if (axi_replay_v4_encode_signed_accounted(
                &fixed.binding, &fixed.replay, &fixed.terminal,
                fixed.recorder_seed, &account, &episode, &episode_len) != 0
                || axb_atomic_publish_bytes_accounted(
                    episode, episode_len, options.record_path, &account) != 0) {
            fprintf(AXI_ERR, "AXI-R019 signed replay evidence could not be saved\n");
            goto publish_failure;
        }
    }
    if (options.aer_path) {
        if (!cli_aer_publish(&fixed, &options, fuel, 1)) {
            fprintf(AXI_ERR, "AXI-R019 AER1 could not be published\n");
            goto publish_failure;
        }
        aer_published = 1;
    }
    if (fwrite(result_text, 1, result_len, AXI_OUT) != result_len)
        goto publish_failure;
    if (options.fuel_report)
        fprintf(AXI_OUT, "fuel %llu\n", (unsigned long long)fuel);
    cli_contract_ledger_print(&fixed.ledger, options.ledger_report);
    if (trace_ready) {
        trace_printed = 1;
        if (!cli_contract_trace_print(&fixed.trace)) goto publish_failure;
    }
    if (ferror(AXI_OUT)) goto publish_failure;
    mem_peak = account.peak;
    rc = 0;
    goto done;
publish_failure:
    if (aer_ready && !aer_published) {
        if (cli_aer_publish(&fixed, &options, fuel, 0)) aer_published = 1;
        else fprintf(AXI_ERR, "AXI-R019 negative AER1 could not be published\n");
    }
    if (trace_ready && !trace_printed && !fixed.trace.oom && fixed.trace.steps) {
        trace_printed = 1;
        (void)cli_contract_trace_print(&fixed.trace);
    }
    if (fixed.journal.n
            && axi_effect_journal_fprint(&fixed.journal, AXI_ERR) != 0)
        fprintf(AXI_ERR, "AXI-R025 contract effect evidence publication failed\n");
done:
    axi_platform_handles_close(&fixed.resources);
    axi_platform_fs_root_close(&fixed.resources);
    if (account_ready
            && !axi_resource_outputs_free(&fixed.resources, &account)) rc = 1;
    if (account_ready && account.denied_failure != AXI_MEM_FAILURE_NONE) {
        cli_mem_denial_diag(&account);
        mem_diag_printed = 1;
    }
    secure_zero(fixed.producer_pk, sizeof fixed.producer_pk);
    secure_zero(fixed.recorder_seed, sizeof fixed.recorder_seed);
    secure_zero(fixed.aer_seed, sizeof fixed.aer_seed);
    if (account_ready) {
        if (result_text && !axi_mem_free(&account, result_text)) rc = 1;
        if (!axi_replay_v4_buffer_release(&account, episode)) rc = 1;
        if (artifact && !axi_mem_free(&account, artifact)) rc = 1;
    } else {
        free(result_text);
        free(episode);
        free(artifact);
    }
    axi_trace_free(&fixed.trace);
    axi_replay_free(&fixed.replay);
    axi_effect_journal_free(&fixed.journal);
    axi_ledger_free(&fixed.ledger);
    axi_vm_contract_invocation_destroy(run);
    axb_contract_mod_free(&fixed.model);
    if (fixed_reserved && !axi_mem_release(&account, fixed_charge)) rc = 1;
    if (account_ready && (account.live != 0 || account.active_count != 0
            || account.fixed != 0)) {
        if (account.denied_failure == AXI_MEM_FAILURE_NONE) {
            account.denied_failure = AXI_MEM_ACCOUNT_CORRUPTION;
            account.denied_request = account.live;
        }
        rc = 1;
    }
    if (account_ready && !mem_diag_printed) cli_mem_denial_diag(&account);
    if (rc == 0 && options.mem_report) {
        if (fprintf(AXI_OUT, "mem %llu\n",
                    (unsigned long long)mem_peak) < 0) rc = 1;
    }
    return rc;
}

static uint8_t *cli_read_bounded(const char *path, size_t max, size_t *out_len,
                                 axi_mem_account *account)
{
    FILE *f;
    uint8_t *bytes = NULL;
    long len;
    int close_rc;
    if (out_len) *out_len = 0;
    if (!path || !*path || !out_len) return NULL;
    f = fopen(path, "rb");
    if (!f || fseek(f, 0, SEEK_END) != 0 || (len = ftell(f)) < 0
            || (size_t)len > max || fseek(f, 0, SEEK_SET) != 0) goto done;
    bytes = account ? (uint8_t *)axi_mem_alloc(
                          account, (size_t)len ? (size_t)len : 1)
                    : (uint8_t *)axi_malloc((size_t)len ? (size_t)len : 1);
    if (!bytes || fread(bytes, 1, (size_t)len, f) != (size_t)len
            || fgetc(f) != EOF || ferror(f)) {
        if (account) (void)axi_mem_free(account, bytes);
        else free(bytes);
        bytes = NULL;
        goto done;
    }
    close_rc = fclose(f);
    f = NULL;
    if (close_rc != 0) {
        if (account) (void)axi_mem_free(account, bytes);
        else free(bytes);
        return NULL;
    }
    *out_len = (size_t)len;
done:
    if (f) (void)fclose(f);
    return bytes;
}

static void cli_put_be64(uint8_t out[8], uint64_t value)
{
    int i;
    for (i = 0; i < 8; i++) out[i] = (uint8_t)(value >> (56 - i * 8));
}

static void cli_put_be32(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static int cli_zero_bytes(const uint8_t *bytes, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) if (bytes[i] != 0) return 0;
    return 1;
}

static int cli_replay_arg(const axb_mtype *type, const char *text,
                          axi_vval *value, axi_replay_v4_arg *wire)
{
    if (!cli_contract_value(type, text, value) || type->tag == AXB_MT_CAP)
        return 0;
    memset(wire, 0, sizeof *wire);
    wire->kind = type->tag;
    switch (type->tag) {
    case AXB_MT_U64:
    case AXB_MT_I64:
    case AXB_MT_F64:
        wire->len = 8; cli_put_be64(wire->bytes, value->bits); return 1;
    case AXB_MT_BOOL:
    case AXB_MT_DECISION:
        wire->len = 1; wire->bytes[0] = (uint8_t)value->bits; return 1;
    case AXB_MT_STR:
    case AXB_MT_BYTES:
    case AXB_MT_JSON:
        if (value->slen > sizeof wire->bytes) return 0;
        wire->len = value->slen;
        memcpy(wire->bytes, value->s, value->slen);
        return 1;
    default:
        return 0;
    }
}

static int cli_replay_output(const axb_manifest *manifest,
                             const axi_vval *value, uint8_t *kind,
                             uint32_t *tag, uint8_t out[AXI_REPLAY_V4_MAX_TERMINAL],
                             uint32_t *len)
{
    uint8_t declared;
    axi_vkind value_kind;
    *tag = AXI_REPLAY_V4_TAG_NONE;
    *len = 0;
    if (!manifest || !value) return 0;
    if (value->kind == VB_ERR) {
        size_t total = 8u + value->atom_len + value->slen;
        if (!value->atom || total > AXI_REPLAY_V4_MAX_TERMINAL) return 0;
        *kind = AXI_REPLAY_V4_KIND_ERR;
        cli_put_be32(out, value->atom_len);
        memcpy(out + 4, value->atom, value->atom_len);
        cli_put_be32(out + 4 + value->atom_len, value->slen);
        if (value->slen)
            memcpy(out + 8 + value->atom_len, value->s, value->slen);
        *len = (uint32_t)total;
        return 1;
    }
    if (value->kind == VB_UNION) {
        if (value->tag >= manifest->nreturns) return 0;
        *tag = value->tag;
        value_kind = value->payload_kind;
        declared = manifest->returns[value->tag].tag;
    } else {
        if (manifest->nreturns != 1) return 0;
        value_kind = value->kind;
        declared = manifest->returns[0].tag;
    }
    *kind = declared;
    if (declared == AXB_MT_OK && value_kind == VB_UNIT) return 1;
    if (value_kind == VB_U64 || value_kind == VB_I64 || value_kind == VB_F64) {
        *len = 8; cli_put_be64(out, value->bits);
    } else if (value_kind == VB_BOOL) {
        *len = 1; out[0] = (uint8_t)value->bits;
    } else {
        if (value->slen > AXI_REPLAY_V4_MAX_TERMINAL) return 0;
        *len = value->slen;
        memcpy(out, value->s, value->slen);
    }
    return 1;
}

int cmd_replay_contract_trusted(const char *replay_path, const char *path,
                                const char *cellname,
                                const char *trusted_key_path,
                                const char *recorder_key_path,
                                int argc, char **argv)
{
    cli_replay_fixed fixed;
    axi_vm_contract_invocation *run = NULL;
    cli_contract_options options;
    axi_mem_account account;
    char *result_text = NULL;
    size_t result_len = 0, fixed_charge = 0, mem_peak = 0;
    uint8_t *artifact = NULL, *wire = NULL, actual_kind;
    size_t artifact_len = 0, wire_len = 0;
    uint64_t fuel = 0;
    uint32_t ci, actual_tag, actual_len, i;
    int account_ready = 0, fixed_reserved = 0, mem_diag_printed = 0;
    int ok, trace_ready = 0, terminal_has_trace, rc = 1;
    cli_options_status options_status;
    memset(&fixed, 0, sizeof fixed);
    options_status = cli_contract_options_parse(&options, argc, argv, 0);
    if (options_status != CLI_OPTIONS_OK) {
        cli_contract_options_diag(options_status, "replay");
        goto done;
    }
    axi_mem_account_init(&account, (size_t)options.mem_budget);
    account_ready = 1;
    if (!cli_fixed_charge_size(sizeof fixed, &fixed_charge)
            || !axi_mem_reserve(&account, fixed_charge)) goto done;
    fixed_reserved = 1;
    axi_replay_v4_episode_init_accounted(&fixed.episode, &account);
    if (!cli_contract_options_read_json(&options)) goto done;
    if (axi_trusted_pk_load(trusted_key_path, fixed.producer_pk) != 0
            || axi_trusted_pk_load(recorder_key_path, fixed.recorder_pk) != 0) {
        fprintf(AXI_ERR, "AXI-R025 replay requires explicit raw producer and recorder keys\n");
        goto done;
    }
    if (axb_contract_v7_load_trusted_snapshot_accounted(
            &fixed.model, &artifact, &artifact_len, path, fixed.producer_pk,
            &account) != 0) {
        fprintf(AXI_ERR, "AXI-R025 replay module is not trusted signed AXB v7\n");
        goto done;
    }
    ci = fixed.model.body.n;
    for (i = 0; i < fixed.model.body.n; i++)
        if (strcmp(fixed.model.body.cells[i].name, cellname) == 0) {
            ci = i; break;
        }
    if (ci == fixed.model.body.n) goto bad_invocation;
    if (!cli_contract_replay_invocation(
            &fixed.invocation, &fixed.model.manifest[ci], ci, &options,
            fixed.args))
        goto bad_invocation;
    wire = cli_read_bounded(replay_path, AXI_REPLAY_V4_MAX_ENCODED, &wire_len,
                            &account);
    if (!artifact || !wire
            || axi_replay_v4_decode_admitted_v7_trusted_accounted(
                   &fixed.episode, wire, wire_len, &fixed.model,
                   fixed.producer_pk, &fixed.invocation, fixed.recorder_pk,
                   &account) != 0) {
        fprintf(AXI_ERR, "AXI-R025 replay episode is not admitted by this invocation\n");
        goto done;
    }
    if (cli_contract_invocation_create_borrowed_accounted(
            &fixed.model, &options.grants, &account, &run) != 0)
        goto done;
    if (!cli_contract_prepare_args(&fixed.model.manifest[ci], &options,
                                   run, fixed.args))
        goto bad_invocation;
    axi_ledger_init_accounted(&fixed.ledger, fixed.model.body.root, &account);
    axi_effect_journal_init_accounted(&fixed.journal, fixed.model.body.root,
                                      &account);
    if (!cli_resource_envelope_init(&fixed.resources, &options)) {
        fprintf(AXI_ERR, "AXI-R026 monotonic deadline unavailable\n");
        goto done;
    }
    terminal_has_trace = !cli_zero_bytes(fixed.episode.terminal.trace_root, 32);
    if (options.trace || terminal_has_trace) {
        axi_trace_init_accounted(&fixed.trace, fixed.model.body.root, &account);
        trace_ready = 1;
    }
    ok = cli_contract_invocation_run_accounted(
        run, ci, fixed.args, (uint8_t)options.npositionals, &fixed.output,
        options.budget, &fuel, NULL, NULL, path, trusted_key_path,
        &fixed.ledger, &fixed.journal, &fixed.episode.effects,
        trace_ready ? &fixed.trace : NULL, &account, &fixed.resources);
    if (trace_ready && ok) axi_trace_verdict(&fixed.trace, "ok");
    if (!ok || fixed.ledger.oom || fixed.journal.oom
            || axi_effect_journal_verify(&fixed.journal) != 0
            || !axi_replay_at_end(&fixed.episode.effects)
            || !cli_replay_output(&fixed.model.manifest[ci], &fixed.output,
                                  &actual_kind, &actual_tag, fixed.actual_output,
                                  &actual_len)
            || actual_kind != fixed.episode.terminal.output_kind
            || actual_tag != fixed.episode.terminal.output_tag
            || actual_len != fixed.episode.terminal.output_len
            || memcmp(fixed.actual_output, fixed.episode.terminal.output,
                      actual_len) != 0
            || fuel != fixed.episode.terminal.total_fuel
            || (terminal_has_trace
                && (!trace_ready || fixed.trace.oom
                    || memcmp(fixed.trace.h,
                              fixed.episode.terminal.trace_root, 32) != 0))
            || memcmp(fixed.ledger.tip, fixed.episode.terminal.ledger_tip,
                      32) != 0
            || memcmp(fixed.journal.tip, fixed.episode.terminal.journal_tip,
                      32) != 0
            || fixed.episode.terminal.journal_state
                != AXI_REPLAY_V4_JOURNAL_COMMITTED)
        goto done;
    if (axi_vm_contract_result_cli_render_accounted(
            &fixed.model.manifest[ci], &fixed.output, &account,
            &result_text, &result_len) != 0)
        goto done;
    if (fwrite(result_text, 1, result_len, AXI_OUT) != result_len) goto done;
    if (options.fuel_report)
        fprintf(AXI_OUT, "fuel %llu\n", (unsigned long long)fuel);
    cli_contract_ledger_print(&fixed.ledger, options.ledger_report);
    if (options.trace && !cli_contract_trace_print(&fixed.trace)) goto done;
    if (!ferror(AXI_OUT)) {
        mem_peak = account.peak;
        rc = 0;
    }
    goto done;
bad_invocation:
    fprintf(AXI_ERR, "AXI-R025 replay invocation does not match the cell contract\n");
done:
    axi_platform_handles_close(&fixed.resources);
    axi_platform_fs_root_close(&fixed.resources);
    if (account_ready
            && !axi_resource_outputs_free(&fixed.resources, &account)) rc = 1;
    if (account_ready && account.denied_failure != AXI_MEM_FAILURE_NONE) {
        cli_mem_denial_diag(&account);
        mem_diag_printed = 1;
    }
    secure_zero(fixed.producer_pk, sizeof fixed.producer_pk);
    secure_zero(fixed.recorder_pk, sizeof fixed.recorder_pk);
    if (account_ready) {
        if (result_text && !axi_mem_free(&account, result_text)) rc = 1;
        if (wire && !axi_mem_free(&account, wire)) rc = 1;
        if (artifact && !axi_mem_free(&account, artifact)) rc = 1;
    } else {
        free(result_text);
        free(wire);
        free(artifact);
    }
    axi_trace_free(&fixed.trace);
    axi_effect_journal_free(&fixed.journal);
    axi_ledger_free(&fixed.ledger);
    axi_vm_contract_invocation_destroy(run);
    axi_replay_v4_episode_free(&fixed.episode);
    axb_contract_mod_free(&fixed.model);
    if (fixed_reserved && !axi_mem_release(&account, fixed_charge)) rc = 1;
    if (account_ready && (account.live != 0 || account.active_count != 0
            || account.fixed != 0)) {
        if (account.denied_failure == AXI_MEM_FAILURE_NONE) {
            account.denied_failure = AXI_MEM_ACCOUNT_CORRUPTION;
            account.denied_request = account.live;
        }
        rc = 1;
    }
    if (account_ready && !mem_diag_printed) cli_mem_denial_diag(&account);
    if (rc == 0 && options.mem_report) {
        if (fprintf(AXI_OUT, "mem %llu\n",
                    (unsigned long long)mem_peak) < 0) rc = 1;
    }
    return rc;
}

void axi_vm_contract_invocation_destroy(axi_vm_contract_invocation *inv)
{
    axi_mem_account *account;
    if (!inv) return;
    account = inv->account;
    axi_vm_output_storage_release(&inv->output_storage);
    if (!account) axb_contract_mod_free(&inv->owned_model);
    secure_zero(inv, sizeof *inv);
    if (account) (void)axi_mem_free(account, inv);
    else free(inv);
}

int axi_vm_run_cell(const axb_mod *m, uint32_t ci,
                    const axi_vval *args, uint8_t argc,
                    axi_vval *out, uint64_t fuel_budget,
                    uint64_t *fuel_used,
                    const axi_grants *grants, void *sink)
{
    return axi_vm_run_cell_diag(m, ci, args, argc, out, fuel_budget,
                                fuel_used, grants, sink, NULL);
}
