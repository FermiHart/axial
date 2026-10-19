/* axial — AXB assembler/disassembler (W08). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * Round-trip law: asm(dis(asm(x))) == asm(x), byte-equal. The gate
 * enforces it; a format drift is a gate failure, not an opinion.
 * Text form (.axs) is canonical: dis output IS the canonical spelling.
 */
#include "axi_bc.h"
#include "axi.h"   /* axi_str_unescape: the one string decoder door */
#include "axi_string.h"
#include "axi_alloc.h"
#include "axi_arena.h"
#include "axi_builtin.h"
#include "axi_checker_identity.h"
#include "axi_contract.h"
#include "axi_hash.h"
#include "axi_replay_v4.h"
#include "axi_sign.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>

/* The archival codec and CA17 executable-body provenance retain the historical
 * v5 framing. Production identity is the exact unsigned AXB v7 container. */
#define AXB_EXEC_BODY_VERSION AXB_ARCHIVE_VERSION
#include "axi_osif.h"   /* AXI-INV-064: one door for the streams */

/* ---- one truth table ---------------------------------------------- */
static const axb_opinfo OPINFO[OP__COUNT] = {
#define X(up, nm, ops, fuel, doc) { nm, ops, fuel },
    AXB_OPCODES(X)
#undef X
};

const axb_opinfo *axb_op_info(uint8_t op) {
    return op < OP__COUNT ? &OPINFO[op] : NULL;
}

axb_compat axb_version_compat(uint32_t version)
{
    /* AXI-INV-152: compatibility classifies bytes; it never widens the loader. */
    if (version == AXB_VERSION) return AXB_COMPAT_CURRENT;
    if (version == AXB_ARCHIVE_VERSION || version == AXB_PREVIOUS_VERSION)
        return AXB_COMPAT_REASSEMBLE;
    return AXB_COMPAT_UNSUPPORTED;
}

void axb_checker_protocol_id(uint8_t out[32])
{
    static const char protocol[] = "AXI-CHECKED-SEAL-v1";
    axi_sha256(protocol, sizeof protocol, out);
}

void axb_checker_semantics_root(uint8_t out[32])
{
    static const char semantics[] =
        "AXI-CHECKER-SEMANTICS-v1\0"
        AXI_CHECKER_SOURCE_ROOT_HEX "\0"
#define X(up, nm, ops, fuel, doc) #up "\0" nm "\0" #ops "\0" #fuel "\0" doc "\0"
        AXB_OPCODES(X)
#undef X
        ;
    axi_sha256(semantics, sizeof semantics, out);
}
int axb_op_by_name(const char *nm, size_t len) {
    for (int i = 0; i < OP__COUNT; i++)
        if (strlen(OPINFO[i].name) == len && memcmp(OPINFO[i].name, nm, len) == 0)
            return i;
    return -1;
}

/* W19: an effect operand is an INDEX into the module's own declared authority.
 * There is no by-name lookup at runtime and no computed name — the reviewer's
 * list and the VM's list are the same list /AXI-INV-036/. */
int axb_mod_eff_index(const axb_mod *m, const char *name) {
    for (uint32_t i = 0; i < m->neff; i++)
        if (strcmp(m->eff[i], name) == 0) return (int)i;
    return -1;
}
int axb_mod_builtin_index(const axb_mod *m, const char *name) {
    for (uint32_t i = 0; i < m->nbuiltin; i++)
        if (strcmp(m->builtin[i], name) == 0) return (int)i;
    return -1;
}

/* ---- in-memory module: types live in axi_bc.h (VM shares them) -----
 * Two lifetimes, both live (owner rule):
 *   builder modules (cmd_asm) — malloc'd piecemeal, axb_mod_free;
 *   loaded modules (run/dis)  — arena-backed (W11), freed wholesale.  */
static int account_free_preserve_failure(axi_mem_account *account, void *ptr);

void axb_mod_free(axb_mod *m) {
    axi_mem_account *account;
    if (!m) return;
    account = m->builder_account;
    for (uint32_t i = 0; i < m->n; i++) {
        axb_cell *c = &m->cells[i];
        for (uint32_t j = 0; j < c->nk; j++)
            (void)account_free_preserve_failure(account, c->k[j].s);
        (void)account_free_preserve_failure(account, c->name);
        (void)account_free_preserve_failure(account, c->k);
        (void)account_free_preserve_failure(account, c->code);
    }
    for (uint32_t i = 0; i < m->neff; i++)
        (void)account_free_preserve_failure(account, m->eff[i]);
    for (uint32_t i = 0; i < m->nbuiltin; i++)
        (void)account_free_preserve_failure(account, m->builtin[i]);
    (void)account_free_preserve_failure(account, m->cells);
    memset(m, 0, sizeof *m);
}

/* ---- deterministic little-endian writer ---------------------------- */
typedef struct {
    uint8_t *p;
    size_t len, cap, max;
    axi_mem_account *account;
    int oom;
} wbuf;

static void wb_grow(wbuf *w, size_t need);
static void wb_raw(wbuf *w, const void *src, size_t n);
static void wb_u8(wbuf *w, uint8_t v);
static void wb_u32(wbuf *w, uint32_t v);
static void wb_u64(wbuf *w, uint64_t v);
static void mod_head_emit(const axb_mod *m, uint32_t version, wbuf *w);
static void cell_emit(const axb_cell *c, wbuf *w);
static void cell_name_emit(const axb_cell *c, wbuf *w);
static void cell_tail_emit(const axb_cell *c, wbuf *w);

static int account_free_preserve_failure(axi_mem_account *account, void *ptr)
{
    axi_mem_failure_cause failure;
    size_t failed_request;
    int freed;
    if (!account) {
        free(ptr);
        return 1;
    }
    failure = account->failure;
    failed_request = account->failed_request;
    freed = axi_mem_free(account, ptr);
    if (freed && failure != AXI_MEM_FAILURE_NONE) {
        account->failure = failure;
        account->failed_request = failed_request;
    }
    return freed;
}

static int account_release_preserve_failure(axi_mem_account *account,
                                            size_t size)
{
    axi_mem_failure_cause failure;
    size_t failed_request;
    int released;
    if (!account) return 1;
    failure = account->failure;
    failed_request = account->failed_request;
    released = axi_mem_release(account, size);
    if (released && failure != AXI_MEM_FAILURE_NONE) {
        account->failure = failure;
        account->failed_request = failed_request;
    }
    return released;
}

static void wb_overflow(wbuf *w)
{
    if (w->account)
        (void)axi_mem_realloc(w->account, w->p, (size_t)-1);
    w->oom = 1;
}

static void wb_free(wbuf *w)
{
    (void)account_free_preserve_failure(w->account, w->p);
    w->p = NULL;
    w->len = w->cap = 0;
}

static void wb_grow(wbuf *w, size_t need) {
    uint8_t *p;
    size_t required, nc;
    if (w->oom) return;
    if (w->max && (w->len > w->max || need > w->max - w->len)) {
        w->oom = 1;
        return;
    }
    if (need > (size_t)-1 - w->len) { wb_overflow(w); return; }
    required = w->len + need;
    if (required <= w->cap) return;
    if (w->cap > (size_t)-1 / 2) { wb_overflow(w); return; }
    nc = w->cap ? w->cap * 2 : 256;
    while (nc < required) {
        if (nc > (size_t)-1 / 2) { wb_overflow(w); return; }
        nc *= 2;
    }
    p = w->account ? axi_mem_realloc(w->account, w->p, nc)
                   : axi_realloc(w->p, nc);
    if (!p) { w->oom = 1; return; }
    w->p = p;
    w->cap = nc;
}
static void wb_raw(wbuf *w, const void *src, size_t n) {
    wb_grow(w, n);
    if (w->oom) return;
    memcpy(w->p + w->len, src, n); w->len += n;
}
static void wb_u8(wbuf *w, uint8_t v)  { wb_raw(w, &v, 1); }
static void wb_u32(wbuf *w, uint32_t v) {
    uint8_t b[4] = { (uint8_t)v, (uint8_t)(v>>8), (uint8_t)(v>>16), (uint8_t)(v>>24) };
    wb_raw(w, b, 4);
}
static void wb_u64(wbuf *w, uint64_t v) {
    wb_u32(w, (uint32_t)v); wb_u32(w, (uint32_t)(v >> 32));
}

static void cell_name_emit(const axb_cell *c, wbuf *w) {
    uint32_t nl = (uint32_t)strlen(c->name);
    wb_u32(w, nl); wb_raw(w, c->name, nl);
}

static void cell_tail_emit(const axb_cell *c, wbuf *w) {
    wb_u32(w, c->nregs);
    wb_u32(w, c->nk);
    for (uint32_t j = 0; j < c->nk; j++) {
        const axb_konst *k = &c->k[j];
        wb_u8(w, k->tag);
        if (k->tag == AXB_KSTR || k->tag == AXB_KERR) {
            wb_u32(w, k->slen); wb_raw(w, k->s, k->slen);
        } else wb_u64(w, k->u);
    }
    wb_u32(w, c->nc);
    for (uint32_t j = 0; j < c->nc; j++) wb_u32(w, c->code[j]);
}

/* INV-385 / AXI-INV-124: these two pieces are the sole cell-body encoder. */
static void cell_emit(const axb_cell *c, wbuf *w) {
    cell_name_emit(c, w);
    cell_tail_emit(c, w);
}

int axb_cell_body_hash_v1_accounted(const axb_cell *cell, uint8_t out[32],
                                     axi_mem_account *account)
{
    static const uint8_t domain[] = "AXI-CELL-BODY-v1";
    wbuf w = {0};
    uint8_t hash[32];
    uint32_t i;
    if (!out) return 1;
    if (!cell || !cell->name || (cell->nk && !cell->k)
            || (cell->nc && !cell->code)) return 1;
    for (i = 0; i < cell->nk; i++)
        if (cell->k[i].tag < AXB_KU64 || cell->k[i].tag > AXB_KERR
                || ((cell->k[i].tag == AXB_KSTR
                     || cell->k[i].tag == AXB_KERR) && !cell->k[i].s))
            return 1;
    w.account = account;
    wb_raw(&w, domain, sizeof domain); /* sizeof includes exactly one NUL. */
    cell_emit(cell, &w);
    if (w.oom) { wb_free(&w); return 1; }
    axi_sha256(w.p, w.len, hash);
    wb_free(&w);
    memcpy(out, hash, sizeof hash);
    return 0;
}

int axb_cell_body_hash_v1(const axb_cell *cell, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    return axb_cell_body_hash_v1_accounted(cell, out, NULL);
}

/* AXI-CA17: stable compiler identity string. The hash is reproducible across
 * rebuilds because the ID contains no path, timestamp or build host. */
void axb_compiler_hash(uint8_t out[32])
{
    static const char id[] = "AXI-CA17-COMPILER-v1 c99";
    if (!out) return;
    axi_sha256(id, sizeof id - 1, out);
}

void axb_artifact_abi_id(uint8_t out[32])
{
    static const uint8_t domain[] = "AXI-ARTIFACT-ABI-v1";
    static const uint32_t versions[] = {
        AXB_ARCHIVE_VERSION,
        AXB_PREVIOUS_VERSION,
        AXB_VERSION,
        AXB_MANIFEST_VERSION,
        AXBS_VERSION,
        AXPC_VERSION,
        AXI_REPLAY_V4_VERSION,
        AXI_REPLAY_V4_SIG_VERSION,
        AXI_DIAG_SCHEMA_VERSION
    };
    uint8_t identity[sizeof domain - 1u + sizeof versions];
    size_t off = sizeof domain - 1u;
    size_t i;
    if (!out) return;
    memcpy(identity, domain, sizeof domain - 1u);
    for (i = 0; i < sizeof versions / sizeof versions[0]; i++) {
        identity[off++] = (uint8_t)versions[i];
        identity[off++] = (uint8_t)(versions[i] >> 8);
        identity[off++] = (uint8_t)(versions[i] >> 16);
        identity[off++] = (uint8_t)(versions[i] >> 24);
    }
    axi_sha256(identity, sizeof identity, out); /* AXI-INV-153 */
}

/* AXI-CA17 / AXI-INV-139: stable executable-body provenance is the SHA-256 of
 * the historical v5 executable framing (header + cells, no manifests/trailer).
 * It is not the runtime root: root names exact unsigned production-v7 bytes. */
int axb_mod_body_hash_accounted(const axb_mod *m, uint8_t out[32],
                                 axi_mem_account *account)
{
    wbuf w = {0};
    uint8_t hash[32];
    uint32_t i;
    if (!out) return 1;
    if (!m || m->n > 256 || m->neff > AXB_MAX_EFF
            || m->nbuiltin > AXB_MAX_BUILTIN) return 1;
    w.account = account;
    w.max = AXB_CONTRACT_MAX_BYTES;
    mod_head_emit(m, AXB_EXEC_BODY_VERSION, &w);
    for (i = 0; i < m->n && !w.oom; i++) cell_emit(&m->cells[i], &w);
    if (w.oom) { wb_free(&w); return 1; }
    axi_sha256(w.p, w.len, hash);
    wb_free(&w);
    memcpy(out, hash, sizeof hash);
    return 0;
}

int axb_mod_body_hash(const axb_mod *m, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    return axb_mod_body_hash_accounted(m, out, NULL);
}

int axb_mod_semantic_hash_v1(const axb_mod *m, uint8_t out[32])
{
    static const uint8_t domain[] = "AXI-MIGRATION-SEMANTICS-v1";
    wbuf w = {0};
    uint32_t i;
    if (!out) return 1;
    memset(out, 0, 32);
    if (!m || axb_mod_verify(m, "<migration>", NULL) != 0) return 1;
    w.max = AXB_CONTRACT_MAX_BYTES;
    wb_raw(&w, domain, sizeof domain);
    wb_u32(&w, m->neff);
    for (i = 0; i < m->neff; i++) {
        size_t len = strlen(m->eff[i]);
        if (len > UINT32_MAX) { w.oom = 1; break; }
        wb_u32(&w, (uint32_t)len);
        wb_raw(&w, m->eff[i], len);
    }
    wb_u32(&w, m->nbuiltin);
    for (i = 0; i < m->nbuiltin && !w.oom; i++) {
        size_t len = strlen(m->builtin[i]);
        if (len > UINT32_MAX) { w.oom = 1; break; }
        wb_u32(&w, (uint32_t)len);
        wb_raw(&w, m->builtin[i], len);
    }
    wb_u32(&w, m->n);
    for (i = 0; i < m->n && !w.oom; i++) cell_emit(&m->cells[i], &w);
    if (w.oom) { free(w.p); return 1; }
    axi_sha256(w.p, w.len, out);
    free(w.p);
    return 0;
}

static int derivation_all_zero(const uint8_t h[32])
{
    int i;
    for (i = 0; i < 32; i++) if (h[i] != 0) return 0;
    return 1;
}

static void mod_head_emit(const axb_mod *m, uint32_t version, wbuf *w) {
    wb_raw(w, AXB_MAGIC, 4);
    wb_u32(w, version);
    wb_raw(w, m->src_hash, 32);       /* W14: src binding lives in the header */
    /* W19: declared authority lives in the header, before any code: whoever
     * reads the container reads what it may do before what it does. */
    wb_u32(w, m->neff);
    for (uint32_t i = 0; i < m->neff; i++) {
        uint32_t nl = (uint32_t)strlen(m->eff[i]);
        wb_u32(w, nl); wb_raw(w, m->eff[i], nl);
    }
    /* M3: declared builtins live in the header, right after authority. */
    wb_u32(w, m->nbuiltin);
    for (uint32_t i = 0; i < m->nbuiltin; i++) {
        uint32_t nl = (uint32_t)strlen(m->builtin[i]);
        wb_u32(w, nl); wb_raw(w, m->builtin[i], nl);
    }
    wb_u32(w, m->n);
}

static void mod_emit(const axb_mod *m, wbuf *w) {
    mod_head_emit(m, AXB_EXEC_BODY_VERSION, w);
    for (uint32_t i = 0; i < m->n; i++) cell_emit(&m->cells[i], w);
}

/* ---- reader --------------------------------------------------------- */
typedef struct { const uint8_t *p; size_t len, off; int err; } rbuf;

static int rb_need(rbuf *r, size_t n) {
    if (r->off > r->len || n > r->len - r->off) {
        r->err = 1; return 0;
    }
    return 1;
}
static uint8_t rb_u8(rbuf *r) {
    if (!rb_need(r, 1)) return 0;
    return r->p[r->off++];
}
static uint32_t rb_u32(rbuf *r) {
    if (!rb_need(r, 4)) return 0;
    const uint8_t *b = r->p + r->off; r->off += 4;
    return (uint32_t)b[0] | (uint32_t)b[1]<<8 | (uint32_t)b[2]<<16 | (uint32_t)b[3]<<24;
}
static uint64_t rb_u64(rbuf *r) {
    uint64_t lo = rb_u32(r); return lo | (uint64_t)rb_u32(r) << 32;
}

static int mod_refuse(axi_diags *diags, const char *path, const char *code,
                      const char *msg, const char *fix)
{
    if (diags)
        axi_diag_add(diags, code, 0, 0, 0, msg, fix);
    else
        fprintf(AXI_ERR, "%s %s: %s | fix: %s\n", code, path, msg, fix);
    return 1;
}

static int mod_name_ok(axi_diags *diags, const char *path,
                       const uint8_t *name, uint32_t len)
{
    if (memchr(name, '\0', len)) {
        mod_refuse(diags, path, "AXI-B023", "module name contains NUL",
                   "reassemble from canonical .axs; names are text, not byte prefixes");
        return 0;
    }
    return 1;
}

int axb_mod_read_diag(axb_mod *m, const uint8_t *p, size_t len,
                      const char *path, struct axi_arena *ar,
                      axi_diags *diags) {
    rbuf r = { p, len, 0, 0 };
    char msg[AXI_DIAG_MSG];
    if (!rb_need(&r, 8) || memcmp(p, AXB_MAGIC, 4) != 0) {
        return mod_refuse(diags, path, "AXI-B010",
                          "not an AXB module (bad magic)",
                          "assemble with `axi asm`");
    }
    r.off = 4;
    uint32_t ver = rb_u32(&r);
    if (ver != AXB_EXEC_BODY_VERSION) {
        snprintf(msg, sizeof msg, "AXB version %u, tool speaks %u",
                 ver, AXB_EXEC_BODY_VERSION);
        return mod_refuse(diags, path, "AXI-B011", msg,
                          "reassemble from .axs");
    }
    if (!rb_need(&r, 32)) {
        return mod_refuse(diags, path, "AXI-B012", "truncated module",
                          "reassemble from .axs; do not edit binaries");
    }
    memcpy(m->src_hash, p + r.off, 32); r.off += 32;      /* W14 binding */
    m->neff = rb_u32(&r);                                 /* W19 authority */
    if (m->neff > AXB_MAX_EFF) {
        snprintf(msg, sizeof msg, "module declares %u effects, ceiling is %u",
                 m->neff, AXB_MAX_EFF);
        return mod_refuse(diags, path, "AXI-B020", msg,
                          "authority a reviewer cannot read is not authority");
    }
    for (uint32_t i = 0; i < m->neff && !r.err; i++) {
        uint32_t nl = rb_u32(&r);
        if (!rb_need(&r, nl)) break;
        if (!mod_name_ok(diags, path, p + r.off, nl)) return 1;
        m->eff[i] = axi_arena_alloc(ar, (size_t)nl + 1);
        if (!m->eff[i]) goto mem;
        memcpy(m->eff[i], p + r.off, nl); m->eff[i][nl] = 0; r.off += nl;
    }
    if (r.err) {
        return mod_refuse(diags, path, "AXI-B012", "truncated module",
                          "reassemble from .axs; do not edit binaries");
    }
    m->nbuiltin = rb_u32(&r);                             /* M3 builtins */
    if (m->nbuiltin > AXB_MAX_BUILTIN) {
        snprintf(msg, sizeof msg, "module declares %u builtins, ceiling is %u",
                 m->nbuiltin, AXB_MAX_BUILTIN);
        return mod_refuse(diags, path, "AXI-B020", msg,
                          "split the module; every builtin must fit the review ceiling");
    }
    for (uint32_t i = 0; i < m->nbuiltin && !r.err; i++) {
        uint32_t nl = rb_u32(&r);
        if (!rb_need(&r, nl)) break;
        if (!mod_name_ok(diags, path, p + r.off, nl)) return 1;
        m->builtin[i] = axi_arena_alloc(ar, (size_t)nl + 1);
        if (!m->builtin[i]) goto mem;
        memcpy(m->builtin[i], p + r.off, nl); m->builtin[i][nl] = 0; r.off += nl;
    }
    if (r.err) {
        return mod_refuse(diags, path, "AXI-B012", "truncated module",
                          "reassemble from .axs; do not edit binaries");
    }
    m->n = rb_u32(&r);
    if (m->n > 256 || m->n > (uint32_t)(len / 8)) {      /* allocation bomb */
        return mod_refuse(diags, path, "AXI-B012", "truncated module",
                          "reassemble from .axs; do not edit binaries");
    }
    m->cells = axi_arena_alloc(ar, (m->n ? m->n : 1) * sizeof(axb_cell));
    if (!m->cells) goto mem;
    for (uint32_t i = 0; i < m->n && !r.err; i++) {
        axb_cell *c = &m->cells[i];
        uint32_t nl = rb_u32(&r);
        if (!rb_need(&r, nl)) break;
        if (!mod_name_ok(diags, path, p + r.off, nl)) return 1;
        c->name = axi_arena_alloc(ar, (size_t)nl + 1);
        if (!c->name) goto mem;
        memcpy(c->name, p + r.off, nl); c->name[nl] = 0; r.off += nl;
        c->nregs = rb_u32(&r);
        c->nk    = rb_u32(&r);
        if (c->nk > 65536 || c->nk > (uint32_t)(len / 4)) {
            r.err = 1; break;
        }
        c->k = axi_arena_alloc(ar, (c->nk ? c->nk : 1) * sizeof(axb_konst));
        if (!c->k) goto mem;
        for (uint32_t j = 0; j < c->nk && !r.err; j++) {
            axb_konst *k = &c->k[j];
            k->tag = rb_u8(&r);
            if (k->tag < AXB_KU64 || k->tag > AXB_KERR)
                return mod_refuse(diags, path, "AXI-B024",
                                  "unknown constant tag",
                                  "reassemble from canonical .axs");
            if (k->tag == AXB_KSTR || k->tag == AXB_KERR) {
                k->slen = rb_u32(&r);
                if (!rb_need(&r, k->slen)) break;
                k->s = axi_arena_alloc(ar, (size_t)k->slen + 1);
                if (!k->s) goto mem;
                memcpy(k->s, p + r.off, k->slen); k->s[k->slen] = 0;
                r.off += k->slen;
            } else k->u = rb_u64(&r);
        }
        c->nc = rb_u32(&r);
        if (c->nc > (uint32_t)(len / 4)) { r.err = 1; break; }
        c->code = axi_arena_alloc(ar, (c->nc ? c->nc : 1) * sizeof(uint32_t));
        if (!c->code) goto mem;
        for (uint32_t j = 0; j < c->nc; j++) c->code[j] = rb_u32(&r);
    }
    if (r.err) {
        return mod_refuse(diags, path, "AXI-B012", "truncated module",
                          "reassemble from .axs; do not edit binaries");
    }

    /* W21 — the container ends where the module ends. The format doc has said
     * since W08 that "a byte that is not described here does not exist", and
     * until now the loader did not enforce it: everything past the last cell
     * was read by nobody and refused by nobody. That is a smuggling channel —
     * a payload `axi dis` never prints, riding inside a module that runs
     * perfectly. Worse, it makes two different files behave identically, and
     * this whole language is built on the opposite promise.
     *
     * So: after the body there is nothing, or there is exactly one signature.
     * The boundary is decided by the body's own parse, never by scanning
     * backwards for a magic — a module whose last bytes happen to spell
     * "AXBS" is not thereby signed. */
    {
        size_t consumed = r.off;
        if (len == consumed) {
            m->has_sig = 0;                       /* anonymous, and honest */
            m->body_len = consumed;
        } else if (len == consumed + AXBS_TRAILER) {
            axi_sig s;
            if (axi_sig_read(p + consumed, &s) != 0) {
                snprintf(msg, sizeof msg,
                         "%u trailing bytes are the size of a signature but are not one",
                         (unsigned)AXBS_TRAILER);
                return mod_refuse(diags, path, "AXI-B022", msg,
                                  "re-sign with `axi sign`; never hand-edit a trailer");
            }
            m->has_sig = 1;
            m->body_len = consumed;
            memcpy(m->sig_pk,  s.pk,  32);
            memcpy(m->sig_sig, s.sig, 64);
        } else {
            snprintf(msg, sizeof msg, "%llu bytes past the end of the module",
                     (unsigned long long)(len - consumed));
            return mod_refuse(diags, path, "AXI-B021", msg,
                              "a byte outside the format does not exist; strip it or sign it");
        }
    }

    if (axb_mod_verify(m, path, diags) != 0) return 1;

    /* W22: the root is taken here and nowhere else. A witness rooted in a
     * field of the file is rooted in a rumour: at run time there is no source
     * to check `src_hash` against, so two different programs that declare the
     * same source produced the same ledger tip. The loader hashes the bytes it
     * actually parsed instead — body only, signature excluded. Any change to
     * code, constants, declared effects or declared provenance moves the root;
     * signing the same program does not. /AXI-INV-062/ */
    axi_sha256(p, m->body_len, m->root);
    return 0;
mem:
    return mod_refuse(diags, path, "AXI-R009",
                      "arena exhausted while loading",
                      "memory is budgeted like fuel; raise --mem or shrink the module");
}

int axb_mod_read(axb_mod *m, const uint8_t *p, size_t len, const char *path,
                 struct axi_arena *ar)
{
    return axb_mod_read_diag(m, p, len, path, ar, NULL);
}

static int name_part(unsigned char c, int first)
{
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_')
        return 1;
    return !first && c >= '0' && c <= '9';
}

static int canonical_name(const char *s, int dotted)
{
    size_t i, n;
    int first = 1;
    if (!s) return 0;
    n = strlen(s);
    if (n == 0 || n > 63) return 0;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (dotted && c == '.') {
            if (first || i + 1 == n) return 0;
            first = 1;
        } else {
            if (!name_part(c, first)) return 0;
            first = 0;
        }
    }
    return !first;
}

/* ---- CA16 phase 1: standalone contract manifest v1 codec -----------------
 * INV-380 / AXI-INV-121. This freezes the bounded value encoding while the
 * production container remains AXB v5. No loader path consumes these bytes yet. */

typedef struct {
    uint8_t *p;
    size_t off;
} mbuf;

static int mname_ok(axb_mstr s, int dotted)
{
    uint32_t i;
    uint32_t dots = 0;
    int first = 1;
    if (!s.p || s.len == 0 || s.len > AXB_MANIFEST_MAX_NAME) return 0;
    for (i = 0; i < s.len; i++) {
        unsigned char c = (unsigned char)s.p[i];
        if (dotted && c == '.') {
            if (first || i + 1 == s.len || ++dots > 1) return 0;
            first = 1;
        } else {
            if (!name_part(c, first)) return 0;
            first = 0;
        }
    }
    return !first;
}

static int mlaw_ok(axb_mstr s)
{
    uint32_t i;
    if (!s.p || s.len == 0 || s.len > AXB_MANIFEST_MAX_LAW) return 0;
    for (i = 0; i < s.len; i++) {
        unsigned char c = (unsigned char)s.p[i];
        if (c == 0 || c == 0x7f || c == '\n' || c == '\r' || c < 0x20)
            return 0;
    }
    return 1;
}

static int mstr_cmp(axb_mstr a, axb_mstr b)
{
    size_t n = a.len < b.len ? a.len : b.len;
    int c = memcmp(a.p, b.p, n);
    if (c) return c;
    return a.len < b.len ? -1 : a.len > b.len;
}

static int mtype_ok(const axb_mtype *t, int parameter)
{
    if (!t) return 0;
    if (t->tag >= AXB_MT_U64 && t->tag <= AXB_MT_DECISION)
        return t->name.len == 0;
    if (!parameter && t->tag == AXB_MT_OK) return t->name.len == 0;
    if (parameter && t->tag == AXB_MT_CAP) return mname_ok(t->name, 1);
    return 0;
}

static int manifest_size(const axb_manifest *m, size_t *out);

int axb_manifest_v1_verify(const axb_manifest *m)
{
    uint32_t i, j;
    size_t wire_size;
    if (!m || m->version != AXB_MANIFEST_VERSION || m->fuel_max == 0
            || (m->flags & ~AXB_MANIFEST_FLAG_MASK)
            || m->flags == AXB_MANIFEST_FLAG_MASK
            || m->nparams > AXB_MANIFEST_MAX_PARAMS
            || m->nreturns > AXB_MANIFEST_MAX_RETURNS
            || m->nerrors > AXB_MANIFEST_MAX_ERRORS
            || m->ncaps > AXB_MANIFEST_MAX_CAPS
            || m->nlaws > AXB_MANIFEST_MAX_LAWS
            || m->nreturns + m->nerrors == 0)
        return 1;
    for (i = 0; i < m->nparams; i++) {
        if (!mname_ok(m->params[i].name, 0)
                || !mtype_ok(&m->params[i].type, 1)) return 1;
        for (j = 0; j < i; j++)
            if (mstr_cmp(m->params[j].name, m->params[i].name) == 0) return 1;
    }
    for (i = 0; i < m->nreturns; i++) {
        if (!mtype_ok(&m->returns[i], 0)) return 1;
        /* Wire canonicalization is numeric by frozen type tag, not spelling. */
        if (i && m->returns[i - 1].tag >= m->returns[i].tag) return 1;
    }
    for (i = 0; i < m->nerrors; i++) {
        if (!mname_ok(m->errors[i], 1)
                || (i && mstr_cmp(m->errors[i - 1], m->errors[i]) >= 0)) return 1;
    }
    for (i = 0; i < m->ncaps; i++) {
        if (!mname_ok(m->caps[i], 1)
                || (i && mstr_cmp(m->caps[i - 1], m->caps[i]) >= 0)) return 1;
    }
    for (i = 0; i < m->nlaws; i++) {
        if (!mlaw_ok(m->laws[i])
                || (i && mstr_cmp(m->laws[i - 1], m->laws[i]) >= 0)) return 1;
    }
    return manifest_size(m, &wire_size) ? 0 : 1;
}

static int msize_add(size_t *n, size_t add)
{
    if (add > AXB_MANIFEST_MAX_BYTES - *n) return 0;
    *n += add;
    return 1;
}

static int msize_str(size_t *n, axb_mstr s)
{
    return msize_add(n, 4) && msize_add(n, s.len);
}

static int manifest_size(const axb_manifest *m, size_t *out)
{
    uint32_t i;
    size_t n = 4 + 4 + 8 + 4;
    for (i = 0; i < m->nparams; i++) {
        if (!msize_str(&n, m->params[i].name) || !msize_add(&n, 1)) return 0;
        if (m->params[i].type.tag == AXB_MT_CAP
                && !msize_str(&n, m->params[i].type.name)) return 0;
    }
    if (!msize_add(&n, 4 + m->nreturns) || !msize_add(&n, 4)) return 0;
    for (i = 0; i < m->nerrors; i++) if (!msize_str(&n, m->errors[i])) return 0;
    if (!msize_add(&n, 4)) return 0;
    for (i = 0; i < m->ncaps; i++) if (!msize_str(&n, m->caps[i])) return 0;
    if (!msize_add(&n, 4)) return 0;
    for (i = 0; i < m->nlaws; i++) if (!msize_str(&n, m->laws[i])) return 0;
    if (!msize_add(&n, 64)) return 0;
    *out = n;
    return 1;
}

static void mw_u8(mbuf *w, uint8_t v) { w->p[w->off++] = v; }
static void mw_u32(mbuf *w, uint32_t v)
{
    for (int i = 0; i < 4; i++) w->p[w->off++] = (uint8_t)(v >> (i * 8));
}
static void mw_u64(mbuf *w, uint64_t v)
{
    mw_u32(w, (uint32_t)v); mw_u32(w, (uint32_t)(v >> 32));
}
static void mw_raw(mbuf *w, const void *p, size_t n)
{
    memcpy(w->p + w->off, p, n); w->off += n;
}
static void mw_str(mbuf *w, axb_mstr s)
{
    mw_u32(w, s.len); mw_raw(w, s.p, s.len);
}
static void mw_type(mbuf *w, axb_mtype t)
{
    mw_u8(w, t.tag);
    if (t.tag == AXB_MT_CAP) mw_str(w, t.name);
}

int axb_manifest_v1_encode(const axb_manifest *m, uint8_t *out, size_t cap,
                           size_t *out_len)
{
    uint32_t i;
    size_t need = 0;
    mbuf w = {out, 0};
    if (out_len) *out_len = 0;
    if (!out_len || !out || axb_manifest_v1_verify(m) != 0
            || !manifest_size(m, &need) || need > cap) return 1;
    mw_u32(&w, m->version); mw_u32(&w, m->flags); mw_u64(&w, m->fuel_max);
    mw_u32(&w, m->nparams);
    for (i = 0; i < m->nparams; i++) {
        mw_str(&w, m->params[i].name); mw_type(&w, m->params[i].type);
    }
    mw_u32(&w, m->nreturns);
    for (i = 0; i < m->nreturns; i++) mw_type(&w, m->returns[i]);
    mw_u32(&w, m->nerrors);
    for (i = 0; i < m->nerrors; i++) mw_str(&w, m->errors[i]);
    mw_u32(&w, m->ncaps);
    for (i = 0; i < m->ncaps; i++) mw_str(&w, m->caps[i]);
    mw_u32(&w, m->nlaws);
    for (i = 0; i < m->nlaws; i++) mw_str(&w, m->laws[i]);
    mw_raw(&w, m->iface_hash, 32); mw_raw(&w, m->body_hash, 32);
    if (w.off != need) return 1;
    *out_len = w.off;
    return 0;
}

static int mr_str(rbuf *r, struct axi_arena *arena, axb_mstr *out,
                  uint32_t max)
{
    uint32_t n = rb_u32(r);
    char *p;
    if (r->err || n == 0 || n > max || !rb_need(r, n)) return 0;
    p = axi_arena_alloc(arena, (size_t)n + 1);
    if (!p) return 0;
    memcpy(p, r->p + r->off, n); p[n] = 0; r->off += n;
    out->p = p; out->len = n;
    return 1;
}

static int mr_type(rbuf *r, struct axi_arena *arena, axb_mtype *out,
                   int parameter)
{
    out->tag = rb_u8(r);
    if (r->err) return 0;
    if (out->tag == AXB_MT_CAP
            && !mr_str(r, arena, &out->name, AXB_MANIFEST_MAX_NAME)) return 0;
    return mtype_ok(out, parameter);
}

int axb_manifest_v1_decode(axb_manifest *out, const uint8_t *bytes, size_t len,
                           struct axi_arena *arena)
{
    axb_manifest m;
    rbuf r = {bytes, len, 0, 0};
    uint32_t i;
    int reserved = 0, rc = 1;
    if (!out) return 1;
    memset(out, 0, sizeof *out);
    memset(&m, 0, sizeof m);
    if (!bytes || !arena || len == 0 || len > AXB_MANIFEST_MAX_BYTES) return 1;
    if (arena->account) {
        if (!axi_mem_reserve(arena->account, sizeof m)) return 1;
        reserved = 1;
    }
    m.version = rb_u32(&r); m.flags = rb_u32(&r); m.fuel_max = rb_u64(&r);
    m.nparams = rb_u32(&r);
    if (r.err || m.nparams > AXB_MANIFEST_MAX_PARAMS) goto done;
    for (i = 0; i < m.nparams; i++)
        if (!mr_str(&r, arena, &m.params[i].name, AXB_MANIFEST_MAX_NAME)
                || !mr_type(&r, arena, &m.params[i].type, 1)) goto done;
    m.nreturns = rb_u32(&r);
    if (r.err || m.nreturns > AXB_MANIFEST_MAX_RETURNS) goto done;
    for (i = 0; i < m.nreturns; i++)
        if (!mr_type(&r, arena, &m.returns[i], 0)) goto done;
    m.nerrors = rb_u32(&r);
    if (r.err || m.nerrors > AXB_MANIFEST_MAX_ERRORS) goto done;
    for (i = 0; i < m.nerrors; i++)
        if (!mr_str(&r, arena, &m.errors[i], AXB_MANIFEST_MAX_NAME)) goto done;
    m.ncaps = rb_u32(&r);
    if (r.err || m.ncaps > AXB_MANIFEST_MAX_CAPS) goto done;
    for (i = 0; i < m.ncaps; i++)
        if (!mr_str(&r, arena, &m.caps[i], AXB_MANIFEST_MAX_NAME)) goto done;
    m.nlaws = rb_u32(&r);
    if (r.err || m.nlaws > AXB_MANIFEST_MAX_LAWS) goto done;
    for (i = 0; i < m.nlaws; i++)
        if (!mr_str(&r, arena, &m.laws[i], AXB_MANIFEST_MAX_LAW)) goto done;
    if (!rb_need(&r, 64)) goto done;
    memcpy(m.iface_hash, r.p + r.off, 32); r.off += 32;
    memcpy(m.body_hash, r.p + r.off, 32); r.off += 32;
    if (r.err || r.off != r.len || axb_manifest_v1_verify(&m) != 0) goto done;
    *out = m;
    rc = 0;
done:
    if (reserved
            && !account_release_preserve_failure(arena->account, sizeof m))
        return 1;
    return rc;
}

static void axpc_emit(const axb_seal_certificate *cert, wbuf *w)
{
    uint32_t i;
    wb_raw(w, AXPC_MAGIC, 4);
    wb_u32(w, cert->version);
    wb_u32(w, cert->maturity);
    wb_raw(w, cert->subject_root, 32);
    wb_raw(w, cert->checker_protocol_id, 32);
    wb_raw(w, cert->checker_semantics_root, 32);
    wb_u64(w, cert->aggregate_budget);
    wb_u64(w, cert->aggregate_fuel_used);
    wb_u32(w, cert->law_count);
    for (i = 0; i < cert->law_count && !w->oom; i++) {
        const axb_seal_law *law = &cert->laws[i];
        wb_u32(w, law->cell_index);
        wb_u32(w, law->name.len);
        wb_raw(w, law->name.p, law->name.len);
        wb_raw(w, law->iface_hash, 32);
        wb_raw(w, law->body_hash, 32);
        wb_u64(w, law->budget);
        wb_u64(w, law->fuel_used);
        wb_u32(w, law->result_kind);
        wb_u32(w, law->verdict);
    }
}

/* INV-387 / AXI-INV-126: the production codec admits one exact version. */
static int axb_contract_v7_encode_profile_with_manifest(
    const axb_contract_mod *m, int include_certificate, int fill_derivation,
    uint8_t **out, size_t *out_len, axi_mem_account *account,
    uint8_t manifest[AXB_MANIFEST_MAX_BYTES])
{
    uint8_t want[32];
    wbuf w = {0};
    size_t ir_len = 0;
    uint32_t i;
    axb_derivation d;
    char *ir = NULL;
    if (!out || !out_len || axb_contract_v1_verify_accounted(m, account) != 0)
        return 1;
    if (include_certificate && m->seal.present
            && axb_contract_seal_verify_accounted(m, 0, account) != 0)
        return 1;
    memset(&d, 0, sizeof d);
    memcpy(&d, &m->derivation, sizeof d);
    /* AXI-CA17 / AXI-INV-139: normal emission fills missing derivation hashes;
     * subject hashing preserves the admitted fields byte-for-byte. */
    if (axb_mod_body_hash_accounted(&m->body, want, account) != 0) return 1;
    if (fill_derivation && derivation_all_zero(d.body_hash))
        memcpy(d.body_hash, want, 32);
    else if (!derivation_all_zero(d.body_hash)
            && memcmp(d.body_hash, want, 32) != 0)
        return 1;
    axb_compiler_hash(want);
    if (fill_derivation && derivation_all_zero(d.compiler_hash))
        memcpy(d.compiler_hash, want, 32);
    else if (!derivation_all_zero(d.compiler_hash)
            && memcmp(d.compiler_hash, want, 32) != 0)
        return 1;
    ir = axb_mod_dis_text_bounded_accounted(
        &m->body, AXB_CONTRACT_MAX_BYTES, &ir_len, account);
    if (!ir) return 1;
    axi_sha256(ir, ir_len, want);
    if (fill_derivation && derivation_all_zero(d.ir_hash))
        memcpy(d.ir_hash, want, 32);
    else if (!derivation_all_zero(d.ir_hash)
            && memcmp(d.ir_hash, want, 32) != 0) {
        (void)account_free_preserve_failure(account, ir);
        return 1;
    }
    if (!account_free_preserve_failure(account, ir)) return 1;
    w.account = account;
    w.max = AXB_CONTRACT_MAX_BYTES;
    wb_raw(&w, AXB_MAGIC, 4);
    wb_u32(&w, AXB_CONTRACT_VERSION);
    wb_raw(&w, m->body.src_hash, 32);
    wb_raw(&w, d.ir_hash, 32);
    wb_raw(&w, d.compiler_hash, 32);
    wb_raw(&w, d.body_hash, 32);
    /* effect table */
    wb_u32(&w, m->body.neff);
    for (i = 0; i < m->body.neff && !w.oom; i++) {
        uint32_t nl = (uint32_t)strlen(m->body.eff[i]);
        wb_u32(&w, nl); wb_raw(&w, m->body.eff[i], nl);
    }
    /* builtin table */
    wb_u32(&w, m->body.nbuiltin);
    for (i = 0; i < m->body.nbuiltin && !w.oom; i++) {
        uint32_t nl = (uint32_t)strlen(m->body.builtin[i]);
        wb_u32(&w, nl); wb_raw(&w, m->body.builtin[i], nl);
    }
    /* cells with their contract manifests */
    wb_u32(&w, m->body.n);
    for (i = 0; i < m->body.n && !w.oom; i++) {
        size_t manifest_len = 0;
        cell_name_emit(&m->body.cells[i], &w);
        if (axb_manifest_v1_encode(&m->manifest[i], manifest,
                                     AXB_MANIFEST_MAX_BYTES,
                                     &manifest_len) != 0) {
            w.oom = 1;
            break;
        }
        wb_u32(&w, (uint32_t)manifest_len);
        wb_raw(&w, manifest, manifest_len);
        cell_tail_emit(&m->body.cells[i], &w);
    }
    if (include_certificate && m->seal.present) {
        wbuf cert = {0};
        cert.account = account;
        cert.max = AXPC_MAX_BYTES;
        axpc_emit(&m->seal, &cert);
        if (cert.oom || cert.len == 0 || cert.len > AXPC_MAX_BYTES) {
            wb_free(&cert);
            wb_free(&w);
            return 1;
        }
        wb_u32(&w, (uint32_t)cert.len);
        wb_raw(&w, cert.p, cert.len);
        wb_free(&cert);
    } else {
        wb_u32(&w, 0);
    }
    if (w.oom || w.len == 0 || w.len > AXB_CONTRACT_MAX_BYTES) {
        wb_free(&w);
        return 1;
    }
    *out = w.p;
    *out_len = w.len;
    return 0;
}

static int axb_contract_v7_encode_profile_legacy(
    const axb_contract_mod *m, int include_certificate, int fill_derivation,
    uint8_t **out, size_t *out_len)
{
    uint8_t manifest[AXB_MANIFEST_MAX_BYTES];
    return axb_contract_v7_encode_profile_with_manifest(
        m, include_certificate, fill_derivation, out, out_len, NULL, manifest);
}

static int axb_contract_v7_encode_profile_accounted(
    const axb_contract_mod *m, int include_certificate, int fill_derivation,
    uint8_t **out, size_t *out_len, axi_mem_account *account)
{
    uint8_t *manifest;
    int rc;
    if (!account)
        return axb_contract_v7_encode_profile_legacy(
            m, include_certificate, fill_derivation, out, out_len);
    manifest = axi_mem_alloc(account, AXB_MANIFEST_MAX_BYTES);
    if (!manifest) return 1;
    rc = axb_contract_v7_encode_profile_with_manifest(
        m, include_certificate, fill_derivation, out, out_len, account,
        manifest);
    if (!account_free_preserve_failure(account, manifest)) return 1;
    return rc;
}

int axb_contract_v7_encode(const axb_contract_mod *m,
                            uint8_t **out, size_t *out_len)
{
    /* INV-480 / AXI-INV-148: once AXPC binds caller-supplied derivation bytes,
     * emission must preserve them instead of normalizing after verification. */
    return axb_contract_v7_encode_profile_accounted(
        m, 1, !m || !m->seal.present, out, out_len, NULL);
}

int axb_contract_seal_subject_root_accounted(const axb_contract_mod *m,
                                              uint8_t out[32],
                                              axi_mem_account *account)
{
    static const char domain[] = "AXI-SEAL-SUBJECT-v1";
    uint8_t *body = NULL, *preimage = NULL;
    uint8_t hash[32];
    size_t body_len = 0, preimage_len;
    if (!m || !out
            || axb_contract_v7_encode_profile_accounted(
                   m, 0, 0, &body, &body_len, account) != 0) goto bad;
    if (body_len > (size_t)-1 - (sizeof domain - 1)) {
        if (account) (void)axi_mem_alloc(account, (size_t)-1);
        goto bad;
    }
    preimage_len = sizeof domain - 1 + body_len;
    preimage = account ? axi_mem_alloc(account, preimage_len)
                       : axi_malloc(preimage_len);
    if (!preimage) goto bad;
    memcpy(preimage, domain, sizeof domain - 1);
    memcpy(preimage + sizeof domain - 1, body, body_len);
    axi_sha256(preimage, preimage_len, hash);
    if (!account_free_preserve_failure(account, preimage)) goto bad_body;
    preimage = NULL;
    if (!account_free_preserve_failure(account, body)) return 1;
    memcpy(out, hash, sizeof hash);
    return 0;
bad_body:
    preimage = NULL;
bad:
    (void)account_free_preserve_failure(account, preimage);
    (void)account_free_preserve_failure(account, body);
    return 1;
}

int axb_contract_seal_subject_root(const axb_contract_mod *m, uint8_t out[32])
{
    return axb_contract_seal_subject_root_accounted(m, out, NULL);
}

static int contract_size_add(size_t left, size_t right, size_t *out)
{
    if (!out || right > (size_t)-1 - left) return 0;
    *out = left + right;
    return 1;
}

static char *contract_read_string(rbuf *r, uint32_t max, axi_arena *arena)
{
    uint32_t len = rb_u32(r);
    size_t alloc_len;
    char *s;
    /* INV-387: wire names are text, never NUL-terminated byte prefixes. */
    if (r->err || len == 0 || len > max || !rb_need(r, len)
            || memchr(r->p + r->off, '\0', len)) return NULL;
    if (!contract_size_add((size_t)len, 1, &alloc_len)) {
        if (arena->account) (void)axi_mem_alloc(arena->account, (size_t)-1);
        r->err = 1;
        return NULL;
    }
    s = axi_arena_alloc(arena, alloc_len);
    if (!s) { r->err = 1; return NULL; }
    memcpy(s, r->p + r->off, len);
    s[len] = '\0';
    r->off += len;
    return s;
}

static int axpc_decode(axb_seal_certificate *out, const uint8_t *bytes,
                       size_t len, axi_arena *arena)
{
    axb_seal_certificate cert;
    rbuf r = {bytes, len, 0, 0};
    uint32_t i;
    int cert_reserved = 0, rc = 1;
    memset(&cert, 0, sizeof cert);
    if (!out || !bytes || !arena || len > AXPC_MAX_BYTES
            || len < AXPC_FIXED_BYTES
            || memcmp(bytes, AXPC_MAGIC, 4) != 0) return 1;
    if (arena->account) {
        if (!axi_mem_reserve(arena->account, sizeof cert)) return 1;
        cert_reserved = 1;
    }
    r.off = 4;
    cert.present = 1;
    cert.version = rb_u32(&r);
    cert.maturity = rb_u32(&r);
    if (!rb_need(&r, 96)) goto done;
    memcpy(cert.subject_root, bytes + r.off, 32); r.off += 32;
    memcpy(cert.checker_protocol_id, bytes + r.off, 32); r.off += 32;
    memcpy(cert.checker_semantics_root, bytes + r.off, 32); r.off += 32;
    cert.aggregate_budget = rb_u64(&r);
    cert.aggregate_fuel_used = rb_u64(&r);
    cert.law_count = rb_u32(&r);
    if (r.err || cert.law_count == 0 || cert.law_count > AXPC_MAX_LAWS)
        goto done;
    for (i = 0; i < cert.law_count; i++) {
        axb_seal_law *law = &cert.laws[i];
        char *name;
        law->cell_index = rb_u32(&r);
        name = contract_read_string(&r, AXB_MANIFEST_MAX_NAME, arena);
        if (!name || !rb_need(&r, 64)) goto done;
        law->name.p = name;
        law->name.len = (uint32_t)strlen(name);
        memcpy(law->iface_hash, bytes + r.off, 32); r.off += 32;
        memcpy(law->body_hash, bytes + r.off, 32); r.off += 32;
        law->budget = rb_u64(&r);
        law->fuel_used = rb_u64(&r);
        law->result_kind = rb_u32(&r);
        law->verdict = rb_u32(&r);
        if (r.err) goto done;
    }
    if (r.off != r.len) goto done;
    *out = cert;
    rc = 0;
done:
    if (cert_reserved
            && !account_release_preserve_failure(arena->account, sizeof cert))
        return 1;
    return rc;
}

static void *contract_arena_array(axi_arena *arena, size_t count,
                                  size_t element)
{
    if (count != 0 && element > (size_t)-1 / count) {
        if (arena->account) (void)axi_mem_alloc(arena->account, (size_t)-1);
        return NULL;
    }
    return axi_arena_alloc(arena, count * element);
}

static void contract_restore_account_failure(
    axi_mem_account *account, axi_mem_failure_cause failure,
    size_t failed_request)
{
    if (account && failure != AXI_MEM_FAILURE_NONE
            && account->failure == AXI_MEM_FAILURE_NONE) {
        account->failure = failure;
        account->failed_request = failed_request;
    }
}

int axb_contract_v7_decode_accounted(axb_contract_mod *out,
                                     const uint8_t *bytes, size_t len,
                                     axi_mem_account *account)
{
    axb_contract_mod model;
    rbuf r = {bytes, len, 0, 0};
    uint32_t i, j, count, cert_len;
    axi_mem_failure_cause failure;
    size_t failed_request;
    int model_reserved = 0;
    if (!out) return 1;
    memset(&model, 0, sizeof model);
    if (account) {
        if (!axi_mem_reserve(account, sizeof model)) return 1;
        model_reserved = 1;
    }
    if (!bytes || len < 8 || len > AXB_CONTRACT_MAX_BYTES
            || memcmp(bytes, AXB_MAGIC, 4) != 0) goto bad;
    r.off = 4;
    if (rb_u32(&r) != AXB_CONTRACT_VERSION) goto bad;
    if (!rb_need(&r, 32 + 96)) goto bad;
    memcpy(model.body.src_hash, bytes + r.off, 32);
    memcpy(model.derivation.src_hash, bytes + r.off, 32);
    r.off += 32;
    memcpy(model.derivation.ir_hash, bytes + r.off, 32);
    r.off += 32;
    memcpy(model.derivation.compiler_hash, bytes + r.off, 32);
    r.off += 32;
    memcpy(model.derivation.body_hash, bytes + r.off, 32);
    r.off += 32;
    axi_arena_init_accounted(&model.arena, AXB_CONTRACT_MAX_BYTES, account);
    /* INV-474 / AXI-INV-143: every decoded byte of the executable model is
     * owned and counted by the same bounded arena used by --mem. */
    model.body_arena_owned = 1;
    /* INV-426 / AXI-INV-136: hostile counts stay local until bounded. The
     * destructor may only observe counts that fit their fixed pointer tables. */
    count = rb_u32(&r);
    if (r.err || count > AXB_MAX_EFF) goto bad;
    model.body.neff = count;
    for (i = 0; i < model.body.neff; i++) {
        model.body.eff[i] = contract_read_string(&r, AXB_MANIFEST_MAX_NAME,
                                                 &model.arena);
        if (!model.body.eff[i]) goto bad;
    }
    count = rb_u32(&r);
    if (r.err || count > AXB_MAX_BUILTIN) goto bad;
    model.body.nbuiltin = count;
    for (i = 0; i < model.body.nbuiltin; i++) {
        model.body.builtin[i] = contract_read_string(&r,
                                                     AXB_MANIFEST_MAX_NAME,
                                                     &model.arena);
        if (!model.body.builtin[i]) goto bad;
    }
    count = rb_u32(&r);
    if (r.err || count == 0 || count > 256 || count > len / 8) goto bad;
    model.body.cells = contract_arena_array(&model.arena, count,
                                             sizeof *model.body.cells);
    if (!model.body.cells) goto bad;
    model.manifest = contract_arena_array(&model.arena, count,
                                           sizeof *model.manifest);
    if (!model.manifest) goto bad;
    model.body.n = model.nmanifest = count;
    for (i = 0; i < count; i++) {
        axb_cell *cell = &model.body.cells[i];
        uint32_t manifest_len, nk;
        cell->name = contract_read_string(&r, AXB_MANIFEST_MAX_NAME,
                                          &model.arena);
        if (!cell->name) goto bad;
        manifest_len = rb_u32(&r);
        if (r.err || manifest_len == 0
                || manifest_len > AXB_MANIFEST_MAX_BYTES
                || !rb_need(&r, manifest_len)
                || axb_manifest_v1_decode(&model.manifest[i], bytes + r.off,
                                          manifest_len, &model.arena) != 0)
            goto bad;
        r.off += manifest_len;
        cell->nregs = rb_u32(&r);
        nk = rb_u32(&r);
        if (r.err || nk > 65536 || nk > len / 5) goto bad;
        cell->k = contract_arena_array(&model.arena, nk ? nk : 1,
                                       sizeof *cell->k);
        if (!cell->k) goto bad;
        cell->nk = nk;
        for (j = 0; j < cell->nk; j++) {
            axb_konst *k = &cell->k[j];
            k->tag = rb_u8(&r);
            if (r.err || k->tag < AXB_KU64 || k->tag > AXB_KERR) goto bad;
            if (k->tag == AXB_KSTR || k->tag == AXB_KERR) {
                k->slen = rb_u32(&r);
                if (r.err || k->slen > AXB_CONTRACT_MAX_BYTES
                        || !rb_need(&r, k->slen)) goto bad;
                size_t string_len;
                if (!contract_size_add((size_t)k->slen, 1,
                                       &string_len)) {
                    if (account) (void)axi_mem_alloc(account, (size_t)-1);
                    goto bad;
                }
                k->s = axi_arena_alloc(&model.arena, string_len);
                if (!k->s) goto bad;
                memcpy(k->s, bytes + r.off, k->slen);
                k->s[k->slen] = '\0';
                r.off += k->slen;
            } else {
                k->u = rb_u64(&r);
                if (r.err) goto bad;
            }
        }
        cell->nc = rb_u32(&r);
        if (r.err || cell->nc > len / 4) goto bad;
        cell->code = contract_arena_array(&model.arena,
                                           cell->nc ? cell->nc : 1,
                                           sizeof *cell->code);
        if (!cell->code) goto bad;
        for (j = 0; j < cell->nc; j++) cell->code[j] = rb_u32(&r);
        if (r.err) goto bad;
    }
    cert_len = rb_u32(&r);
    if (r.err || cert_len > AXPC_MAX_BYTES || !rb_need(&r, cert_len)) goto bad;
    if (cert_len && axpc_decode(&model.seal, bytes + r.off, cert_len,
                                &model.arena) != 0) goto bad;
    r.off += cert_len;
    if (r.off != len
            || axb_contract_v1_verify_accounted(&model, account) != 0) goto bad;
    model.body.body_len = len;
    model.body.has_sig = 0;
    /* AXI-CA17 / AXI-INV-139: provenance is verified when claimed. An all-zero
     * field carries no derivation claim and cannot override the runtime root,
     * which stays the exact unsigned v7 container identity below. */
    {
        uint8_t want[32];
        int claimed = !derivation_all_zero(model.derivation.ir_hash)
            || !derivation_all_zero(model.derivation.compiler_hash)
            || !derivation_all_zero(model.derivation.body_hash);
        if (claimed) {
            size_t ir_len = 0;
            char *ir = axb_mod_dis_text_bounded_accounted(
                &model.body, AXB_CONTRACT_MAX_BYTES, &ir_len, account);
            if (!ir) goto bad;
            axi_sha256(ir, ir_len, want);
            if (!derivation_all_zero(model.derivation.ir_hash)
                    && memcmp(want, model.derivation.ir_hash, 32) != 0)
                { (void)account_free_preserve_failure(account, ir); goto bad; }
            if (!account_free_preserve_failure(account, ir)) goto bad;
            axb_compiler_hash(want);
            if (!derivation_all_zero(model.derivation.compiler_hash)
                    && memcmp(want, model.derivation.compiler_hash, 32) != 0)
                goto bad;
            if (axb_mod_body_hash_accounted(&model.body, want, account) != 0)
                goto bad;
            if (!derivation_all_zero(model.derivation.body_hash)
                    && memcmp(want, model.derivation.body_hash, 32) != 0)
                goto bad;
        }
        if (!derivation_all_zero(model.derivation.src_hash)
                && memcmp(model.derivation.src_hash, model.body.src_hash, 32) != 0)
            goto bad;
    }
    axi_sha256(bytes, len, model.body.root);
    if (model.seal.present
            && axb_contract_seal_verify_accounted(&model, 0, account) != 0)
        goto bad;
    *out = model;
    if (model_reserved
            && !account_release_preserve_failure(account, sizeof model))
        return 1;
    return 0;
bad:
    failure = account ? account->failure : AXI_MEM_FAILURE_NONE;
    failed_request = account ? account->failed_request : 0;
    axb_contract_mod_free(&model);
    contract_restore_account_failure(account, failure, failed_request);
    if (model_reserved)
        (void)account_release_preserve_failure(account, sizeof model);
    return 1;
}

int axb_contract_v7_decode(axb_contract_mod *out,
                           const uint8_t *bytes, size_t len)
{
    return axb_contract_v7_decode_accounted(out, bytes, len, NULL);
}

/* INV-420 / AXI-INV-130: signed v7 is exactly one verified AXBS trailer over
 * the body bytes. Trust is explicit and no partial model escapes refusal. */
int axb_contract_v7_encode_signed(const axb_contract_mod *m,
                                  const uint8_t seed[32],
                                  uint8_t **out, size_t *out_len)
{
    return axb_contract_v7_encode_signed_accounted(m, seed, out, out_len, NULL);
}

int axb_contract_v7_encode_signed_accounted(const axb_contract_mod *m,
    const uint8_t seed[32], uint8_t **out, size_t *out_len, axi_mem_account *account)
{
    uint8_t *body = NULL, *framed = NULL;
    size_t body_len = 0, framed_len;
    axi_sig sig;
    if (!m || !seed || !out || !out_len) return 1;
    if (axb_contract_v7_encode_profile_accounted(m, 1, !m->seal.present, &body, &body_len, account) != 0) return 1;
    if (body_len > AXB_CONTRACT_MAX_BYTES
            || body_len > (size_t)-1 - AXBS_TRAILER) goto bad;
    framed_len = body_len + AXBS_TRAILER;
    if (account && !axi_mem_reserve(account, AXI_ED25519_MESSAGE_SCRATCH_BYTES)) goto bad;
    {
        int signed_rc = axi_sig_make(body, body_len, seed, &sig);
        if (!account_release_preserve_failure(account, AXI_ED25519_MESSAGE_SCRATCH_BYTES)
                || signed_rc != 0) goto bad;
    }
    framed = account ? axi_mem_alloc(account, framed_len) : axi_malloc(framed_len);
    if (!framed) goto bad;
    memcpy(framed, body, body_len);
    axi_sig_write(&sig, framed + body_len);
    (void)account_free_preserve_failure(account, body);
    *out = framed;
    *out_len = framed_len;
    return 0;
bad:
    (void)account_free_preserve_failure(account, framed);
    (void)account_free_preserve_failure(account, body);
    return 1;
}

int axb_contract_v7_decode_trusted_accounted(
    axb_contract_mod *out, const uint8_t *bytes, size_t len,
    const uint8_t trusted_pk[32], axi_mem_account *account)
{
    axb_contract_mod model;
    axi_sig sig;
    size_t body_len;
    int model_reserved = 0, signature_scratch_reserved = 0, rc = 1;
    if (!out || !bytes || !trusted_pk || len < AXBS_TRAILER + 8
            || len > AXB_CONTRACT_MAX_BYTES + AXBS_TRAILER) return 1;
    memset(&model, 0, sizeof model);
    if (account) {
        if (!axi_mem_reserve(account, sizeof model)) return 1;
        model_reserved = 1;
    }
    body_len = len - AXBS_TRAILER;
    if (body_len > AXB_CONTRACT_MAX_BYTES
            || axi_sig_read(bytes + body_len, &sig) != 0
            || memcmp(sig.pk, trusted_pk, sizeof sig.pk) != 0) goto done;
    if (account) {
        if (!axi_mem_reserve(account, AXI_ED25519_MESSAGE_SCRATCH_BYTES))
            goto done;
        signature_scratch_reserved = 1;
    }
    if (axi_sig_verify(bytes, body_len, &sig) != 0) goto done;
    if (signature_scratch_reserved) {
        if (!account_release_preserve_failure(
                account, AXI_ED25519_MESSAGE_SCRATCH_BYTES)) goto done;
        signature_scratch_reserved = 0;
    }
    if (axb_contract_v7_decode_accounted(&model, bytes, body_len,
                                         account) != 0) goto done;
    model.body.has_sig = 1;
    model.body.body_len = body_len;
    memcpy(model.body.sig_pk, sig.pk, sizeof model.body.sig_pk);
    memcpy(model.body.sig_sig, sig.sig, sizeof model.body.sig_sig);
    *out = model;
    memset(&model, 0, sizeof model);
    rc = 0;
done:
    axb_contract_mod_free(&model);
    if (signature_scratch_reserved
            && !account_release_preserve_failure(
                account, AXI_ED25519_MESSAGE_SCRATCH_BYTES))
        rc = 1;
    if (model_reserved
            && !account_release_preserve_failure(account, sizeof model))
        return 1;
    return rc;
}

int axb_contract_v7_decode_trusted(axb_contract_mod *out,
                                   const uint8_t *bytes, size_t len,
                                   const uint8_t trusted_pk[32])
{
    return axb_contract_v7_decode_trusted_accounted(
        out, bytes, len, trusted_pk, NULL);
}

/* INV-341 / AXI-INV-107: decoded does not mean admissible. Loader, writer and
 * direct VM entry all cross this same structural verifier. */
int axb_mod_verify(const axb_mod *m, const char *path, axi_diags *diags)
{
    uint32_t i, j, pc;
    const char *why = NULL;
    if (!m || (m->n && !m->cells) || m->n > 256 || m->neff > AXB_MAX_EFF
            || m->nbuiltin > AXB_MAX_BUILTIN) {
        why = "module table count exceeds the AXB encoding";
        goto bad;
    }
    for (i = 0; i < m->neff; i++) {
        if (!canonical_name(m->eff[i], 1)) {
            why = "effect name is not canonical"; goto bad;
        }
        for (j = 0; j < i; j++) if (!strcmp(m->eff[i], m->eff[j])) {
            why = "duplicate effect name"; goto bad;
        }
    }
    for (i = 0; i < m->nbuiltin; i++) {
        if (!canonical_name(m->builtin[i], 1)) {
            why = "builtin name is not canonical"; goto bad;
        }
        for (j = 0; j < i; j++) if (!strcmp(m->builtin[i], m->builtin[j])) {
            why = "duplicate builtin name"; goto bad;
        }
    }
    for (i = 0; i < m->n; i++) {
        const axb_cell *c = &m->cells[i];
        uint32_t nr = c->nregs ? c->nregs : 1;
        if (!canonical_name(c->name, 0)) {
            why = "cell name is not canonical"; goto bad;
        }
        for (j = 0; j < i; j++) if (!strcmp(c->name, m->cells[j].name)) {
            why = "duplicate cell name"; goto bad;
        }
        if (c->nregs > AXB_MAX_REGS || c->nk > 65536) {
            why = "cell count exceeds its encoded register or constant range";
            goto bad;
        }
        if ((c->nk && !c->k) || (c->nc && !c->code)) {
            why = "cell table pointer is absent"; goto bad;
        }
        for (j = 0; j < c->nk; j++)
            if (c->k[j].tag < AXB_KU64 || c->k[j].tag > AXB_KERR
                    || ((c->k[j].tag == AXB_KSTR || c->k[j].tag == AXB_KERR)
                        && !c->k[j].s)) {
                why = "unknown constant tag"; goto bad;
            }
        for (pc = 0; pc < c->nc; pc++) {
            uint32_t w = c->code[pc];
            uint8_t op = (uint8_t)w, a = (uint8_t)(w >> 8);
            uint8_t b = (uint8_t)(w >> 16), cc = (uint8_t)(w >> 24);
            uint16_t bc = (uint16_t)((uint16_t)b << 8 | cc);
            const axb_opinfo *oi = axb_op_info(op);
            int64_t target;
            if (!oi) { why = "unknown opcode"; goto bad; }
            switch (oi->ops) {
            case AXB_OPS_NONE:
                if (a || b || cc) why = "reserved operand byte is nonzero";
                break;
            case AXB_OPS_RA:
                if (a >= nr || b || cc) why = "invalid RA operand shape";
                break;
            case AXB_OPS_RA_RB:
                if (a >= nr || b >= nr || cc) why = "invalid RA_RB operand shape";
                break;
            case AXB_OPS_RA_RB_RC:
                if (a >= nr || b >= nr || cc >= nr) why = "register outside nregs";
                break;
            case AXB_OPS_RA_KBC:
                if (a >= nr || bc >= c->nk) why = "constant operand out of range";
                break;
            case AXB_OPS_RA_SBC:
                target = (int64_t)pc + (int16_t)bc;
                if (a >= nr || target < 0 || target >= c->nc)
                    why = "conditional jump target out of range";
                break;
            case AXB_OPS_SBC:
                target = (int64_t)pc + (int16_t)bc;
                if (a || target < 0 || target >= c->nc)
                    why = "jump target or reserved operand out of range";
                break;
            case AXB_OPS_RA_CB_IC:
                /* AXB v5 carries a caller window, not declared callee arity
                 * (CA16 owns exact arity). Preserve that compatibility here. */
                if (a >= nr || b >= m->n || cc > 16
                        || a + (uint32_t)cc > nr)
                    why = "call index or register window out of range";
                break;
            case AXB_OPS_RA_EB_RC:
                if (a >= nr || b >= m->neff || cc >= nr)
                    why = "effect index or register out of range";
                break;
            case AXB_OPS_RA_BB_RC: {
                const axi_builtin_info *bi = b < m->nbuiltin
                    ? axi_builtin_lookup(m->builtin[b], strlen(m->builtin[b])) : NULL;
                if (a >= nr || b >= m->nbuiltin || cc >= nr
                        || (bi && cc + (uint32_t)bi->arity > nr))
                    why = "builtin index or register window out of range";
                break;
            }
            }
            if (why) goto bad;
        }
    }
    return 0;
bad:
    return mod_refuse(diags, path ? path : "<module>", "AXI-B024", why,
                      "reassemble from canonical .axs; do not hand-edit AXB");
}

/* ---- assembler ------------------------------------------------------ */
typedef struct {
    const char *path;
    const char *src;
    size_t      len;
    size_t      off;
    uint32_t    line;
    int         errs;
    char      **cellnames;   /* prescan: forward refs in `call @name` */
    uint32_t    ncells;
    axi_mem_account *account;
} asm_st;

static void *asm_realloc(asm_st *a, void *p, size_t size)
{ return a->account ? axi_mem_realloc(a->account, p, size) : axi_realloc(p, size); }
static void *asm_malloc(asm_st *a, size_t size)
{ return a->account ? axi_mem_alloc(a->account, size) : axi_malloc(size); }
static char *asm_strdup(asm_st *a, const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = asm_malloc(a, n);
    if (p) memcpy(p, s, n);
    return p;
}
static char *asm_unescape(asm_st *a, const char *s, size_t len, uint32_t *outlen)
{
    char *p;
    uint32_t n;
    if (axi_str_decoded_length(s, len, &n) != 0) return NULL;
    p = asm_malloc(a, (size_t)n + 1);
    if (!p) return NULL;
    if (axi_str_decode_into(s, len, p, (size_t)n + 1, &n) != 0) {
        (void)account_free_preserve_failure(a->account, p); return NULL;
    }
    *outlen = n;
    return p;
}

static void aerr(asm_st *a, const char *code, const char *msg, const char *fix);

/* prescan cell names so `call @name` may point forward */
static void prescan_cells(asm_st *a) {
    size_t off = 0;
    uint32_t line = 1;
    while (off < a->len) {
        while (off < a->len && (a->src[off] == ' ' || a->src[off] == '\t')) off++;
        if (a->len - off >= 5 && memcmp(a->src + off, "cell", 4) == 0
                && (a->src[off + 4] == ' ' || a->src[off + 4] == '\t')) {
            size_t b = off + 5, e;
            if (a->ncells == 256) {
                a->line = line;
                aerr(a, "AXI-B024", "module has more than 256 cells",
                     "the encoded call index is one byte");
                return;
            }
            while (b < a->len && (a->src[b] == ' ' || a->src[b] == '\t')) b++;
            e = b;
            while (e < a->len && a->src[e] != ' ' && a->src[e] != '\t'
                    && a->src[e] != '\n') e++;
            char **names = asm_realloc(a,
                a->cellnames, (a->ncells + 1) * sizeof(char *));
            char *nm;
            if (!names) {
                fprintf(AXI_ERR, "AXI-D999 %s: out of memory\n", a->path);
                a->errs++;
                return;
            }
            a->cellnames = names;
            nm = asm_malloc(a, e - b + 1);
            if (!nm) {
                fprintf(AXI_ERR, "AXI-D999 %s: out of memory\n", a->path);
                a->errs++;
                return;
            }
            memcpy(nm, a->src + b, e - b); nm[e - b] = 0;
            a->cellnames[a->ncells++] = nm;
        }
        while (off < a->len && a->src[off] != '\n') off++;
        if (off < a->len) {
            off++;
            if (line != UINT32_MAX) line++;
        }
    }
}

static void aerr(asm_st *a, const char *code, const char *msg, const char *fix) {
    fprintf(AXI_ERR, "%s %s:%u: %s | fix: %s\n", code, a->path, a->line, msg, fix);
    a->errs++;
}

/* one line at a time; returns 0 at EOF */
static int next_line(asm_st *a, char *buf, size_t cap) {
    if (a->off == a->len) return 0;
    size_t n = 0;
    int overflow = 0;
    while (a->off < a->len && a->src[a->off] != '\n') {
        if (n + 1 < cap) buf[n++] = a->src[a->off];
        else overflow = 1;
        a->off++;
    }
    if (a->off < a->len && a->src[a->off] == '\n') a->off++;
    buf[n] = 0;
    a->line++;
    if (overflow) {
        aerr(a, "AXI-B025", "assembly line exceeds 511 bytes",
             "split the instruction or string; a line is never truncated");
        buf[0] = 0;
    }
    return 1;
}

/* W19: a quoted run is ONE token. Without this the assembler could not spell a
 * string containing a space — the first program that touches the world says
 * "metal na veia" and the space is part of the meaning. Inside quotes, '#' is
 * text, not a comment. No escapes in v0: what you type is what is sealed.
 * An unterminated quote is left with its opening '"' and no closing one, so the
 * const parser refuses it with AXI-B007 instead of silently truncating.
 * /AXI-INV-041/ */
static void split_ws(char *s, int *argc, char *argv[8]) {
    int n = 0;
    while (*s && n < 8) {
        while (*s == ' ' || *s == '\t') s++;
        if (!*s || *s == '#') break;              /* # comment to EOL */
        argv[n++] = s;
        if (*s == '"') {
            s++;                                  /* opening quote */
            while (*s && *s != '"') {
                if (*s == '\\' && s[1]) s++;
                s++;
            }
            if (*s != '"') { *argc = 9; return; }
            s++;                                  /* closing quote, kept in token */
            if (*s && *s != ' ' && *s != '\t') { *argc = 9; return; }
        } else {
            while (*s && *s != ' ' && *s != '\t') s++;
        }
        if (*s) *s++ = 0;
    }
    while (*s == ' ' || *s == '\t') s++;
    if (*s && *s != '#') n = 9; /* token overflow is malformed, never ignored */
    *argc = n;
}

static void *asm_array_grow(asm_st *a, void *array, size_t *capacity,
                            size_t count, size_t element)
{
    size_t max = (size_t)-1 / element;
    size_t grown;
    void *storage;
    if (count <= *capacity) return array;
    if (count > max) {
        aerr(a, "AXI-B024", "assembly table size overflow",
             "reduce the cell's constants or instructions");
        return NULL;
    }
    grown = *capacity ? *capacity : 16;
    while (grown < count) {
        if (grown > max / 2) { grown = count; break; }
        grown *= 2;
    }
    storage = asm_realloc(a, array, grown * element);
    if (!storage) {
        aerr(a, "AXI-D999", "out of memory", "retry with enough host memory");
        return NULL;
    }
    *capacity = grown;
    return storage;
}

/* INV-342 / AXI-INV-108: numeric fields have one complete grammar. */
static int parse_uint(asm_st *a, const char *t, unsigned base,
                      uint64_t max, const char *code, uint64_t *out)
{
    uint64_t v = 0;
    size_t i = 0;
    if (!t[0]) goto bad;
    while (t[i]) {
        unsigned char c = (unsigned char)t[i++];
        unsigned d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (base == 16 && c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (base == 16 && c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else goto bad;
        if (d >= base || v > (max - d) / base) goto bad;
        v = v * base + d;
    }
    *out = v;
    return 1;
bad:
    aerr(a, code, "numeric field is malformed or overflows",
         "use one complete canonical number with no sign or suffix");
    return 0;
}

static int parse_i64(asm_st *a, const char *t, uint64_t *out)
{
    uint64_t mag;
    int neg = t[0] == '-';
    const char *digits = neg ? t + 1 : t;
    uint64_t max = neg ? UINT64_C(9223372036854775808)
                       : UINT64_C(9223372036854775807);
    if (!parse_uint(a, digits, 10, max, "AXI-B007", &mag)) return 0;
    *out = neg ? (uint64_t)(0 - mag) : mag;
    return 1;
}

static int parse_reg(asm_st *a, const char *t, uint8_t *out) {
    if (t[0] != 'r') { aerr(a, "AXI-B002", "expected register rN", "spell registers r0..r255"); return 0; }
    uint64_t v;
    if (!parse_uint(a, t + 1, 10, 255, "AXI-B002", &v)) return 0;
    *out = (uint8_t)v;
    return 1;
}
static int parse_k(asm_st *a, const char *t, uint32_t nk, uint16_t *out) {
    if (t[0] != 'k') { aerr(a, "AXI-B003", "expected const kN", "spell const refs k0..kN-1"); return 0; }
    uint64_t v;
    if (!parse_uint(a, t + 1, 10, 0xffff, "AXI-B003", &v)) return 0;
    if (v >= nk) {
        aerr(a, "AXI-B003", "const index out of range", "declare the const above the code");
        return 0;
    }
    *out = (uint16_t)v;
    return 1;
}
static int parse_cellref(asm_st *a, const char *t, uint8_t *out) {
    if (t[0] != '@') { aerr(a, "AXI-B014", "expected cell ref @name", "call rBASE @cell argc"); return 0; }
    for (uint32_t i = 0; i < a->ncells; i++)
        if (strcmp(a->cellnames[i], t + 1) == 0) {
            if (i > 0xFF) { aerr(a, "AXI-B014", "cell index over 255", "AXB v1 calls reach the first 256 cells"); return 0; }
            *out = (uint8_t)i;
            return 1;
        }
    aerr(a, "AXI-B014", "unknown cell in call", "the callee must be a cell in this module");
    return 0;
}
/* W19: @name → an INDEX into the module's declared authority. Refused here at
 * assembly, and re-derived at the instant of the effect: the front end is a
 * courtesy, the VM is the last door /AXI-INV-037/. */
static int parse_effref(asm_st *a, const axb_mod *m, const char *t, uint8_t *out) {
    if (t[0] != '@') {
        aerr(a, "AXI-B019", "expected effect ref @Name.Verb", "spell it: eff rA @Name.Verb rC");
        return 0;
    }
    int ix = axb_mod_eff_index(m, t + 1);
    if (ix < 0) {
        aerr(a, "AXI-B019", "undeclared effect", "declare it above the first cell: .eff <Name.Verb>");
        return 0;
    }
    *out = (uint8_t)ix;
    return 1;
}
static int parse_builtinref(asm_st *a, const axb_mod *m, const char *t, uint8_t *out) {
    if (t[0] != '@') {
        aerr(a, "AXI-B019", "expected builtin ref @Name", "spell it: builtin rA @Name rC");
        return 0;
    }
    int ix = axb_mod_builtin_index(m, t + 1);
    if (ix < 0) {
        aerr(a, "AXI-B019", "undeclared builtin", "declare it above the first cell: .builtin <Name>");
        return 0;
    }
    *out = (uint8_t)ix;
    return 1;
}
static int parse_imm8(asm_st *a, const char *t, uint8_t *out) {
    uint64_t v;
    if (!parse_uint(a, t, 10, 255, "AXI-B015", &v)) return 0;
    *out = (uint8_t)v;
    return 1;
}
static int parse_sbc(asm_st *a, const char *t, uint16_t *out) {
    if (t[0] != '+' && t[0] != '-') { aerr(a, "AXI-B004", "expected relative offset", "spell jumps +N or -N (words)"); return 0; }
    uint64_t mag;
    int neg = t[0] == '-';
    int64_t v;
    if (!parse_uint(a, t + 1, 10, neg ? 32768 : 32767, "AXI-B004", &mag)) return 0;
    v = neg ? -(int64_t)mag : (int64_t)mag;
    *out = (uint16_t)(int16_t)v;
    return 1;
}

static int asm_module(asm_st *a, axb_mod *m) {
    char line[512];
    axb_cell *c = NULL;
    size_t konst_capacity = 0, code_capacity = 0;
    while (next_line(a, line, sizeof line)) {
        int argc;
        char *argv[8];
        split_ws(line, &argc, argv);
        if (argc == 0) continue;
        if (strcmp(argv[0], ".eff") == 0) {
            /* W19: the module declares, in its own text — therefore inside
             * src_hash — every authority it may ever exercise. Declarations sit
             * above the first cell: the first thing a reviewer reads. */
            if (c || m->n) {
                aerr(a, "AXI-B018", "effect declared after code began",
                     "move every .eff above the first cell");
                continue;
            }
            if (argc != 2) { aerr(a, "AXI-B018", "malformed effect declaration", "spell it: .eff <Name.Verb>"); continue; }
            if (m->neff >= AXB_MAX_EFF) { aerr(a, "AXI-B020", "too many declared effects", "authority a reviewer cannot read is not authority"); continue; }
            if (axb_mod_eff_index(m, argv[1]) >= 0) { aerr(a, "AXI-B018", "effect declared twice", "one line per authority"); continue; }
            m->eff[m->neff] = asm_strdup(a, argv[1]);
            if (!m->eff[m->neff]) {
                aerr(a, "AXI-D999", "out of memory", "retry with enough host memory");
                return 1;
            }
            m->neff++;
            continue;
        }
        if (strcmp(argv[0], ".builtin") == 0) {
            /* M3: builtins are declared like effects, before any cell. */
            if (c || m->n) {
                aerr(a, "AXI-B018", "builtin declared after code began",
                     "move every .builtin above the first cell");
                continue;
            }
            if (argc != 2) { aerr(a, "AXI-B018", "malformed builtin declaration", "spell it: .builtin <Name>"); continue; }
            if (m->nbuiltin >= AXB_MAX_BUILTIN) { aerr(a, "AXI-B020", "too many declared builtins", "a reviewer cannot read an endless list"); continue; }
            if (axb_mod_builtin_index(m, argv[1]) >= 0) { aerr(a, "AXI-B018", "builtin declared twice", "one line per builtin"); continue; }
            m->builtin[m->nbuiltin] = asm_strdup(a, argv[1]);
            if (!m->builtin[m->nbuiltin]) {
                aerr(a, "AXI-D999", "out of memory", "retry with enough host memory");
                return 1;
            }
            m->nbuiltin++;
            continue;
        }
        if (strcmp(argv[0], "cell") == 0) {
            if (c) { aerr(a, "AXI-B005", "cell inside cell", "close the previous cell with `end`"); continue; }
            if (argc != 3 || strncmp(argv[2], "nregs=", 6) != 0) {
                aerr(a, "AXI-B005", "malformed cell header", "spell it: cell <name> nregs=<n>"); continue;
            }
            uint64_t nr;
            if (!parse_uint(a, argv[2] + 6, 10, AXB_MAX_REGS,
                            "AXI-B005", &nr)) continue;
            axb_cell *cells = asm_realloc(a,
                m->cells, (m->n + 1) * sizeof(axb_cell));
            if (!cells) {
                aerr(a, "AXI-D999", "out of memory", "retry with enough host memory");
                return 1;
            }
            m->cells = cells;
            c = &m->cells[m->n++];
            memset(c, 0, sizeof *c);
            konst_capacity = code_capacity = 0;
            c->name = asm_strdup(a, argv[1]);
            if (!c->name) {
                aerr(a, "AXI-D999", "out of memory", "retry with enough host memory");
                return 1;
            }
            c->nregs = (uint32_t)nr;
            continue;
        }
        if (strcmp(argv[0], "end") == 0) {
            if (argc != 1) {
                aerr(a, "AXI-B008", "end takes no operands", "spell it: end");
                continue;
            }
            if (!c) aerr(a, "AXI-B006", "end without cell", "delete the stray `end`");
            c = NULL;
            continue;
        }
        if (!c) { aerr(a, "AXI-B006", "code outside cell", "open a cell first: cell <name> nregs=<n>"); continue; }
        if (argv[0][0] == 'k' && argv[0][1] >= '0' && argv[0][1] <= '9') {
            /* kN <tag> <payload> — consts must appear in order */
            uint64_t idx;
            if (!parse_uint(a, argv[0] + 1, 10, 0xffff, "AXI-B007", &idx)
                    || idx != c->nk || argc != 3) {
                aerr(a, "AXI-B007", "const out of order or malformed", "declare k0,k1,... in order: kN u64|i64|f64|str|err <payload>");
                continue;
            }
            axb_konst *konsts = asm_array_grow(a, c->k, &konst_capacity,
                                               (size_t)c->nk + 1, sizeof *c->k);
            if (!konsts) return 1;
            c->k = konsts;
            axb_konst *k = &c->k[c->nk];
            memset(k, 0, sizeof *k);
            if (strcmp(argv[1], "u64") == 0) {
                k->tag = AXB_KU64;
                if (!parse_uint(a, argv[2], 10, UINT64_MAX, "AXI-B007", &k->u)) continue;
            } else if (strcmp(argv[1], "i64") == 0) {
                k->tag = AXB_KI64;
                if (!parse_i64(a, argv[2], &k->u)) continue;
            } else if (strcmp(argv[1], "f64") == 0) {
                k->tag = AXB_KF64;
                if (!parse_uint(a, argv[2], 16, UINT64_MAX, "AXI-B007", &k->u)) continue;
            }
            else if (strcmp(argv[1], "str") == 0 || strcmp(argv[1], "err") == 0) {
                k->tag = argv[1][0] == 's' ? AXB_KSTR : AXB_KERR;
                const char *s = argv[2];
                size_t sl = strlen(s);
                if (sl < 2 || s[0] != '"' || s[sl-1] != '"') {
                    aerr(a, "AXI-B007", "string const needs quotes", "kN str \"bytes\" (no escapes in v0)");
                    continue;
                }
                /* INV-323 / AXI-INV-105: one decoder, one meaning — the
                 * assembler uses the same door as the codegen. */
                char *buf = asm_unescape(a, s, sl, &k->slen);
                if (!buf) {
                    aerr(a, "AXI-D999", "out of memory or malformed string",
                         "kN str \"bytes\" with the source string grammar");
                    return 1;
                }
                k->s = buf;
            } else { aerr(a, "AXI-B007", "unknown const tag", "u64|i64|f64|str|err"); continue; }
            c->nk++;
            continue;
        }
        int op = axb_op_by_name(argv[0], strlen(argv[0]));
        if (op < 0) { aerr(a, "AXI-B001", "unknown opcode", "the opcode table in axi_bc.h is the whole truth"); continue; }
        const axb_opinfo *oi = &OPINFO[op];
        uint8_t ra = 0, rb = 0, rc = 0; uint16_t bc16 = 0; int ok = 1;
        int want = (oi->ops == AXB_OPS_NONE) ? 1 :
                   (oi->ops == AXB_OPS_RA || oi->ops == AXB_OPS_SBC) ? 2 :
                   (oi->ops == AXB_OPS_RA_RB_RC || oi->ops == AXB_OPS_RA_CB_IC ||
                    oi->ops == AXB_OPS_RA_EB_RC || oi->ops == AXB_OPS_RA_BB_RC) ? 4 : 3;
        if (argc != want) {
            aerr(a, "AXI-B008", "wrong operand count", "match the shape in axi_bc.h");
            continue;
        }
        switch (oi->ops) {
        case AXB_OPS_NONE: break;
        case AXB_OPS_RA:       ok = parse_reg(a, argv[1], &ra); break;
        case AXB_OPS_RA_RB:    ok = parse_reg(a, argv[1], &ra) && parse_reg(a, argv[2], &rb); break;
        case AXB_OPS_RA_RB_RC: ok = parse_reg(a, argv[1], &ra) && parse_reg(a, argv[2], &rb) && parse_reg(a, argv[3], &rc); break;
        case AXB_OPS_RA_KBC:   ok = parse_reg(a, argv[1], &ra) && parse_k(a, argv[2], c->nk, &bc16); break;
        case AXB_OPS_RA_SBC:   ok = parse_reg(a, argv[1], &ra) && parse_sbc(a, argv[2], &bc16); break;
        case AXB_OPS_SBC:      ok = parse_sbc(a, argv[1], &bc16); break;
        case AXB_OPS_RA_CB_IC: ok = parse_reg(a, argv[1], &ra) && parse_cellref(a, argv[2], &rb) && parse_imm8(a, argv[3], &rc); break;
        case AXB_OPS_RA_EB_RC: ok = parse_reg(a, argv[1], &ra) && parse_effref(a, m, argv[2], &rb) && parse_reg(a, argv[3], &rc); break;
        case AXB_OPS_RA_BB_RC: ok = parse_reg(a, argv[1], &ra) && parse_builtinref(a, m, argv[2], &rb) && parse_reg(a, argv[3], &rc); break;
        }
        if (!ok) continue;
        if (oi->ops == AXB_OPS_RA_KBC || oi->ops == AXB_OPS_RA_SBC || oi->ops == AXB_OPS_SBC) {
            rb = (uint8_t)(bc16 >> 8); rc = (uint8_t)bc16;
        }
        if (c->nc == UINT32_MAX) {
            aerr(a, "AXI-B024", "too many instructions in one cell",
                 "the encoded instruction count is 32 bits");
            return 1;
        }
        uint32_t *code = asm_array_grow(a, c->code, &code_capacity,
                                       (size_t)c->nc + 1, sizeof *c->code);
        if (!code) return 1;
        c->code = code;
        c->code[c->nc++] = (uint32_t)op | (uint32_t)ra << 8 | (uint32_t)rb << 16 | (uint32_t)rc << 24;
    }
    if (c) aerr(a, "AXI-B005", "cell not closed at EOF", "close it with `end`");
    return a->errs ? 1 : 0;
}

/* ---- disassembler (canonical spelling) ------------------------------ */
typedef struct {
    FILE *file;
    char *p;
    size_t len, cap, max;
    axi_mem_account *account;
    int strict_strings;
    int failed;
} text_sink;

static void ts_grow(text_sink *s, size_t need)
{
    size_t cap, ceiling, required;
    char *p;
    if (s->failed || s->file) return;
    if ((s->max && (s->len > s->max || need > s->max - s->len))
            || s->len == (size_t)-1
            || need > (size_t)-1 - s->len - 1) {
        s->failed = 1;
        return;
    }
    required = s->len + need + 1;
    if (required <= s->cap) return;
    ceiling = s->max == (size_t)-1 ? (size_t)-1 : s->max + 1u;
    cap = s->cap ? s->cap : 512u;
    if (s->max && cap > ceiling) cap = ceiling;
    while (required > cap) {
        if (cap > (size_t)-1 / 2) {
            if (s->account)
                (void)axi_mem_realloc(s->account, s->p, (size_t)-1);
            s->failed = 1;
            return;
        }
        cap *= 2;
        if (s->max && cap > ceiling) cap = ceiling;
    }
    p = s->account ? axi_mem_realloc(s->account, s->p, cap)
                   : axi_realloc(s->p, cap);
    if (!p) { s->failed = 1; return; }
    s->p = p;
    s->cap = cap;
}

static void ts_printf(text_sink *s, const char *fmt, ...)
{
    va_list ap;
    int n;
    va_start(ap, fmt);
    if (s->file) {
        if (vfprintf(s->file, fmt, ap) < 0) s->failed = 1;
        va_end(ap);
        return;
    }
    {
        va_list copy;
        va_copy(copy, ap);
        n = vsnprintf(NULL, 0, fmt, copy);
        va_end(copy);
    }
    if (n < 0) { s->failed = 1; va_end(ap); return; }
    ts_grow(s, (size_t)n);
    if (!s->failed) {
        (void)vsnprintf(s->p + s->len, s->cap - s->len, fmt, ap);
        s->len += (size_t)n;
    }
    va_end(ap);
}

static void ts_ch(text_sink *s, int ch)
{
    if (s->file) {
        if (fputc(ch, s->file) == EOF) s->failed = 1;
        return;
    }
    ts_grow(s, 1);
    if (!s->failed) { s->p[s->len++] = (char)ch; s->p[s->len] = '\0'; }
}

/* Text-string contract v1: both tags preserve declared byte lengths and
 * spell supported controls with the same escapes consumed by the lexer. */
static void ts_quoted(text_sink *s, const char *p, uint32_t len)
{
    uint32_t i;
    ts_ch(s, '"');
    for (i = 0; i < len && !s->failed; i++) {
        unsigned char ch = (unsigned char)p[i];
        char escaped[2];
        int count = axi_string_escape_byte(ch, escaped);
        if (!count) {
            if (s->strict_strings) { s->failed = 1; break; }
            ts_ch(s, ch);
        } else for (int j = 0; j < count; j++) ts_ch(s, escaped[j]);
    }
    ts_ch(s, '"');
}

static void render_module(const axb_mod *m, text_sink *out) {
    /* W19: authority first, always — the reviewer reads what this module may do
     * before reading a single instruction. Canonical order, one per line. */
    for (uint32_t i = 0; i < m->neff && !out->failed; i++) ts_printf(out, ".eff %s\n", m->eff[i]);
    for (uint32_t i = 0; i < m->nbuiltin && !out->failed; i++) ts_printf(out, ".builtin %s\n", m->builtin[i]);
    if (m->neff || m->nbuiltin) ts_ch(out, '\n');
    for (uint32_t i = 0; i < m->n && !out->failed; i++) {
        const axb_cell *c = &m->cells[i];
        if (i) ts_ch(out, '\n');   /* canonical: one blank line between cells (W05) */
        ts_printf(out, "cell %s nregs=%u\n", c->name, c->nregs);
        for (uint32_t j = 0; j < c->nk && !out->failed; j++) {
            const axb_konst *k = &c->k[j];
            switch (k->tag) {
            case AXB_KU64: ts_printf(out, "  k%u u64 %llu\n", j, (unsigned long long)k->u); break;
            case AXB_KI64: ts_printf(out, "  k%u i64 %lld\n", j, (long long)(int64_t)k->u); break;
            case AXB_KF64: ts_printf(out, "  k%u f64 %llx\n", j, (unsigned long long)k->u); break;
            case AXB_KSTR: {
                ts_printf(out, "  k%u str ", j);
                ts_quoted(out, k->s, k->slen);
                ts_ch(out, '\n');
                break;
            }
            case AXB_KERR:
                ts_printf(out, "  k%u err ", j);
                ts_quoted(out, k->s, k->slen);
                ts_ch(out, '\n');
                break;
            }
        }
        for (uint32_t j = 0; j < c->nc && !out->failed; j++) {
            uint32_t w = c->code[j];
            uint8_t op = (uint8_t)w, ra = (uint8_t)(w>>8), rb = (uint8_t)(w>>16), rc = (uint8_t)(w>>24);
            const axb_opinfo *oi = axb_op_info(op);
            if (!oi) { ts_printf(out, "  # AXI-B013 bad opcode %u\n", op); continue; }
            uint16_t bc16 = (uint16_t)(rb << 8 | rc);
            switch (oi->ops) {
            case AXB_OPS_NONE:     ts_printf(out, "  %s\n", oi->name); break;
            case AXB_OPS_RA:       ts_printf(out, "  %s r%u\n", oi->name, ra); break;
            case AXB_OPS_RA_RB:    ts_printf(out, "  %s r%u r%u\n", oi->name, ra, rb); break;
            case AXB_OPS_RA_RB_RC: ts_printf(out, "  %s r%u r%u r%u\n", oi->name, ra, rb, rc); break;
            case AXB_OPS_RA_KBC:   ts_printf(out, "  %s r%u k%u\n", oi->name, ra, bc16); break;
            case AXB_OPS_RA_SBC:   ts_printf(out, "  %s r%u %+d\n", oi->name, ra, (int16_t)bc16); break;
            case AXB_OPS_SBC:      ts_printf(out, "  %s %+d\n", oi->name, (int16_t)bc16); break;
            case AXB_OPS_RA_CB_IC:
                if (rb < m->n) ts_printf(out, "  %s r%u @%s %u\n", oi->name, ra, m->cells[rb].name, rc);
                else           ts_printf(out, "  # AXI-B014 bad cell index %u\n", rb);
                break;
            case AXB_OPS_RA_EB_RC:
                /* W19: an effect index with no declaration behind it is not a
                 * name the disassembler may invent — it is a broken module. */
                if (rb < m->neff) ts_printf(out, "  %s r%u @%s r%u\n", oi->name, ra, m->eff[rb], rc);
                else              ts_printf(out, "  # AXI-B019 bad effect index %u\n", rb);
                break;
            case AXB_OPS_RA_BB_RC:
                if (rb < m->nbuiltin) ts_printf(out, "  %s r%u @%s r%u\n", oi->name, ra, m->builtin[rb], rc);
                else                  ts_printf(out, "  # AXI-B019 bad builtin index %u\n", rb);
                break;
            }
        }
        ts_printf(out, "end\n");
    }
}

char *axb_mod_dis_text(const axb_mod *m, size_t *out_len)
{
    text_sink out = {0};
    if (out_len) *out_len = 0;
    if (!m) return NULL;
    ts_grow(&out, 0);
    if (!out.failed) out.p[0] = '\0';
    render_module(m, &out);
    if (out.failed) { free(out.p); return NULL; }
    if (out_len) *out_len = out.len;
    return out.p;
}

char *axb_mod_dis_text_bounded(const axb_mod *m, size_t max, size_t *out_len)
{
    if (out_len) *out_len = 0;
    return axb_mod_dis_text_bounded_accounted(m, max, out_len, NULL);
}

char *axb_mod_dis_text_bounded_accounted(const axb_mod *m, size_t max,
                                         size_t *out_len,
                                         axi_mem_account *account)
{
    text_sink out = {0};
    if (!m || max == 0) return NULL;
    out.max = max;
    out.account = account;
    out.strict_strings = 1;
    ts_grow(&out, 0);
    if (!out.failed) out.p[0] = '\0';
    render_module(m, &out);
    if (out.failed) {
        (void)account_free_preserve_failure(account, out.p);
        return NULL;
    }
    if (out_len) *out_len = out.len;
    return out.p;
}

static void dis_module(const axb_mod *m, FILE *out)
{
    text_sink sink = {0};
    sink.file = out;
    render_module(m, &sink);
}

/* ---- file plumbing --------------------------------------------------- */
static char *slurp(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(AXI_ERR, "AXI-C001 cannot read file: %s\n", path); return NULL; }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    char *p = axi_malloc((size_t)sz + 1);
    if (!p) {
        fprintf(AXI_ERR, "AXI-D999 %s: out of memory\n", path);
        fclose(f);
        return NULL;
    }
    if (fread(p, 1, (size_t)sz, f) != (size_t)sz) { fclose(f); free(p); return NULL; }
    fclose(f);
    p[sz] = 0;
    if (n) *n = (size_t)sz;
    return p;
}

/* ---- W14: what "the source bytes" means, said exactly once ------------
 * The module binds to the WHOLE file, not to the prefix the lexer happens
 * to consume. An embedded NUL would split those two: the lexer stops, the
 * file does not, and two different files could then claim one hash. So a
 * NUL in axial text is refused here, at the door, fail-closed. */
static int src_bind_hash(const char *src, size_t n, const char *path,
                         uint8_t out[32]) {
    if (memchr(src, 0, n) != NULL) {
        fprintf(AXI_ERR, "AXI-B017 %s: NUL byte in source text | "
                "fix: axial source is text; strip the NUL — a module cannot "
                "bind to bytes its own lexer refuses to read\n", path);
        return 1;
    }
    axi_sha256(src, n, out);
    return 0;
}

/* W12: the one door from .axs text to a module. The seal runner and
 * cmd_asm both enter here — a second assembler would be a second truth. */
int axb_asm_text(const char *src, size_t n, const char *path, axb_mod *m)
{
    return axb_asm_text_accounted(src, n, path, m, NULL);
}

int axb_asm_text_accounted(const char *src, size_t n, const char *path,
                            axb_mod *m, axi_mem_account *account)
{
    asm_st a = { .path = path ? path : "<assembly>",
                 .src = src ? src : "", .len = n, .account = account };
    int rc;
    if (!m || (!src && n) || m->cells || m->n || m->neff || m->nbuiltin) return 1;
    if (account && !axi_mem_reserve(account, sizeof a + 512)) return 1;
    m->builder_account = account;
    if (src_bind_hash(a.src, n, a.path, m->src_hash) != 0) {
        (void)account_release_preserve_failure(account, sizeof a + 512);
        return 1;
    }
    prescan_cells(&a);
    rc = a.errs ? 1 : asm_module(&a, m);
    for (uint32_t i = 0; i < a.ncells; i++)
        (void)account_free_preserve_failure(account, a.cellnames[i]);
    (void)account_free_preserve_failure(account, a.cellnames);
    (void)account_release_preserve_failure(account, sizeof a + 512);
    return rc;
}

/* INV-342 / AXI-INV-108; INV-421 / AXI-INV-131: every AXB writer publishes
 * complete bytes through one temp/fsync/close/rename door; a refusal only
 * removes the private temp. */
static int open_publication_parent(const char *path, char leaf[256])
{
    char parent[4096];
    char *slash;
    int fd;
    struct stat st;
    size_t len;
    if (!path || !*path || !leaf
            || (len = strlen(path)) >= 4096u) return -1;
    memcpy(parent, path, len + 1);
    slash = strrchr(parent, '/');
    if (slash) {
        if (slash[1] == '\0') return -1;
        if (strlen(slash + 1) >= 256u) return -1;
        memcpy(leaf, slash + 1, strlen(slash + 1) + 1);
        if (slash == parent) slash[1] = '\0';
        else *slash = '\0';
    } else {
        memcpy(parent, ".", 2);
        if (len >= 256u) return -1;
        memcpy(leaf, path, len + 1);
    }
    fd = open(parent, O_RDONLY);
    if (fd < 0) return -1;
    if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode)) {
        close(fd);
        return -1;
    }
    return fd;
}

static int sync_parent_directory(const char *path)
{
    char leaf[256];
    int fd = open_publication_parent(path, leaf);
    int rc;
    if (fd < 0) return -1;
    rc = fsync(fd);
    if (close(fd) != 0) rc = -1;
    return rc;
}

static int write_all_fd(int fd, const uint8_t *bytes, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, bytes + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

int axb_atomic_publish_bytes_accounted(const uint8_t *bytes, size_t len,
                                       const char *out_path,
                                       axi_mem_account *account)
{
    char leaf[256];
    int rc = 0, fd = -1, parent_fd = -1;
    int n;
    char *tmp;
    size_t leaf_len, tmp_len;
    unsigned attempt;
    if (!bytes || len == 0 || !out_path || !*out_path) return 2;
    parent_fd = open_publication_parent(out_path, leaf);
    if (parent_fd < 0 || !*leaf) return 2;
    leaf_len = strlen(leaf);
    if (leaf_len > (size_t)-1 - 64u) {
        if (account) (void)axi_mem_alloc(account, (size_t)-1);
        close(parent_fd);
        return 2;
    }
    tmp_len = leaf_len + 64u;
    tmp = account ? axi_mem_alloc(account, tmp_len) : axi_malloc(tmp_len);
    if (!tmp) { close(parent_fd); return 2; }
    for (attempt = 0; attempt < 128u; attempt++) {
        n = snprintf(tmp, tmp_len, ".%s.tmp.%ld.%u", leaf,
                     (long)getpid(), attempt);
        if (n < 0 || (size_t)n >= tmp_len) {
            rc = 2;
            goto done;
        }
        fd = openat(parent_fd, tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0 || errno != EEXIST) break;
    }
    if (fd < 0) {
        fprintf(AXI_ERR, "AXI-C002 cannot publish atomically: %s\n", out_path);
        rc = 2;
        goto done;
    }
    if (write_all_fd(fd, bytes, len) != 0 || fsync(fd) != 0) {
        fprintf(AXI_ERR, "AXI-C002 cannot publish atomically: %s\n", out_path);
        rc = 2;
        close(fd);
        fd = -1;
        unlinkat(parent_fd, tmp, 0);
    } else if (close(fd) != 0) {
        fprintf(AXI_ERR, "AXI-C002 cannot close publication: %s\n", out_path);
        rc = 2;
        fd = -1;
        unlinkat(parent_fd, tmp, 0);
    } else if (renameat(parent_fd, tmp, parent_fd, leaf) != 0) {
        fprintf(AXI_ERR, "AXI-C002 cannot publish atomically: %s\n", out_path);
        rc = 2;
        fd = -1;
        unlinkat(parent_fd, tmp, 0);
    } else if (fsync(parent_fd) != 0) {
        fprintf(AXI_ERR, "AXI-C002 publication directory is not durable: %s\n",
                out_path);
        rc = 2;
    }
done:
    if (fd >= 0) close(fd);
    if (parent_fd >= 0) close(parent_fd);
    (void)account_free_preserve_failure(account, tmp);
    return rc;
}

static int publication_path_root(const char *path, uint8_t root[32],
                                 int *present)
{
    struct stat info;
    void *bytes = MAP_FAILED;
    int fd;
    if (!path || !root || !present) return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) {
            memset(root, 0, 32);
            *present = 0;
            return 0;
        }
        return -1;
    }
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size < 0
            || (uint64_t)info.st_size > (uint64_t)SIZE_MAX) goto failed;
    if (info.st_size == 0) axi_sha256(NULL, 0, root);
    else {
        bytes = mmap(NULL, (size_t)info.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (bytes == MAP_FAILED) goto failed;
        axi_sha256(bytes, (size_t)info.st_size, root);
        if (munmap(bytes, (size_t)info.st_size) != 0) {
            bytes = MAP_FAILED;
            goto failed;
        }
        bytes = MAP_FAILED;
    }
    if (close(fd) != 0) return -1;
    *present = 1;
    return 0;
failed:
    if (bytes != MAP_FAILED) (void)munmap(bytes, (size_t)info.st_size);
    close(fd);
    return -1;
}

int axb_atomic_publish_bytes_result(const uint8_t *bytes, size_t len,
                                    const char *out_path,
                                    axb_publish_result *result)
{
    uint8_t current[32];
    int present = 0, rc;
    if (!bytes || len == 0 || !out_path || !result) return 2;
    memset(result, 0, sizeof *result);
    axi_sha256(bytes, len, result->intended_root);
    if (publication_path_root(out_path, result->predecessor_root,
                              &result->had_predecessor) != 0) {
        result->state = AXB_PUBLISH_CONFLICT;
        return 2;
    }
    rc = axb_atomic_publish_bytes_accounted(bytes, len, out_path, NULL);
    if (rc == 0) {
        result->state = AXB_PUBLISH_COMMITTED;
        return 0;
    }
    if (publication_path_root(out_path, current, &present) == 0
            && present
            && memcmp(current, result->intended_root, 32) == 0)
        result->state = AXB_PUBLISH_COMMIT_AMBIGUOUS;
    else
        result->state = AXB_PUBLISH_NOT_COMMITTED;
    return rc;
}

int axb_atomic_recover_bytes(const uint8_t *bytes, size_t len,
                             const char *out_path,
                             const axb_publish_result *previous,
                             axb_publish_state *state)
{
    uint8_t intended[32], current[32];
    int fd = -1, present = 0;
    if (!bytes || len == 0 || !out_path || !previous || !state) return 2;
    axi_sha256(bytes, len, intended);
    if (memcmp(intended, previous->intended_root, 32) != 0
            || publication_path_root(out_path, current, &present) != 0) {
        *state = AXB_PUBLISH_CONFLICT;
        return 2;
    }
    if (present && memcmp(current, intended, 32) == 0) {
        fd = open(out_path, O_RDONLY);
        if (fd < 0) {
            *state = AXB_PUBLISH_COMMIT_AMBIGUOUS;
            return 2;
        }
        int sync_rc = fsync(fd);
        int close_rc = close(fd);
        fd = -1;
        if (sync_rc != 0 || close_rc != 0
                || sync_parent_directory(out_path) != 0) {
            *state = AXB_PUBLISH_COMMIT_AMBIGUOUS;
            return 2;
        }
        *state = AXB_PUBLISH_COMMITTED;
        return 0;
    }
    if ((!present && !previous->had_predecessor)
            || (present && previous->had_predecessor
                && memcmp(current, previous->predecessor_root, 32) == 0)) {
        *state = AXB_PUBLISH_NOT_COMMITTED;
        return 0;
    }
    *state = AXB_PUBLISH_CONFLICT;
    return 2;
}

int axb_atomic_publish_bytes(const uint8_t *bytes, size_t len,
                             const char *out_path)
{
    return axb_atomic_publish_bytes_accounted(bytes, len, out_path, NULL);
}

int axb_mod_write(const axb_mod *m, const char *out_path) {
    wbuf w = {0};
    int rc;
    if (axb_mod_verify(m, out_path, NULL) != 0) return 1;
    mod_emit(m, &w);
    if (w.oom) {
        fprintf(AXI_ERR, "AXI-D999 %s: out of memory before publication\n",
                out_path);
        free(w.p);
        return 2;
    }
    rc = axb_atomic_publish_bytes(w.p, w.len, out_path);
    free(w.p);
    return rc;
}

int axb_contract_v7_write_signed(const axb_contract_mod *m,
                                 const uint8_t seed[32], const char *out_path)
{
    return axb_contract_v7_write_signed_accounted(m, seed, out_path, NULL);
}

int axb_contract_v7_write_signed_accounted(const axb_contract_mod *m,
    const uint8_t seed[32], const char *out_path, axi_mem_account *account)
{
    uint8_t *bytes = NULL;
    size_t len = 0;
    int rc;
    if (!m || !seed || !out_path || !*out_path) return 1;
    if (axb_contract_v7_encode_signed_accounted(m, seed, &bytes, &len, account) != 0) return 1;
    rc = axb_atomic_publish_bytes_accounted(bytes, len, out_path, account);
    (void)account_free_preserve_failure(account, bytes);
    return rc;
}

/* INV-422 / AXI-INV-132: path loading applies the complete signed-container
 * ceiling before allocation and publishes only the trusted decoded model. */
int axb_contract_v7_load_trusted(axb_contract_mod *out, const char *path,
                                 const uint8_t trusted_pk[32])
{
    FILE *f = NULL;
    uint8_t *bytes = NULL;
    long size;
    int rc = 1;
    if (!out || !path || !*path || !trusted_pk) return 1;
    f = fopen(path, "rb");
    if (!f || fseek(f, 0, SEEK_END) != 0) goto done;
    size = ftell(f);
    if (size < 0 || (size_t)size > AXB_CONTRACT_MAX_BYTES + AXBS_TRAILER
            || (size_t)size < AXBS_TRAILER + 8
            || fseek(f, 0, SEEK_SET) != 0) goto done;
    bytes = axi_malloc((size_t)size);
    if (!bytes || fread(bytes, 1, (size_t)size, f) != (size_t)size
            || fgetc(f) != EOF || ferror(f)) goto done;
    if (fclose(f) != 0) { f = NULL; goto done; }
    f = NULL;
    rc = axb_contract_v7_decode_trusted(out, bytes, (size_t)size, trusted_pk);
done:
    if (f) (void)fclose(f);
    free(bytes);
    return rc;
}

int cmd_asm(const char *in, const char *out_path) {
    size_t n; char *src = slurp(in, &n);
    if (!src) return 2;
    axb_mod m = {0};
    int rc = axb_asm_text(src, n, in, &m);
    if (rc == 0) rc = axb_mod_write(&m, out_path);
    axb_mod_free(&m); free(src);
    return rc;
}

int axb_mod_load(axb_mod *m, const char *path, struct axi_arena *ar) {
    size_t n; char *raw = slurp(path, &n);
    if (!raw) return 2;
    int rc = axb_mod_read(m, (const uint8_t *)raw, n, path, ar);
    free(raw);
    return rc;
}

/* ---- W21: seal — the producer signs, and after that the bytes are not
 * theirs to change either. `axi seal mod.axb --key seed` appends exactly one
 * trailer; `axi verify mod.axb` says who signed, or refuses.
 *
 * The key file is 32 raw bytes of seed the operator generated and owns. This
 * tool reads it, uses it, and wipes it — it never prints it, never copies it
 * beside the artifact, and never invents one for you. A tool that quietly
 * manufactures an identity is not signing, it is impersonating. */
static int seed_load(const char *path, uint8_t seed[32]) {
    size_t n; char *raw = slurp(path, &n);
    if (!raw) return 2;
    if (n != 32) {
        fprintf(AXI_ERR, "AXI-N001 %s: key file is %llu bytes, a seed is exactly 32 | "
                "fix: this wants raw seed bytes, not hex and not a PEM\n",
                path, (unsigned long long)n);
        memset(raw, 0, n); free(raw);
        return 1;
    }
    memcpy(seed, raw, 32);
    memset(raw, 0, n);
    free(raw);
    return 0;
}

int cmd_sign(const char *mod_path, const char *key_path) {
    axi_arena ar; axi_arena_init(&ar, 1u << 20);
    axb_mod m = {0};
    uint8_t seed[32];
    axi_sig s;
    uint8_t trailer[AXBS_TRAILER];
    char hex[65];
    size_t n;
    char *raw = NULL;
    char *tmp = NULL;
    FILE *f = NULL;
    int fd = -1;
    int rc = axb_mod_load(&m, mod_path, &ar);

    if (rc == 0 && m.has_sig) {
        /* Re-signing would mean two producers claiming one artifact, or one
         * producer quietly replacing the other. Neither is a thing this
         * format can express, so neither is a thing it will pretend to do. */
        fprintf(AXI_ERR, "AXI-N002 %s: already signed | fix: a module carries one signature; reassemble from source to sign again\n",
                mod_path);
        rc = 1;
    }
    if (rc != 0) { axi_arena_free(&ar); return rc; }

    /* Sign the body we just proved parses. Signing bytes nobody validated
     * would be a notary stamping a page they did not read. */
    raw = slurp(mod_path, &n);
    if (!raw) { axi_arena_free(&ar); return 2; }
    if (seed_load(key_path, seed) != 0) { free(raw); axi_arena_free(&ar); return 1; }

    rc = axi_sig_make((const uint8_t *)raw, m.body_len, seed, &s);
    memset(seed, 0, sizeof seed);
    if (rc != 0) {
        fprintf(AXI_ERR, "AXI-N003 %s: signing failed | fix: check the key file is a real seed\n", mod_path);
        free(raw); axi_arena_free(&ar); return 1;
    }

    axi_sig_write(&s, trailer);
    /* INV-367 / AXI-INV-116: signing publishes body+trailer through a private
     * temp. Buffered write, flush, fsync and close failures leave the reviewed
     * unsigned module byte-identical; rename is the only publication point. */
    tmp = axi_malloc(strlen(mod_path) + 16);
    if (tmp) {
        sprintf(tmp, "%s.tmp.XXXXXX", mod_path);
        fd = mkstemp(tmp);
        f = fd >= 0 ? fdopen(fd, "wb") : NULL;
    }
    if (!f || fwrite(raw, 1, n, f) != n
            || fwrite(trailer, 1, AXBS_TRAILER, f) != AXBS_TRAILER
            || fflush(f) != 0 || fsync(fd) != 0) {
        if (f) fclose(f);
        else if (fd >= 0) close(fd);
        rc = 2;
    } else if (fclose(f) != 0) {
        rc = 2;
    } else if (rename(tmp, mod_path) != 0) {
        rc = 2;
    }
    if (rc != 0) {
        fprintf(AXI_ERR, "AXI-N004 %s: cannot publish signature atomically | fix: check write permission and disk space\n", mod_path);
        if (tmp) unlink(tmp);
        free(tmp); free(raw); axi_arena_free(&ar); return rc;
    }
    free(tmp);
    free(raw);

    axi_hash_hex(s.pk, hex);
    printf("signed %s by %s\n", mod_path, hex);
    axi_arena_free(&ar);
    return 0;
}

int cmd_dis(const char *in) {
    axi_arena ar; axi_arena_init(&ar, 1u << 20);
    axb_mod m = {0};
    int rc = axb_mod_load(&m, in, &ar);
    if (rc == 0) dis_module(&m, AXI_OUT);
    axi_arena_free(&ar);
    return rc;
}

/* ---- W14: bind — the module names its source, the tool checks the claim.
 * `axi bind mod.axb src.axs`: recompute SHA-256 over the source bytes and
 * compare with the hash the module carries. Match prints the address and
 * exits 0; anything else is a refusal — a module you cannot tie back to
 * text is not evidence, it is a rumor. */
int cmd_bind(const char *mod_path, const char *src_path) {
    axi_arena ar; axi_arena_init(&ar, 1u << 20);
    axb_mod m = {0};
    uint8_t want[32];
    size_t n;
    int rc = axb_mod_load(&m, mod_path, &ar);
    if (rc == 0) {
        char *src = slurp(src_path, &n);
        if (!src) { axi_arena_free(&ar); return 2; }
        rc = src_bind_hash(src, n, src_path, want);
        free(src);
        if (rc != 0) { axi_arena_free(&ar); return rc; }
        if (memcmp(want, m.src_hash, 32) != 0) {
            fprintf(AXI_ERR, "AXI-B016 %s: src_hash does not match %s | "
                    "fix: reassemble from the true source; never edit either side\n",
                    mod_path, src_path);
            rc = 1;
        } else {
            for (int i = 0; i < 32; i++) printf("%02x", m.src_hash[i]);
            printf("  %s -> %s\n", src_path, mod_path);
        }
    }
    axi_arena_free(&ar);
    return rc;
}
