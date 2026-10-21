/* axial - production AXS contract-v1 profile (CA16/CA17 merge).
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 * INV-385 / AXI-INV-124.
 */
#include "axi_contract.h"

#include "axi_alloc.h"
#include "axi_builtin.h"
#include "axi_codegen.h"
#include "axi_hash.h"
#include "axi_iface.h"
#include "axi_osif.h"
#include "axi_sign.h"
#include "axi_u64.h"
#include "axi_vm.h"
#include "axi_wipe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONTRACT_MODULE_MAX (1024u * 1024u)

typedef struct {
    char *p;
    size_t n, cap, max;
    int failed;
    axi_mem_account *account;
} cbuf;

typedef struct {
    const char *p;
    size_t n;
} slice;

typedef struct {
    const char *src;
    size_t len, off;
} lines;

static void cb_grow(cbuf *b, size_t need)
{
    size_t cap;
    char *p;
    if (b->failed) return;
    if (b->max && (b->n > b->max || need > b->max - b->n)) {
        b->failed = 1;
        return;
    }
    if (need > (size_t)-1 - b->n - 1) { b->failed = 1; return; }
    if (b->n + need + 1 <= b->cap) return;
    cap = b->cap ? b->cap : 512;
    while (b->n + need + 1 > cap) {
        if (cap > (size_t)-1 / 2) { b->failed = 1; return; }
        cap *= 2;
    }
    p = b->account ? axi_mem_realloc(b->account, b->p, cap) : axi_realloc(b->p, cap);
    if (!p) { b->failed = 1; return; }
    b->p = p;
    b->cap = cap;
}

static void cb_raw(cbuf *b, const char *p, size_t n)
{
    cb_grow(b, n);
    if (b->failed) return;
    memcpy(b->p + b->n, p, n);
    b->n += n;
    b->p[b->n] = '\0';
}

static void cb_str(cbuf *b, const char *s) { cb_raw(b, s, strlen(s)); }
static void cb_ch(cbuf *b, char c) { cb_raw(b, &c, 1); }

static int line_next(lines *it, slice *out)
{
    size_t start;
    if (it->off >= it->len) return 0;
    start = it->off;
    while (it->off < it->len && it->src[it->off] != '\n') it->off++;
    out->p = it->src + start;
    out->n = it->off - start;
    if (it->off < it->len) it->off++;
    return 1;
}

static int seq(slice s, const char *text)
{
    size_t n = strlen(text);
    return s.n == n && memcmp(s.p, text, n) == 0;
}

static int prefix(slice s, const char *text)
{
    size_t n = strlen(text);
    return s.n >= n && memcmp(s.p, text, n) == 0;
}

static int fields(slice s, slice out[4])
{
    size_t i = 0;
    int n = 0;
    while (i < s.n) {
        size_t start;
        while (i < s.n && s.p[i] == ' ') i++;
        if (i == s.n) break;
        if (s.p[i] == '\t' || n == 4) return -1;
        start = i;
        while (i < s.n && s.p[i] != ' ') {
            if (s.p[i] == '\t') return -1;
            i++;
        }
        out[n].p = s.p + start;
        out[n].n = i - start;
        n++;
    }
    return n;
}

static int token_eq(slice s, const char *text)
{
    size_t n = strlen(text);
    return s.n == n && memcmp(s.p, text, n) == 0;
}

static int arena_str(axi_arena *arena, slice s, axb_mstr *out)
{
    char *p;
    if (s.n == 0 || s.n > UINT32_MAX) return 0;
    p = axi_arena_alloc(arena, s.n + 1);
    if (!p) return 0;
    memcpy(p, s.p, s.n);
    p[s.n] = '\0';
    out->p = p;
    out->len = (uint32_t)s.n;
    return 1;
}

static int parse_type(axi_arena *arena, slice a, slice b, int has_b,
                      int parameter, axb_mtype *out)
{
    static const struct { const char *name; uint8_t tag; } atoms[] = {
        {"u64", AXB_MT_U64}, {"i64", AXB_MT_I64}, {"f64", AXB_MT_F64},
        {"bool", AXB_MT_BOOL}, {"str", AXB_MT_STR},
        {"bytes", AXB_MT_BYTES}, {"json", AXB_MT_JSON},
        {"decision", AXB_MT_DECISION}, {"ok", AXB_MT_OK}
    };
    size_t i;
    memset(out, 0, sizeof *out);
    if (has_b) {
        if (!parameter || !token_eq(a, "cap") || !arena_str(arena, b, &out->name))
            return 0;
        out->tag = AXB_MT_CAP;
        return 1;
    }
    for (i = 0; i < sizeof atoms / sizeof atoms[0]; i++)
        if (token_eq(a, atoms[i].name)) {
            if (parameter && atoms[i].tag == AXB_MT_OK) return 0;
            out->tag = atoms[i].tag;
            return 1;
        }
    return 0;
}

static int parse_contract(lines *it, axb_manifest *m, axi_arena *arena)
{
    slice line, f[4];
    int stage = 0, have_fuel = 0;
    memset(m, 0, sizeof *m);
    m->version = AXB_MANIFEST_VERSION;
    while (line_next(it, &line)) {
        int nf;
        if (seq(line, "  endcontract")) return have_fuel ? 0 : 1;
        if (!prefix(line, "    ")) return 1;
        line.p += 4;
        line.n -= 4;
        if (prefix(line, "law ")) {
            slice law = {line.p + 4, line.n - 4};
            if (stage > 6 || m->nlaws >= AXB_MANIFEST_MAX_LAWS
                    || !arena_str(arena, law, &m->laws[m->nlaws])) return 1;
            stage = 6;
            m->nlaws++;
            continue;
        }
        nf = fields(line, f);
        if (nf < 1) return 1;
        if (token_eq(f[0], "param")) {
            if (stage > 0 || m->nparams >= AXB_MANIFEST_MAX_PARAMS
                    || (nf != 3 && nf != 4)
                    || !arena_str(arena, f[1], &m->params[m->nparams].name)
                    || !parse_type(arena, f[2], nf == 4 ? f[3] : f[2],
                                   nf == 4, 1, &m->params[m->nparams].type)) return 1;
            m->nparams++;
        } else if (token_eq(f[0], "ret")) {
            if (stage > 1 || nf != 2 || m->nreturns >= AXB_MANIFEST_MAX_RETURNS
                    || !parse_type(arena, f[1], f[1], 0, 0,
                                   &m->returns[m->nreturns])) return 1;
            stage = 1;
            m->nreturns++;
        } else if (token_eq(f[0], "err")) {
            if (stage > 2 || nf != 2 || m->nerrors >= AXB_MANIFEST_MAX_ERRORS
                    || !arena_str(arena, f[1], &m->errors[m->nerrors])) return 1;
            stage = 2;
            m->nerrors++;
        } else if (token_eq(f[0], "cap")) {
            if (stage > 3 || nf != 2 || m->ncaps >= AXB_MANIFEST_MAX_CAPS
                    || !arena_str(arena, f[1], &m->caps[m->ncaps])) return 1;
            stage = 3;
            m->ncaps++;
        } else if (token_eq(f[0], "fuel")) {
            if (stage > 4 || nf != 2 || have_fuel
                    || axi_u64_parse(f[1].p, f[1].n, AXI_U64_POSITIVE_ONLY,
                                     &m->fuel_max) != AXI_U64_OK) return 1;
            stage = 4;
            have_fuel = 1;
        } else if (token_eq(f[0], "pure") || token_eq(f[0], "policy")) {
            if (stage > 5 || nf != 1 || !have_fuel || m->flags != 0) return 1;
            stage = 5;
            m->flags = token_eq(f[0], "pure") ? AXB_MANIFEST_FLAG_PURE
                                               : AXB_MANIFEST_FLAG_POLICY;
        } else {
            return 1; /* hashes and unknown facts are never accepted. */
        }
    }
    return 1;
}

static int derivation_all_zero(const uint8_t h[32])
{
    int i;
    for (i = 0; i < 32; i++) if (h[i] != 0) return 0;
    return 1;
}

static int contract_free_owned(axi_mem_account *account, void *ptr);

void axb_contract_mod_free(axb_contract_mod *m)
{
    if (!m) return;
    if (!m->body_arena_owned) {
        axi_mem_account *account = m->body.builder_account;
        axb_mod_free(&m->body);
        (void)contract_free_owned(account, m->manifest);
    }
    axi_arena_free(&m->arena);
    memset(m, 0, sizeof *m);
}

typedef struct {
    const char *p;
    uint32_t len;
} cap_ref;

typedef struct {
    cap_ref v[AXB_MANIFEST_MAX_CAPS];
    uint32_t n;
} cap_set;

static const char *type_name(uint8_t tag);

static int cap_eq(cap_ref a, const char *p, size_t len)
{
    return a.len == len && memcmp(a.p, p, len) == 0;
}

static int cap_set_add(cap_set *set, const char *p, size_t len)
{
    uint32_t i;
    if (!p || len == 0 || len > UINT32_MAX) return 0;
    for (i = 0; i < set->n; i++)
        if (cap_eq(set->v[i], p, len)) return 1;
    if (set->n >= AXB_MANIFEST_MAX_CAPS) return 0;
    set->v[set->n].p = p;
    set->v[set->n].len = (uint32_t)len;
    set->n++;
    return 1;
}

static int cap_set_merge(cap_set *dst, const cap_set *src, int *changed)
{
    uint32_t i, before = dst->n;
    for (i = 0; i < src->n; i++)
        if (!cap_set_add(dst, src->v[i].p, src->v[i].len)) return 0;
    if (dst->n != before) *changed = 1;
    return 1;
}

static int cap_set_matches(const cap_set *set, const axb_manifest *manifest)
{
    uint32_t i, j;
    if (set->n != manifest->ncaps) return 0;
    for (i = 0; i < manifest->ncaps; i++) {
        for (j = 0; j < set->n; j++)
            if (cap_eq(set->v[j], manifest->caps[i].p,
                       manifest->caps[i].len)) break;
        if (j == set->n) return 0;
    }
    return 1;
}

static int bound_add(size_t *n, size_t add)
{
    if (add > CONTRACT_MODULE_MAX - *n) return 0;
    *n += add;
    return 1;
}

static size_t decimal_len(uint64_t n)
{
    size_t len = 1;
    while (n >= 10) { n /= 10; len++; }
    return len;
}

static size_t manifest_type_text_len(const axb_mtype *type)
{
    const char *name = type_name(type->tag);
    return name ? strlen(name) : 4u + type->name.len;
}

static int contract_text_fits(size_t body_len, const axb_contract_mod *m)
{
    size_t n = body_len;
    uint32_t i, j;
    for (i = 0; i < m->nmanifest; i++) {
        const axb_manifest *manifest = &m->manifest[i];
        if (!bound_add(&n, 27)) return 0;
        for (j = 0; j < manifest->nparams; j++)
            if (!bound_add(&n, 12u + manifest->params[j].name.len
                                + manifest_type_text_len(
                                      &manifest->params[j].type))) return 0;
        for (j = 0; j < manifest->nreturns; j++)
            if (!bound_add(&n, 9u + manifest_type_text_len(
                                      &manifest->returns[j]))) return 0;
        for (j = 0; j < manifest->nerrors; j++)
            if (!bound_add(&n, 9u + manifest->errors[j].len)) return 0;
        for (j = 0; j < manifest->ncaps; j++)
            if (!bound_add(&n, 9u + manifest->caps[j].len)) return 0;
        if (!bound_add(&n, 10u + decimal_len(manifest->fuel_max))) return 0;
        if ((manifest->flags & AXB_MANIFEST_FLAG_PURE) && !bound_add(&n, 9))
            return 0;
        if ((manifest->flags & AXB_MANIFEST_FLAG_POLICY) && !bound_add(&n, 11))
            return 0;
        for (j = 0; j < manifest->nlaws; j++)
            if (!bound_add(&n, 9u + manifest->laws[j].len)) return 0;
    }
    return 1;
}

static int contract_free_owned(axi_mem_account *account, void *ptr)
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

static int contract_release_owned(axi_mem_account *account, size_t size)
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

/* INV-386 / AXI-INV-125: contract authority is an exact graph fixpoint. */
static int contract_v1_verify_with_diags(const axb_contract_mod *m,
                                         axi_mem_account *account,
                                         axi_diags *diags)
{
    cap_set *closure = NULL;
    char *body_text = NULL;
    size_t body_len = 0;
    uint32_t i, j, pass;
    int rc = 1;
    if (!m || !m->manifest || m->body.n == 0 || m->body.n > 256
            || m->nmanifest != m->body.n || !m->body.cells) return 1;
    for (i = 0; i < m->body.n; i++) {
        const axb_cell *cell = &m->body.cells[i];
        if (!cell->name || cell->nk > 65536
                || cell->nc > CONTRACT_MODULE_MAX / sizeof *cell->code
                || (cell->nk && !cell->k) || (cell->nc && !cell->code))
            return 1;
        if ((cell->nregs ? cell->nregs : 1) < m->manifest[i].nparams)
            return 1;
        for (j = 0; j < cell->nk; j++)
            if ((cell->k[j].tag == AXB_KSTR || cell->k[j].tag == AXB_KERR)
                    && cell->k[j].slen > CONTRACT_MODULE_MAX) return 1;
    }
    axi_diags_init(diags);
    if (axb_mod_verify(&m->body, "<contract-v1>", diags) != 0) return 1;
    body_text = axb_mod_dis_text_bounded_accounted(
        &m->body, CONTRACT_MODULE_MAX, &body_len, account);
    if (!body_text) return 1;
    for (i = 0; i < m->body.n; i++) {
        const axb_manifest *manifest = &m->manifest[i];
        if (axb_manifest_v1_verify(manifest) != 0) goto done;
    }
    if (!contract_text_fits(body_len, m)) goto done;
    closure = account ? axi_mem_calloc(account, m->body.n, sizeof *closure)
                      : axi_calloc(m->body.n, sizeof *closure);
    if (!closure) goto done;
    for (i = 0; i < m->body.n; i++) {
        const axb_cell *cell = &m->body.cells[i];
        const axb_manifest *manifest = &m->manifest[i];
        uint8_t iface_hash[32], body_hash[32];
        if (axi_manifest_iface_hash_v1_accounted(
                cell->name, manifest, iface_hash, account) != 0
                || axb_cell_body_hash_v1_accounted(
                       cell, body_hash, account) != 0
                || memcmp(iface_hash, manifest->iface_hash, 32) != 0
                || memcmp(body_hash, manifest->body_hash, 32) != 0)
            goto done;
        for (j = 0; j < manifest->nparams; j++)
            if (manifest->params[j].type.tag == AXB_MT_CAP
                    && !cap_set_add(&closure[i],
                                    manifest->params[j].type.name.p,
                                    manifest->params[j].type.name.len)) goto done;
        for (j = 0; j < cell->nc; j++) {
            uint32_t word = cell->code[j];
            uint8_t op = (uint8_t)word;
            uint8_t b = (uint8_t)(word >> 16);
            uint8_t c = (uint8_t)(word >> 24);
            if (op == OP_CALL && c != m->manifest[b].nparams) goto done;
            if (op == OP_EFF
                    && !cap_set_add(&closure[i], m->body.eff[b],
                                    strlen(m->body.eff[b]))) goto done;
            if (op == OP_BUILTIN) {
                const axi_builtin_info *builtin = axi_builtin_lookup(
                    m->body.builtin[b], strlen(m->body.builtin[b]));
                if (!builtin) goto done;
                if (builtin->cap_name
                        && !cap_set_add(&closure[i], builtin->cap_name,
                                        strlen(builtin->cap_name))) goto done;
            }
        }
    }
    for (pass = 0; pass < m->body.n; pass++) {
        int changed = 0;
        for (i = 0; i < m->body.n; i++) {
            const axb_cell *cell = &m->body.cells[i];
            for (j = 0; j < cell->nc; j++) {
                uint32_t word = cell->code[j];
                if ((uint8_t)word == OP_CALL)
                    if (!cap_set_merge(&closure[i],
                                       &closure[(uint8_t)(word >> 16)],
                                       &changed)) goto done;
            }
        }
        if (!changed) break;
    }
    for (i = 0; i < m->body.n; i++)
        if (!cap_set_matches(&closure[i], &m->manifest[i])
                || ((m->manifest[i].flags & AXB_MANIFEST_FLAG_PURE)
                    && closure[i].n != 0)) goto done;
    /* AXI-CA17 / AXI-INV-139: if a derivation record is present, it must agree
     * with the executable body, the compiler identity and the IR text. */
    if (!derivation_all_zero(m->derivation.body_hash)) {
        uint8_t want[32];
        if (axb_mod_body_hash_accounted(&m->body, want, account) != 0
                || memcmp(want, m->derivation.body_hash, 32) != 0) {
            goto done;
        }
    }
    if (!derivation_all_zero(m->derivation.compiler_hash)) {
        uint8_t want[32];
        axb_compiler_hash(want);
        if (memcmp(want, m->derivation.compiler_hash, 32) != 0) {
            goto done;
        }
    }
    if (!derivation_all_zero(m->derivation.ir_hash)) {
        uint8_t want[32];
        axi_sha256(body_text, body_len, want);
        if (memcmp(want, m->derivation.ir_hash, 32) != 0) {
            goto done;
        }
    }
    if (!derivation_all_zero(m->derivation.src_hash)) {
        if (memcmp(m->derivation.src_hash, m->body.src_hash, 32) != 0) {
            goto done;
        }
    }
    rc = 0;
done:
    (void)contract_free_owned(account, closure);
    (void)contract_free_owned(account, body_text);
    return rc;
}

int axb_contract_v1_verify_accounted(const axb_contract_mod *m,
                                     axi_mem_account *account)
{
    axi_diags *diags;
    int rc;
    if (!account) return axb_contract_v1_verify(m);
    diags = axi_mem_alloc(account, sizeof *diags);
    if (!diags) return 1;
    rc = contract_v1_verify_with_diags(m, account, diags);
    if (!contract_free_owned(account, diags)) return 1;
    return rc;
}

int axb_contract_v1_verify(const axb_contract_mod *m)
{
    axi_diags diags;
    return contract_v1_verify_with_diags(m, NULL, &diags);
}

int axb_contract_v1_parse(const char *src, size_t len, axb_contract_mod *out)
{
    return axb_contract_v1_parse_accounted(src, len, out, NULL);
}

int axb_contract_v1_parse_accounted(const char *src, size_t len,
                                    axb_contract_mod *out, axi_mem_account *account)
{
    axb_contract_mod tmp;
    cbuf body = {0};
    lines it;
    slice line, contract;
    uint32_t ncontracts = 0;
    int in_cell = 0;
    size_t i;
    axi_diags diags;
    if (!out) return 1;
    memset(out, 0, sizeof *out);
    memset(&tmp, 0, sizeof tmp);
    if (!src || len == 0 || len > CONTRACT_MODULE_MAX || memchr(src, 0, len))
        return 1;
    if (account && !axi_mem_reserve(account, sizeof tmp + sizeof diags)) return 1;
    tmp.body.builder_account = account;
    body.account = account;
    axi_arena_init_accounted(&tmp.arena, CONTRACT_MODULE_MAX, account);
    it.src = src; it.len = len; it.off = 0;
    while (line_next(&it, &line)) {
        if (prefix(line, "cell ")) {
            axb_manifest *v;
            if (in_cell) goto bad;
            if (ncontracts >= 256) goto bad;
            in_cell = 1;
            cb_raw(&body, line.p, line.n); cb_ch(&body, '\n');
            if (!line_next(&it, &contract) || !seq(contract, "  contract 1"))
                goto bad;
            v = account ? axi_mem_realloc(account, tmp.manifest,
                            (ncontracts + 1) * sizeof *tmp.manifest)
                        : axi_realloc(tmp.manifest,
                            (ncontracts + 1) * sizeof *tmp.manifest);
            if (!v) goto bad;
            tmp.manifest = v;
            if (parse_contract(&it, &tmp.manifest[ncontracts], &tmp.arena) != 0)
                goto bad;
            ncontracts++;
            continue;
        }
        if (prefix(line, "  contract") || seq(line, "  endcontract")) goto bad;
        if (seq(line, "end")) in_cell = 0;
        cb_raw(&body, line.p, line.n); cb_ch(&body, '\n');
    }
    if (in_cell || body.failed || ncontracts == 0) goto bad;
    if (axb_asm_text_accounted(body.p, body.n, "<contract-v1>", &tmp.body, account) != 0)
        goto bad;
    /* INV-387 / AXI-INV-126: src_hash names the exact contract AXS, not the
     * temporary legacy projection with its contract blocks removed. */
    axi_sha256(src, len, tmp.body.src_hash);
    /* AXI-CA17 / AXI-INV-139: canonical derivation record, no path or timestamp.
     * src_hash binds the original source, ir_hash binds the AXS IR body, the
     * compiler hash identifies the canonical compiler string, and body_hash is
     * the executable AXB body root. */
    axi_sha256(src, len, tmp.derivation.src_hash);
    axb_compiler_hash(tmp.derivation.compiler_hash);
    /* INV-476 / AXI-INV-145: a failed derivation hash must fail the build,
     * never publish an artifact whose provenance silently dropped out. */
    if (axb_mod_body_hash_accounted(&tmp.body, tmp.derivation.body_hash, account) != 0)
        goto bad;
    {
        char *ir_text = axb_mod_dis_text_bounded_accounted(&tmp.body, CONTRACT_MODULE_MAX,
                                                 &i, account);
        if (!ir_text) goto bad;
        axi_sha256(ir_text, i, tmp.derivation.ir_hash);
        (void)contract_free_owned(account, ir_text);
    }
    if (tmp.body.n != ncontracts) goto bad;
    axi_diags_init(&diags);
    if (axb_mod_verify(&tmp.body, "<contract-v1>", &diags) != 0) goto bad;
    tmp.nmanifest = ncontracts;
    for (i = 0; i < ncontracts; i++) {
        if (axi_manifest_iface_hash_v1_accounted(tmp.body.cells[i].name,
                                       &tmp.manifest[i],
                                       tmp.manifest[i].iface_hash, account) != 0
                || axb_cell_body_hash_v1_accounted(&tmp.body.cells[i],
                                         tmp.manifest[i].body_hash, account) != 0
                || axb_manifest_v1_verify(&tmp.manifest[i]) != 0)
            goto bad;
    }
    if (axb_contract_v1_verify_accounted(&tmp, account) != 0) goto bad;
    (void)contract_free_owned(account, body.p);
    *out = tmp;
    (void)contract_release_owned(account, sizeof tmp + sizeof diags);
    return 0;
bad:
    (void)contract_free_owned(account, body.p);
    axb_contract_mod_free(&tmp);
    (void)contract_release_owned(account, sizeof tmp + sizeof diags);
    return 1;
}

static const char *type_name(uint8_t tag)
{
    static const char *const names[] = {
        NULL, "u64", "i64", "f64", "bool", "str", "bytes", "json",
        "decision", "ok"
    };
    return tag < sizeof names / sizeof names[0] ? names[tag] : NULL;
}

static void render_mstr(cbuf *b, axb_mstr s) { cb_raw(b, s.p, s.len); }

static void render_type(cbuf *b, const axb_mtype *t)
{
    const char *name = type_name(t->tag);
    if (name) cb_str(b, name);
    else if (t->tag == AXB_MT_CAP) {
        cb_str(b, "cap ");
        render_mstr(b, t->name);
    } else b->failed = 1;
}

static void render_contract(cbuf *b, const axb_manifest *m)
{
    uint32_t i;
    cb_str(b, "  contract 1\n");
    for (i = 0; i < m->nparams; i++) {
        cb_str(b, "    param "); render_mstr(b, m->params[i].name); cb_ch(b, ' ');
        render_type(b, &m->params[i].type); cb_ch(b, '\n');
    }
    for (i = 0; i < m->nreturns; i++) {
        cb_str(b, "    ret "); render_type(b, &m->returns[i]); cb_ch(b, '\n');
    }
    for (i = 0; i < m->nerrors; i++) {
        cb_str(b, "    err "); render_mstr(b, m->errors[i]); cb_ch(b, '\n');
    }
    for (i = 0; i < m->ncaps; i++) {
        cb_str(b, "    cap "); render_mstr(b, m->caps[i]); cb_ch(b, '\n');
    }
    {
        char fuel[32];
        axi_canon_int_json(m->fuel_max, fuel, sizeof fuel);
        cb_str(b, "    fuel "); cb_str(b, fuel); cb_ch(b, '\n');
    }
    if (m->flags & AXB_MANIFEST_FLAG_PURE) cb_str(b, "    pure\n");
    if (m->flags & AXB_MANIFEST_FLAG_POLICY) cb_str(b, "    policy\n");
    for (i = 0; i < m->nlaws; i++) {
        cb_str(b, "    law "); render_mstr(b, m->laws[i]); cb_ch(b, '\n');
    }
    cb_str(b, "  endcontract\n");
}

char *axb_contract_v1_render(const axb_contract_mod *m, size_t *out_len)
{
    return axb_contract_v1_render_accounted(m, out_len, NULL);
}

char *axb_contract_v1_render_accounted(const axb_contract_mod *m, size_t *out_len,
                                       axi_mem_account *account)
{
    cbuf out = {0};
    char *body;
    size_t body_len, off = 0;
    uint32_t cell = 0;
    if (out_len) *out_len = 0;
    out.max = CONTRACT_MODULE_MAX;
    out.account = account;
    if (axb_contract_v1_verify_accounted(m, account) != 0) return NULL;
    body = axb_mod_dis_text_bounded_accounted(&m->body, CONTRACT_MODULE_MAX, &body_len, account);
    if (!body) return NULL;
    cell = 0;
    while (off < body_len) {
        size_t start = off;
        while (off < body_len && body[off] != '\n') off++;
        cb_raw(&out, body + start, off - start);
        cb_ch(&out, '\n');
        if (off < body_len) off++;
        if (off - start >= 5 && memcmp(body + start, "cell ", 5) == 0) {
            if (cell >= m->nmanifest) { out.failed = 1; break; }
            render_contract(&out, &m->manifest[cell++]);
        }
    }
    (void)contract_free_owned(account, body);
    if (out.failed || out.n > CONTRACT_MODULE_MAX || cell != m->nmanifest) {
        (void)contract_free_owned(account, out.p);
        return NULL;
    }
    if (out_len) *out_len = out.n;
    return out.p;
}

char *axi_codegen_contract_v1(const axi_node *unit, size_t *out_len)
{
    axb_contract_mod model;
    char *legacy = NULL, *rendered = NULL;
    size_t legacy_len = 0, ir_len = 0;
    uint32_t i;
    axi_diags diags;
    axi_mem_account storage, *account = NULL;
    if (out_len) *out_len = 0;
    memset(&model, 0, sizeof model);
    if (!unit || !unit->contract_checked) return NULL;
    if (unit->budget) {
        axi_compile_account_init(&storage, unit->budget);
        account = &storage;
        if (!axi_mem_reserve(account, sizeof model + sizeof diags)) return NULL;
    }
    model.body.builder_account = account;
    legacy = axi_codegen(unit, &legacy_len);
    if (!legacy || axb_asm_text_accounted(legacy, legacy_len, "<codegen-contract-v1>",
                                &model.body, account) != 0) goto done;
    if (model.body.n == 0) goto done;
    (void)axi_compile_free(unit->budget, legacy);
    legacy = NULL;
    axi_diags_init(&diags);
    if (axb_mod_verify(&model.body, "<codegen-contract-v1>", &diags) != 0)
        goto done;
    model.manifest = account ? axi_mem_calloc(account, model.body.n, sizeof *model.manifest)
                             : axi_calloc(model.body.n, sizeof *model.manifest);
    if (!model.manifest) goto done;
    model.nmanifest = model.body.n;
    /* AXI-CA17: the synthetic builder path has no .axi source; provenance is
     * intentionally incomplete (src_hash stays zero). The IR is the canonical
     * disassembly of the assembled module, the compiler is the canonical
     * compiler string, and the body hash is the executable AXB body root. */
    memset(model.body.src_hash, 0, sizeof model.body.src_hash);
    memset(model.derivation.src_hash, 0, sizeof model.derivation.src_hash);
    {
        char *ir_text = axb_mod_dis_text_bounded_accounted(&model.body,
                                                 CONTRACT_MODULE_MAX, &ir_len, account);
        if (!ir_text) goto done;
        axi_sha256(ir_text, ir_len, model.derivation.ir_hash);
        (void)contract_free_owned(account, ir_text);
    }
    axb_compiler_hash(model.derivation.compiler_hash);
    if (axb_mod_body_hash_accounted(&model.body, model.derivation.body_hash, account) != 0)
        goto done;
    axi_arena_init_accounted(&model.arena, CONTRACT_MODULE_MAX, account);
    if (axi_iface_manifests_v1(unit, &model.body, model.manifest,
                               &model.arena) != 0) goto done;
    for (i = 0; i < model.body.n; i++) {
        const axb_cell *cell = &model.body.cells[i];
        if (axb_cell_body_hash_v1_accounted(cell,
                                         model.manifest[i].body_hash, account) != 0)
            goto done;
    }
    rendered = axb_contract_v1_render_accounted(&model, out_len, account);
    if (rendered && account) {
        size_t size = strlen(rendered) + 1;
        char *owned = axi_compile_malloc(unit->budget, size);
        if (owned) memcpy(owned, rendered, size);
        (void)contract_free_owned(account, rendered);
        rendered = owned;
        if (!rendered && out_len) *out_len = 0;
    }
done:
    (void)axi_compile_free(unit->budget, legacy);
    axb_contract_mod_free(&model);
    (void)contract_release_owned(account, sizeof model + sizeof diags);
    return rendered;
}

static void snapshot_restore_account_failure(
    axi_mem_account *account, axi_mem_failure_cause failure,
    size_t failed_request)
{
    if (account && failure != AXI_MEM_FAILURE_NONE
            && account->failure == AXI_MEM_FAILURE_NONE) {
        account->failure = failure;
        account->failed_request = failed_request;
    }
}

int axb_contract_v7_load_trusted_snapshot_accounted(
    axb_contract_mod *out, uint8_t **snapshot, size_t *snapshot_len,
    const char *path, const uint8_t trusted_pk[32],
    axi_mem_account *account)
{
    axb_contract_mod model;
    FILE *f = NULL;
    uint8_t *bytes = NULL;
    long size;
    axi_mem_failure_cause failure;
    size_t failed_request;
    int model_reserved = 0, rc = 1;
    if (!out || !snapshot || !snapshot_len || !path || !*path || !trusted_pk)
        return 1;
    memset(&model, 0, sizeof model);
    if (account) {
        if (!axi_mem_reserve(account, sizeof model)) return 1;
        model_reserved = 1;
    }
    f = fopen(path, "rb");
    if (!f || fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0
            || (size_t)size < AXBS_TRAILER + 8
            || (size_t)size > AXB_CONTRACT_MAX_BYTES + AXBS_TRAILER
            || fseek(f, 0, SEEK_SET) != 0) goto done;
    bytes = account ? axi_mem_alloc(account, (size_t)size)
                    : axi_malloc((size_t)size);
    if (!bytes || fread(bytes, 1, (size_t)size, f) != (size_t)size
            || fgetc(f) != EOF || ferror(f)) goto done;
    if (fclose(f) != 0) { f = NULL; goto done; }
    f = NULL;
    if (axb_contract_v7_decode_trusted_accounted(
            &model, bytes, (size_t)size, trusted_pk, account) != 0) goto done;
    *out = model;
    *snapshot = bytes;
    *snapshot_len = (size_t)size;
    bytes = NULL;
    memset(&model, 0, sizeof model);
    rc = 0;
done:
    failure = account ? account->failure : AXI_MEM_FAILURE_NONE;
    failed_request = account ? account->failed_request : 0;
    if (f) (void)fclose(f);
    if (bytes) {
        if (account) (void)axi_mem_free(account, bytes);
        else free(bytes);
    }
    axb_contract_mod_free(&model);
    snapshot_restore_account_failure(account, failure, failed_request);
    if (model_reserved
            && !contract_release_owned(account, sizeof model)) return 1;
    return rc;
}

int axb_contract_v7_load_trusted_snapshot(
    axb_contract_mod *out, uint8_t **snapshot, size_t *snapshot_len,
    const char *path, const uint8_t trusted_pk[32])
{
    return axb_contract_v7_load_trusted_snapshot_accounted(
        out, snapshot, snapshot_len, path, trusted_pk, NULL);
}

static char *contract_source_read(const char *path, size_t *out_len)
{
    FILE *f = NULL;
    char *src = NULL;
    long size;
    int close_rc;
    if (!path || !*path || !out_len) return NULL;
    *out_len = 0;
    f = fopen(path, "rb");
    if (!f || fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) <= 0
            || (size_t)size > AXB_CONTRACT_MAX_BYTES
            || fseek(f, 0, SEEK_SET) != 0) goto done;
    src = axi_malloc((size_t)size + 1);
    if (!src || fread(src, 1, (size_t)size, f) != (size_t)size
            || fgetc(f) != EOF || ferror(f)) {
        free(src);
        src = NULL;
        goto done;
    }
    close_rc = fclose(f);
    f = NULL;
    if (close_rc != 0) { free(src); return NULL; }
    src[size] = '\0';
    *out_len = (size_t)size;
done:
    if (f) (void)fclose(f);
    return src;
}

int axb_contract_v1_write_signed_text(const char *src, size_t len,
                                      const char *source_path,
                                      const char *out_path,
                                      const char *signing_key_path)
{
    return axb_contract_v1_write_signed_text_accounted(src, len, source_path,
        out_path, signing_key_path, NULL);
}

int axb_contract_v1_write_signed_text_accounted(const char *src, size_t len,
    const char *source_path, const char *out_path, const char *signing_key_path,
    axi_mem_account *account)
{
    axb_contract_mod model;
    uint8_t seed[32];
    int rc = 1;
    if (account && !axi_mem_reserve(account, sizeof model + sizeof seed)) return 1;
    memset(&model, 0, sizeof model);
    memset(seed, 0, sizeof seed);
    if (!src || !len || !source_path || !out_path || !signing_key_path
            || axb_contract_v1_parse_accounted(src, len, &model, account) != 0) {
        fprintf(AXI_ERR, "AXI-B025 %s: exact contract-bearing AXS required\n",
                source_path ? source_path : "<missing>");
        goto done;
    }
    if (axi_signing_seed_load(signing_key_path, seed) != 0) {
        fprintf(AXI_ERR, "AXI-N001 %s: signing key must be one explicit "
                "32-byte raw seed\n", signing_key_path);
        goto done;
    }
    rc = axb_contract_v7_write_signed_accounted(&model, seed, out_path, account);
    if (rc != 0)
        fprintf(AXI_ERR, "AXI-N004 %s: signed AXB v7 publication failed\n",
                out_path);
done:
    axi_private_wipe(seed, sizeof seed);
    axb_contract_mod_free(&model);
    (void)contract_release_owned(account, sizeof model + sizeof seed);
    return rc;
}

int cmd_asm_contract_signed(const char *in, const char *out_path,
                             const char *signing_key_path)
{
    size_t len = 0;
    char *src = contract_source_read(in, &len);
    int rc;
    if (!src) {
        fprintf(AXI_ERR, "AXI-B025 cannot read bounded contract AXS: %s\n", in);
        return 2;
    }
    rc = axb_contract_v1_write_signed_text(src, len, in, out_path,
                                           signing_key_path);
    free(src);
    return rc;
}

int cmd_migrate_contract_v5(const char *legacy_path, const char *source_path,
                            const char *out_path,
                            const char *signing_key_path)
{
    axb_contract_mod current;
    axb_mod legacy;
    axi_arena arena;
    uint8_t legacy_hash[32], current_hash[32], header[8];
    char *source = NULL;
    size_t source_len = 0;
    FILE *file = NULL;
    uint32_t version;
    int rc = 1;
    memset(&current, 0, sizeof current);
    memset(&legacy, 0, sizeof legacy);
    axi_arena_init(&arena, AXB_CONTRACT_MAX_BYTES);
    if (!legacy_path || !source_path || !out_path || !signing_key_path
            || strcmp(out_path, legacy_path) == 0
            || strcmp(out_path, source_path) == 0
            || strcmp(out_path, signing_key_path) == 0) {
        fprintf(AXI_ERR, "AXI-C002 migration requires a distinct output path\n");
        goto done;
    }
    file = fopen(legacy_path, "rb");
    if (!file) {
        fprintf(AXI_ERR, "AXI-B012 %s: cannot read AXB header\n", legacy_path);
        goto done;
    }
    if (fread(header, 1, sizeof header, file) != sizeof header) {
        (void)fclose(file);
        file = NULL;
        fprintf(AXI_ERR, "AXI-B012 %s: truncated AXB header\n", legacy_path);
        goto done;
    }
    if (fclose(file) != 0) {
        file = NULL;
        fprintf(AXI_ERR, "AXI-B012 %s: cannot close AXB input\n", legacy_path);
        goto done;
    }
    file = NULL;
    if (memcmp(header, AXB_MAGIC, 4) != 0) {
        fprintf(AXI_ERR, "AXI-B010 %s: not an AXB module\n", legacy_path);
        goto done;
    }
    version = (uint32_t)header[4]
            | (uint32_t)header[5] << 8
            | (uint32_t)header[6] << 16
            | (uint32_t)header[7] << 24;
    if (version != AXB_ARCHIVE_VERSION) {
        fprintf(AXI_ERR, "AXI-B011 %s: offline migration supports exact AXB v5, got v%u\n",
                legacy_path, version);
        goto done;
    }
    source = contract_source_read(source_path, &source_len);
    if (!source || axb_contract_v1_parse(source, source_len, &current) != 0
            || axb_mod_load(&legacy, legacy_path, &arena) != 0
            || axb_mod_semantic_hash_v1(&legacy, legacy_hash) != 0
            || axb_mod_semantic_hash_v1(&current.body, current_hash) != 0)
        goto done;
    if (memcmp(legacy_hash, current_hash, sizeof legacy_hash) != 0) {
        fprintf(AXI_ERR, "AXI-B016 %s: enriched contract source changes executable semantics\n",
                source_path);
        goto done;
    }
    rc = axb_contract_v1_write_signed_text(source, source_len, source_path,
                                            out_path, signing_key_path);
    if (rc == 0)
        printf("migrated AXB v5 -> v7: %s -> %s\n", legacy_path, out_path);
done:
    if (file) (void)fclose(file);
    free(source);
    axb_contract_mod_free(&current);
    axi_arena_free(&arena);
    return rc;
}

/* INV-480 / AXI-INV-148: AXPC never trusts a producer-stated proposition.
 * Static admission rederives every identity; proof-required admission also
 * reexecutes the complete law set under the frozen empty-authority envelope. */
static int seal_law_shape_valid(const axb_manifest *manifest)
{
    return manifest->nparams == 0 && manifest->nreturns == 1
        && manifest->returns[0].tag == AXB_MT_BOOL && manifest->ncaps == 0
        && manifest->flags == AXB_MANIFEST_FLAG_PURE;
}

/* The subject-root encoder already verifies the immutable complete model.
 * Re-running that verifier for every law is redundant. Execute through the
 * existing private, pure preverified door and retain caller memory accounting. */
static int seal_run_verified_law(const axb_contract_mod *model, uint32_t cell,
                                  axi_vval *value, uint64_t budget,
                                  uint64_t *used, axi_mem_account *account)
{
    if (account)
        return axi_vm_run_contract_cell_preverified_accounted_diag(
            model, cell, NULL, 0, value, budget, used, NULL, NULL, account);
    return axi_vm_run_contract_cell_preverified_pure_diag(
        model, cell, NULL, 0, value, budget, used, NULL, NULL);
}

int axb_contract_seal_verify_accounted(const axb_contract_mod *m, int execute,
                                        axi_mem_account *account)
{
    const axb_seal_certificate *cert;
    uint8_t want[32];
    uint64_t aggregate_budget = 0, aggregate_fuel = 0;
    uint32_t i, law_index = 0;
    if (!m || !m->seal.present) return 1;
    cert = &m->seal;
    if (cert->version != AXPC_VERSION
            || cert->maturity != AXPC_MATURITY_CHECKED
            || cert->law_count == 0 || cert->law_count > AXPC_MAX_LAWS)
        return 1;
    axb_checker_protocol_id(want);
    if (memcmp(want, cert->checker_protocol_id, 32) != 0) return 1;
    axb_checker_semantics_root(want);
    if (memcmp(want, cert->checker_semantics_root, 32) != 0) return 1;
    if (axb_contract_seal_subject_root_accounted(m, want, account) != 0
            || memcmp(want, cert->subject_root, 32) != 0) return 1;
    for (i = 0; i < m->body.n; i++) {
        const axb_cell *cell = &m->body.cells[i];
        const axb_manifest *manifest = &m->manifest[i];
        const axb_seal_law *law;
        uint64_t budget;
        size_t name_len;
        if (strncmp(cell->name, "law_", 4) != 0) continue;
        if (law_index >= cert->law_count) return 1;
        law = &cert->laws[law_index++];
        name_len = strlen(cell->name);
        budget = manifest->fuel_max;
        if (budget > AXPC_MAX_AGGREGATE_FUEL)
            budget = AXPC_MAX_AGGREGATE_FUEL;
        if (!seal_law_shape_valid(manifest)
                || law->cell_index != i || law->name.len != name_len
                || !law->name.p
                || memcmp(law->name.p, cell->name, name_len) != 0
                || memcmp(law->iface_hash, manifest->iface_hash, 32) != 0
                || memcmp(law->body_hash, manifest->body_hash, 32) != 0
                || law->budget != budget || law->fuel_used > law->budget
                || law->result_kind != AXPC_RESULT_BOOL
                || law->verdict != AXPC_VERDICT_TRUE)
            return 1;
        if (aggregate_budget > AXPC_MAX_AGGREGATE_FUEL - budget
                || aggregate_fuel > AXPC_MAX_AGGREGATE_FUEL - law->fuel_used)
            return 1;
        aggregate_budget += budget;
        aggregate_fuel += law->fuel_used;
        if (execute) {
            axi_vval value;
            uint64_t used = 0;
            memset(&value, 0, sizeof value);
            if (seal_run_verified_law(m, i, &value, budget, &used, account) != 1
                    || value.kind != VB_BOOL || value.bits != 1
                    || used != law->fuel_used)
                return 1;
        }
    }
    return law_index == cert->law_count
        && aggregate_budget == cert->aggregate_budget
        && aggregate_fuel == cert->aggregate_fuel_used ? 0 : 1;
}

int axb_contract_seal_verify(const axb_contract_mod *m, int execute)
{
    return axb_contract_seal_verify_accounted(m, execute, NULL);
}

int cmd_seal_contract_signed(const char *in, const char *out_path,
                             const char *signing_key_path)
{
    axb_contract_mod model;
    axi_vval value;
    uint8_t seed[32];
    uint64_t fuel, budget;
    size_t len = 0;
    char *src = contract_source_read(in, &len);
    uint8_t *body = NULL;
    size_t body_len = 0;
    uint8_t module_root[32];
    char subject_hex[65], module_hex[65];
    uint32_t i, nlaws = 0;
    int rc = 1;
    memset(&model, 0, sizeof model);
    memset(seed, 0, sizeof seed);
    if (!src || axb_contract_v1_parse(src, len, &model) != 0) {
        fprintf(AXI_ERR, "AXI-B025 %s: exact contract-bearing AXS required\n",
                in ? in : "<missing>");
        goto done;
    }
    model.seal.present = 1;
    model.seal.version = AXPC_VERSION;
    model.seal.maturity = AXPC_MATURITY_CHECKED;
    axb_checker_protocol_id(model.seal.checker_protocol_id);
    axb_checker_semantics_root(model.seal.checker_semantics_root);
    for (i = 0; i < model.body.n; i++) {
        axb_seal_law *law;
        const axb_manifest *manifest;
        if (strncmp(model.body.cells[i].name, "law_", 4) != 0) continue;
        if (nlaws >= AXPC_MAX_LAWS) goto done;
        manifest = &model.manifest[i];
        if (!seal_law_shape_valid(manifest)) {
            fprintf(AXI_ERR, "AXI-S002 %s: law `%s` requires a pure, "
                    "CAP-free, zero-argument boolean contract\n",
                    in, model.body.cells[i].name);
            goto done;
        }
        budget = manifest->fuel_max;
        if (budget > AXPC_MAX_AGGREGATE_FUEL)
            budget = AXPC_MAX_AGGREGATE_FUEL;
        if (model.seal.aggregate_budget > AXPC_MAX_AGGREGATE_FUEL - budget) {
            fprintf(AXI_ERR, "AXI-S004 %s: aggregate law budget exceeds %llu | "
                    "fix: split the checked artifact or lower declared law fuel\n",
                    in, (unsigned long long)AXPC_MAX_AGGREGATE_FUEL);
            goto done;
        }
        law = &model.seal.laws[nlaws];
        law->cell_index = i;
        law->name.p = model.body.cells[i].name;
        law->name.len = (uint32_t)strlen(model.body.cells[i].name);
        memcpy(law->iface_hash, manifest->iface_hash, 32);
        memcpy(law->body_hash, manifest->body_hash, 32);
        law->budget = budget;
        law->result_kind = AXPC_RESULT_BOOL;
        law->verdict = AXPC_VERDICT_TRUE;
        nlaws++;
        memset(&value, 0, sizeof value);
        fuel = 0;
        /* INV-476 / AXI-INV-145: activation cannot erase the diagnostic that
         * explains why a law trapped. */
        /* Parsing above verified this model, including transitive caps. */
        if (seal_run_verified_law(&model, i, &value, budget, &fuel, NULL) != 1) {
            fprintf(AXI_ERR, "AXI-S002 %s: law `%s` is not green (trapped) | "
                    "fix: a law runs to bool true on budget; the cell does not "
                    "seal until it does\n", in, model.body.cells[i].name);
            goto done;
        }
        if (value.kind != VB_BOOL || value.bits != 1) {
            fprintf(AXI_ERR, "AXI-S002 %s: law `%s` is not green (did not "
                    "judge true) | fix: a law runs to bool true on budget; "
                    "the cell does not seal until it does\n",
                    in, model.body.cells[i].name);
            goto done;
        }
        law->fuel_used = fuel;
        model.seal.aggregate_budget += budget;
        model.seal.aggregate_fuel_used += fuel;
    }
    if (nlaws == 0) {
        fprintf(AXI_ERR, "AXI-S001 %s: no `law_*` cells | fix: a seal attests "
                "laws; state at least one, or use `axi asm` for unsealed "
                "bytecode\n", in);
        goto done;
    }
    model.seal.law_count = nlaws;
    if (axb_contract_seal_subject_root(&model, model.seal.subject_root) != 0
            || axb_contract_seal_verify(&model, 0) != 0) {
        fprintf(AXI_ERR, "AXI-S005 %s: checked-seal certificate binding failed\n",
                in);
        goto done;
    }
    if (axi_signing_seed_load(signing_key_path, seed) != 0) {
        fprintf(AXI_ERR, "AXI-N001 %s: signing key must be one explicit "
                "32-byte raw seed\n", signing_key_path);
        goto done;
    }
    if (axb_contract_v7_encode(&model, &body, &body_len) != 0) goto done;
    axi_sha256(body, body_len, module_root);
    free(body);
    body = NULL;
    rc = axb_contract_v7_write_signed(&model, seed, out_path);
    if (rc == 0) {
        axi_hash_hex(model.seal.subject_root, subject_hex);
        axi_hash_hex(module_root, module_hex);
        printf("checked: %u law%s subject %s module %s\n", nlaws,
               nlaws == 1 ? "" : "s", subject_hex, module_hex);
    }
done:
    free(body);
    axi_private_wipe(seed, sizeof seed);
    axb_contract_mod_free(&model);
    free(src);
    return rc;
}

static int cli_load_trusted(axb_contract_mod *model, const char *path,
                            const char *trusted_key_path)
{
    uint8_t trusted_pk[32];
    if (axi_trusted_pk_load(trusted_key_path, trusted_pk) != 0) {
        fprintf(AXI_ERR, "AXI-N001 %s: trusted key must be one explicit "
                "32-byte raw public key\n", trusted_key_path ? trusted_key_path
                                                               : "<missing>");
        return 1;
    }
    if (axb_contract_v7_load_trusted(model, path, trusted_pk) != 0) {
        fprintf(AXI_ERR, "AXI-B025 %s: signed AXB v7 is not admitted by the "
                "selected trusted key\n", path ? path : "<missing>");
        memset(trusted_pk, 0, sizeof trusted_pk);
        return 1;
    }
    memset(trusted_pk, 0, sizeof trusted_pk);
    return 0;
}

int cmd_dis_contract_trusted(const char *path, const char *trusted_key_path)
{
    axb_contract_mod model;
    char *text;
    size_t len = 0;
    int rc = 1;
    memset(&model, 0, sizeof model);
    if (cli_load_trusted(&model, path, trusted_key_path) != 0) return 1;
    text = axb_contract_v1_render(&model, &len);
    if (text && fwrite(text, 1, len, AXI_OUT) == len) rc = 0;
    else fprintf(AXI_ERR, "AXI-B025 %s: contract disassembly failed\n", path);
    free(text);
    axb_contract_mod_free(&model);
    return rc;
}

int cmd_inspect_contract_trusted(const char *path,
                                 const char *trusted_key_path)
{
    axb_contract_mod model;
    cbuf out = {0};
    char hex[65], number[32];
    uint32_t i;
    int rc = 1;
    memset(&model, 0, sizeof model);
    if (cli_load_trusted(&model, path, trusted_key_path) != 0) return 1;
    out.max = CONTRACT_MODULE_MAX;
    cb_str(&out, "format 7\ncontract 1\ntrusted ");
    axi_hash_hex(model.body.sig_pk, hex); cb_str(&out, hex);
    cb_str(&out, "\nroot "); axi_hash_hex(model.body.root, hex); cb_str(&out, hex);
    cb_str(&out, "\nseal ");
    cb_str(&out, model.seal.present ? "CHECKED" : "UNCHECKED");
    if (model.seal.present) {
        cb_str(&out, "\nsubject ");
        axi_hash_hex(model.seal.subject_root, hex); cb_str(&out, hex);
        cb_str(&out, "\nchecker-protocol ");
        axi_hash_hex(model.seal.checker_protocol_id, hex); cb_str(&out, hex);
        cb_str(&out, "\nchecker-semantics ");
        axi_hash_hex(model.seal.checker_semantics_root, hex); cb_str(&out, hex);
        cb_str(&out, "\nseal-budget ");
        axi_canon_int_json(model.seal.aggregate_budget, number, sizeof number);
        cb_str(&out, number);
        cb_str(&out, "\nseal-fuel-used ");
        axi_canon_int_json(model.seal.aggregate_fuel_used, number, sizeof number);
        cb_str(&out, number);
        cb_str(&out, "\nseal-laws ");
        axi_canon_int_json(model.seal.law_count, number, sizeof number);
        cb_str(&out, number); cb_ch(&out, '\n');
        for (i = 0; i < model.seal.law_count; i++) {
            const axb_seal_law *law = &model.seal.laws[i];
            cb_str(&out, "law ");
            axi_canon_int_json(law->cell_index, number, sizeof number);
            cb_str(&out, number); cb_ch(&out, ' '); cb_str(&out, law->name.p);
            cb_str(&out, "\n  iface ");
            axi_hash_hex(law->iface_hash, hex); cb_str(&out, hex);
            cb_str(&out, "\n  body ");
            axi_hash_hex(law->body_hash, hex); cb_str(&out, hex);
            cb_str(&out, "\n  budget ");
            axi_canon_int_json(law->budget, number, sizeof number);
            cb_str(&out, number);
            cb_str(&out, "\n  fuel-used ");
            axi_canon_int_json(law->fuel_used, number, sizeof number);
            cb_str(&out, number);
            cb_str(&out, "\n  result BOOL TRUE\n");
        }
    }
    cb_str(&out, model.seal.present ? "cells " : "\ncells ");
    axi_canon_int_json(model.body.n, number, sizeof number); cb_str(&out, number);
    cb_ch(&out, '\n');
    for (i = 0; i < model.body.n; i++) {
        cb_str(&out, "cell ");
        axi_canon_int_json(i, number, sizeof number); cb_str(&out, number);
        cb_ch(&out, ' '); cb_str(&out, model.body.cells[i].name); cb_ch(&out, '\n');
        cb_str(&out, "  iface ");
        axi_hash_hex(model.manifest[i].iface_hash, hex); cb_str(&out, hex);
        cb_str(&out, "\n  body ");
        axi_hash_hex(model.manifest[i].body_hash, hex); cb_str(&out, hex);
        cb_str(&out, "\n  fuel ");
        axi_canon_int_json(model.manifest[i].fuel_max, number, sizeof number);
        cb_str(&out, number); cb_ch(&out, '\n');
    }
    if (!out.failed && fwrite(out.p, 1, out.n, AXI_OUT) == out.n) rc = 0;
    else fprintf(AXI_ERR, "AXI-B025 %s: contract inspection failed\n", path);
    free(out.p);
    axb_contract_mod_free(&model);
    return rc;
}

int cmd_verify_contract_trusted(const char *path,
                                const char *trusted_key_path)
{
    axb_contract_mod model;
    char hex[65];
    memset(&model, 0, sizeof model);
    if (cli_load_trusted(&model, path, trusted_key_path) != 0) return 1;
    axi_hash_hex(model.body.sig_pk, hex);
    printf("signature-valid %s by %s\n", path, hex);
    axb_contract_mod_free(&model);
    return 0;
}

int cmd_check_seal_contract_trusted(const char *path,
                                    const char *trusted_key_path)
{
    axb_contract_mod model;
    char subject[65], root[65];
    memset(&model, 0, sizeof model);
    if (cli_load_trusted(&model, path, trusted_key_path) != 0) return 1;
    if (axb_contract_seal_verify(&model, 1) != 0) {
        axb_contract_mod_free(&model);
        return 1;
    }
    axi_hash_hex(model.seal.subject_root, subject);
    axi_hash_hex(model.body.root, root);
    printf("checked %s subject %s module %s\n", path, subject, root);
    axb_contract_mod_free(&model);
    return 0;
}

int cmd_bind_contract_trusted(const char *path, const char *source_path,
                              const char *trusted_key_path)
{
    axb_contract_mod model;
    uint8_t source_hash[32];
    char hex[65];
    char *src;
    size_t len = 0;
    int rc = 1;
    memset(&model, 0, sizeof model);
    if (cli_load_trusted(&model, path, trusted_key_path) != 0) return 1;
    src = contract_source_read(source_path, &len);
    if (!src || memchr(src, 0, len)) {
        fprintf(AXI_ERR, "AXI-B017 %s: source must be bounded text\n",
                source_path ? source_path : "<missing>");
        goto done;
    }
    axi_sha256(src, len, source_hash);
    if (memcmp(source_hash, model.body.src_hash, sizeof source_hash) != 0) {
        fprintf(AXI_ERR, "AXI-B016 %s: src_hash does not match %s\n",
                path, source_path);
        goto done;
    }
    axi_hash_hex(source_hash, hex);
    printf("%s  %s -> %s\n", hex, source_path, path);
    rc = 0;
done:
    free(src);
    axb_contract_mod_free(&model);
    return rc;
}
