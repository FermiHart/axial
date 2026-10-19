/* axial — interface projection (W15). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * Order is identity. Everything that is semantically a SET is sorted
 * (cells, error atoms, caps, laws, return atoms); the one thing that is
 * a SEQUENCE — the parameter list — keeps source order, because calls
 * are positional. Sorting a set costs nothing and buys a stable hash:
 * moving a `cap` line in the source must not invent a new contract.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "axi_alloc.h"
#include "axi_arena.h"
#include "axi_iface.h"
#include "axi_hash.h"
#include "axi_cap_table.h"
#include "axi_osif.h"   /* AXI-INV-064: one door for the streams */

/* ---- tiny string builder (local: canon's is static by design) --------- */

typedef struct {
    char  *p;
    size_t n, cap;
    int failed;
    axi_mem_account *account;
} sb;

static int iface_free_owned(axi_mem_account *account, void *ptr)
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

static void sb_overflow(sb *b)
{
    if (b->account)
        (void)axi_mem_realloc(b->account, b->p, (size_t)-1);
    b->failed = 1;
}

static void sb_grow(sb *b, size_t need)
{
    size_t cap;
    char *p;
    if (b->failed) return;
    if (b->n == (size_t)-1 || need > (size_t)-1 - b->n - 1) {
        sb_overflow(b);
        return;
    }
    if (b->n + need + 1 <= b->cap) return;
    cap = b->cap ? b->cap : 512;
    while (b->n + need + 1 > cap) {
        if (cap > (size_t)-1 / 2) { sb_overflow(b); return; }
        cap *= 2;
    }
    p = b->account ? (char *)axi_mem_realloc(b->account, b->p, cap)
                   : (char *)axi_realloc(b->p, cap);
    if (!p) { b->failed = 1; return; }
    b->p = p;
    b->cap = cap;
}

static void sb_put(sb *b, const char *s, size_t len)
{
    sb_grow(b, len);
    if (b->failed) return;
    memcpy(b->p + b->n, s, len);
    b->n += len;
    b->p[b->n] = '\0';
}

static void sb_str(sb *b, const char *s) { sb_put(b, s, strlen(s)); }
static void sb_ch(sb *b, char c)         { sb_put(b, &c, 1); }

/* AXI-INV-025: this file owns NO digit loop. It once did, and it disagreed
 * with the canonical form on `10_000` vs `10000` — while feeding the text
 * that gets HASHED. The tool was signing text its own G1 law would reject.
 * Both spellings are minted in axi_canon.c; here we only ask. */
static void sb_canon_u64(sb *b, uint64_t v)   /* text face: G1, may carry `_` */
{
    char t[32];
    axi_canon_int_str(v, t, sizeof t);
    sb_str(b, t);
}

static void sb_json_u64(sb *b, uint64_t v)    /* machine face: plain digits */
{
    char t[32];
    axi_canon_int_json(v, t, sizeof t);
    sb_str(b, t);
}

/* JSON string escape — the projection must survive being a value. */
static void sb_jstr(sb *b, const char *s)
{
    sb_ch(b, '"');
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"':  sb_str(b, "\\\""); break;
        case '\\': sb_str(b, "\\\\"); break;
        case '\n': sb_str(b, "\\n");  break;
        case '\t': sb_str(b, "\\t");  break;
        case '\r': sb_str(b, "\\r");  break;
        default:
            if (c < 0x20) {
                char esc[7];
                snprintf(esc, sizeof esc, "\\u%04x", c);
                sb_str(b, esc);
            } else {
                sb_ch(b, (char)c);
            }
        }
    }
    sb_ch(b, '"');
}

/* ---- model ------------------------------------------------------------ */

typedef struct {
    char *name;
    char *type;
} ifc_param;

typedef struct {
    char      *name;
    ifc_param *params; size_t nparams;
    char     **rets;   size_t nrets;   /* sorted: a union is a set */
    char     **errs;   size_t nerrs;   /* sorted */
    char     **caps;   size_t ncaps;   /* sorted */
    uint64_t   fuel;   int     has_fuel;
    int        pure, policy;
    char     **laws;   size_t nlaws;   /* sorted, canonical text */
    char       hash[65];
    uint8_t    hash_bytes[32];
    axi_mem_account *account;
} ifc_cell;

typedef struct {
    ifc_cell *cells;
    size_t    n;
} ifc;

static void free_strv(axi_mem_account *account, char **v, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) (void)iface_free_owned(account, v[i]);
    (void)iface_free_owned(account, v);
}

static void ifc_cell_free(ifc_cell *c)
{
    size_t j;
    if (!c) return;
    (void)iface_free_owned(c->account, c->name);
    for (j = 0; j < c->nparams; j++) {
        (void)iface_free_owned(c->account, c->params[j].name);
        (void)iface_free_owned(c->account, c->params[j].type);
    }
    (void)iface_free_owned(c->account, c->params);
    free_strv(c->account, c->rets, c->nrets);
    free_strv(c->account, c->errs, c->nerrs);
    free_strv(c->account, c->caps, c->ncaps);
    free_strv(c->account, c->laws, c->nlaws);
    memset(c, 0, sizeof *c);
}

/* INV-309 / AXI-INV-096: a projection owns every string and vector it
 * derives. The returned rendering is independent and does not retain them. */
static void ifc_free(ifc *f)
{
    size_t i;
    if (!f) return;
    for (i = 0; i < f->n; i++) ifc_cell_free(&f->cells[i]);
    free(f->cells);
    f->cells = NULL;
    f->n = 0;
}

static char *dupn_accounted(const char *s, size_t n,
                            axi_mem_account *account)
{
    char *d;
    if (n == (size_t)-1) {
        if (account) (void)axi_mem_alloc(account, (size_t)-1);
        return NULL;
    }
    d = account ? (char *)axi_mem_alloc(account, n + 1)
                : (char *)axi_malloc(n + 1);
    if (!d) return NULL;
    memcpy(d, s, n);
    d[n] = '\0';
    return d;
}

static char *dupn(const char *s, size_t n)
{
    return dupn_accounted(s, n, NULL);
}

static char *lex_of(const axi_node *n)
{
    if (!n || !n->lex) return dupn("?", 1);
    return dupn(n->lex, n->lexlen);
}

static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static int cmp_cell(const void *a, const void *b)
{
    return strcmp(((const ifc_cell *)a)->name, ((const ifc_cell *)b)->name);
}

static int push_str_accounted(char ***v, size_t *n, char *s,
                              axi_mem_account *account)
{
    char **nv;
    if (!s) return 0;
    if (*n == (size_t)-1 || *n + 1 > (size_t)-1 / sizeof **v) {
        if (account) (void)axi_mem_realloc(account, *v, (size_t)-1);
        (void)iface_free_owned(account, s);
        return 0;
    }
    nv = account
        ? (char **)axi_mem_realloc(account, *v, (*n + 1) * sizeof **v)
        : (char **)axi_realloc(*v, (*n + 1) * sizeof **v);
    if (!nv) { (void)iface_free_owned(account, s); return 0; }
    *v = nv;
    (*v)[(*n)++] = s;
    return 1;
}

static int push_str(char ***v, size_t *n, char *s)
{
    return push_str_accounted(v, n, s, NULL);
}

static int push_unique_str(char ***v, size_t *n, char *s)
{
    size_t i;
    if (!s) return 0;
    for (i = 0; i < *n; i++)
        if (strcmp((*v)[i], s) == 0) { free(s); return 1; }
    return push_str(v, n, s);
}

static char *type_text(const axi_node *t)
{
    char *s;
    if (!t || !t->lex) return dupn("?", 1);
    if (t->ival != 1) return dupn(t->lex, t->lexlen);
    s = axi_malloc((size_t)t->lexlen + 5);
    if (!s) return NULL;
    memcpy(s, "cap ", 4);
    memcpy(s + 4, t->lex, t->lexlen);
    s[t->lexlen + 4] = '\0';
    return s;
}

/* Render one cell block into `b`; the per-cell hash is taken over exactly
 * these bytes, so a cell's identity does not depend on its neighbours. */
static void render_cell_block(sb *b, const ifc_cell *c)
{
    size_t i;
    sb_str(b, "cell ");   sb_str(b, c->name); sb_ch(b, '\n');
    for (i = 0; i < c->nparams; i++) {
        sb_str(b, "param "); sb_str(b, c->params[i].name);
        sb_ch(b, ' ');       sb_str(b, c->params[i].type); sb_ch(b, '\n');
    }
    for (i = 0; i < c->nrets; i++) { sb_str(b, "ret ");  sb_str(b, c->rets[i]); sb_ch(b, '\n'); }
    for (i = 0; i < c->nerrs; i++) { sb_str(b, "err ");  sb_str(b, c->errs[i]); sb_ch(b, '\n'); }
    for (i = 0; i < c->ncaps; i++) { sb_str(b, "cap ");  sb_str(b, c->caps[i]); sb_ch(b, '\n'); }
    if (c->has_fuel) { sb_str(b, "fuel "); sb_canon_u64(b, c->fuel); sb_ch(b, '\n'); }
    if (c->pure)     { sb_str(b, "pure\n"); }
    for (i = 0; i < c->nlaws; i++) { sb_str(b, "law ");  sb_str(b, c->laws[i]); sb_ch(b, '\n'); }
    sb_str(b, "end\n");
}

static void hash_text(const char *s, char out[65])
{
    uint8_t h[32];
    axi_sha256(s, strlen(s), h);
    axi_hash_hex(h, out);
}

/* ---- projection ------------------------------------------------------- */

static int project_cell(const axi_node *cell, ifc_cell *o)
{
    const axi_node *sig = cell->a, *k, *m;
    sb cb = {0};

    memset(o, 0, sizeof *o);
    o->name = lex_of(cell);
    if (!o->name) return 1;
    o->policy = cell->kind == N_POLICY;

    if (sig) {
        for (k = sig->list; k; k = k->next) {
            char *ty = type_text(k->a);
            ifc_param *params = (ifc_param *)axi_realloc(
                o->params, (o->nparams + 1) * sizeof *o->params);
            if (!params) { free(ty); goto bad; }
            o->params = params;
            memset(&o->params[o->nparams], 0, sizeof *o->params);
            o->params[o->nparams].name = lex_of(k);
            o->params[o->nparams].type = ty;
            o->nparams++;
            if (!o->params[o->nparams - 1].name || !ty) goto bad;
            /* G4: caps live in signatures only — the cap SET is therefore
             * fully known here, without looking at one line of body. */
            if (k->a && k->a->ival == 1
                    && !push_unique_str(&o->caps, &o->ncaps, lex_of(k->a))) goto bad;
        }
        if (sig->b) {
            for (k = sig->b->list; k; k = k->next) {
                switch (k->kind) {
                case N_OKT:
                    if (!push_str(&o->rets, &o->nrets, dupn("ok", 2))) goto bad;
                    break;
                case N_ERRT:
                    if (!push_str(&o->errs, &o->nerrs, lex_of(k))) goto bad;
                    break;
                default:
                    if (!push_str(&o->rets, &o->nrets, type_text(k))) goto bad;
                    break;
                }
            }
        }
    }

    for (m = cell->list; m; m = m->next) {
        if (m->kind == N_FUEL) { o->fuel = m->ival; o->has_fuel = 1; }
        if (m->kind == N_PURE) o->pure = 1;
    }
    for (int kind = 1; kind < CAP__COUNT; kind++) {
        size_t i;
        int present = 0;
        if (!(cell->inferred_caps_mask & (UINT32_C(1) << kind))) continue;
        for (i = 0; i < o->ncaps; i++)
            if (strcmp(o->caps[i], axi_cap_name((axi_cap_kind)kind)) == 0)
                present = 1;
        if (!present)
            if (!push_str(&o->caps, &o->ncaps,
                          dupn(axi_cap_name((axi_cap_kind)kind),
                               strlen(axi_cap_name((axi_cap_kind)kind)))))
                goto bad;
    }

    /* Laws are the semantic half of the contract: dropping one promises
     * strictly less, so the diff has to see them. */
    if (cell->c) {
        for (m = cell->c->list; m; m = m->next)
            if (m->a && !push_str(&o->laws, &o->nlaws,
                                   axi_canon_expr_str_fallible(m->a))) goto bad;
    }

    if (o->nrets > 1) qsort(o->rets, o->nrets, sizeof *o->rets, cmp_str);
    if (o->nerrs > 1) qsort(o->errs, o->nerrs, sizeof *o->errs, cmp_str);
    if (o->ncaps > 1) qsort(o->caps, o->ncaps, sizeof *o->caps, cmp_str);
    if (o->nlaws > 1) qsort(o->laws, o->nlaws, sizeof *o->laws, cmp_str);

    sb_grow(&cb, 1);
    render_cell_block(&cb, o);
    if (cb.failed) goto bad;
    axi_sha256(cb.p, cb.n, o->hash_bytes);
    axi_hash_hex(o->hash_bytes, o->hash);
    free(cb.p);
    return 0;
bad:
    free(cb.p);
    return 1;
}

static int project(const axi_node *unit, ifc *out)
{
    const axi_node *c;
    size_t i = 0, n = 0;

    memset(out, 0, sizeof *out);
    for (c = unit->list; c; c = c->next)
        if (c->kind == N_CELL || c->kind == N_POLICY) n++;
    out->cells = n ? (ifc_cell *)axi_calloc(n, sizeof *out->cells) : NULL;
    if (n && !out->cells) return 1;
    out->n = n;
    for (c = unit->list; c; c = c->next)
        if (c->kind == N_CELL || c->kind == N_POLICY)
            if (project_cell(c, &out->cells[i++]) != 0) {
                ifc_free(out);
                return 1;
            }
    if (n > 1) qsort(out->cells, n, sizeof *out->cells, cmp_cell);
    return 0;
}

char *axi_iface_render(const axi_node *unit)
{
    ifc f;
    sb b = {0};
    size_t i;
    char uh[65];

    if (project(unit, &f) != 0) goto oom;
    sb_grow(&b, 1);
    sb_str(&b, "axi-iface 1\n");
    for (i = 0; i < f.n; i++) render_cell_block(&b, &f.cells[i]);
    if (b.failed) goto oom;
    hash_text(b.p, uh);
    sb_str(&b, "iface-hash ");
    sb_str(&b, uh);
    sb_ch(&b, '\n');
    /* INV-383 / AXI-INV-123: the final hash append is part of publication. */
    if (b.failed) goto oom;
    ifc_free(&f);
    return b.p;
oom:
    fprintf(AXI_ERR, "AXI-D999 iface: out of memory\n");
    ifc_free(&f);
    free(b.p);
    return NULL;
}

char *axi_iface_json(const axi_node *unit)
{
    ifc f;
    sb b = {0}, body = {0};
    size_t i, j;
    char uh[65];

    if (project(unit, &f) != 0) goto oom;
    /* the hash in JSON is the hash of the TEXT projection: one contract,
     * one identity, regardless of which face you asked for */
    sb_grow(&body, 1);
    sb_str(&body, "axi-iface 1\n");
    for (i = 0; i < f.n; i++) render_cell_block(&body, &f.cells[i]);
    if (body.failed) goto oom;
    hash_text(body.p, uh);
    free(body.p);
    body.p = NULL;

    sb_grow(&b, 1);
    sb_str(&b, "{\"iface\":1,\"hash\":");
    sb_jstr(&b, uh);
    sb_str(&b, ",\"cells\":[");
    for (i = 0; i < f.n; i++) {
        const ifc_cell *c = &f.cells[i];
        if (i) sb_ch(&b, ',');
        sb_str(&b, "{\"name\":"); sb_jstr(&b, c->name);
        sb_str(&b, ",\"params\":[");
        for (j = 0; j < c->nparams; j++) {
            if (j) sb_ch(&b, ',');
            sb_str(&b, "{\"name\":"); sb_jstr(&b, c->params[j].name);
            sb_str(&b, ",\"type\":");  sb_jstr(&b, c->params[j].type);
            sb_ch(&b, '}');
        }
        sb_str(&b, "],\"ret\":[");
        for (j = 0; j < c->nrets; j++) { if (j) sb_ch(&b, ','); sb_jstr(&b, c->rets[j]); }
        sb_str(&b, "],\"err\":[");
        for (j = 0; j < c->nerrs; j++) { if (j) sb_ch(&b, ','); sb_jstr(&b, c->errs[j]); }
        sb_str(&b, "],\"cap\":[");
        for (j = 0; j < c->ncaps; j++) { if (j) sb_ch(&b, ','); sb_jstr(&b, c->caps[j]); }
        sb_str(&b, "],\"fuel\":");
        if (c->has_fuel) sb_json_u64(&b, c->fuel); else sb_str(&b, "null");
        sb_str(&b, ",\"pure\":");
        sb_str(&b, c->pure ? "true" : "false");
        sb_str(&b, ",\"laws\":[");
        for (j = 0; j < c->nlaws; j++) { if (j) sb_ch(&b, ','); sb_jstr(&b, c->laws[j]); }
        sb_str(&b, "],\"hash\":");
        sb_jstr(&b, c->hash);
        sb_ch(&b, '}');
    }
    sb_str(&b, "]}\n");
    if (b.failed) goto oom;
    ifc_free(&f);
    return b.p;
oom:
    fprintf(AXI_ERR, "AXI-D999 iface: out of memory\n");
    ifc_free(&f);
    free(body.p);
    free(b.p);
    return NULL;
}

/* ---- diff ------------------------------------------------------------- */

/* A change is BREAKING when an existing caller that compiled against the
 * old contract could now fail: more authority demanded, more errors to
 * handle, a bigger bill to pay, a law withdrawn. It is COMPATIBLE when the
 * new contract promises MORE with LESS. Direction is the whole point:
 * diff(old,new) and diff(new,old) are different questions. */
typedef struct {
    int   breaking;          /* 0 = compatible note, 1 = breaking */
    char *cell;
    char *what;
} chg;

typedef struct {
    chg   *v;
    size_t n;
} chgs;

static void chgs_free(chgs *cs)
{
    size_t i;
    for (i = 0; i < cs->n; i++) {
        free(cs->v[i].cell);
        free(cs->v[i].what);
    }
    free(cs->v);
    cs->v = NULL;
    cs->n = 0;
}

/* `what` is always a caller-built string: no non-literal format ever
 * reaches printf here (a format string built from source text is how
 * tools grow a format-string bug). */
static void chg_add(chgs *cs, int breaking, const char *cell, const char *what)
{
    chg *v = (chg *)axi_realloc(cs->v, (cs->n + 1) * sizeof *cs->v);
    if (!v) { fprintf(AXI_ERR, "AXI-D999 iface: out of memory\n"); exit(2); }
    cs->v = v;
    cs->v[cs->n].breaking = breaking;
    cs->v[cs->n].cell = dupn(cell, strlen(cell));
    cs->v[cs->n].what = dupn(what, strlen(what));
    cs->n++;
}

static int has_str(char **v, size_t n, const char *s)
{
    size_t i;
    for (i = 0; i < n; i++) if (!strcmp(v[i], s)) return 1;
    return 0;
}

static const ifc_cell *find_cell(const ifc *f, const char *name)
{
    size_t i;
    for (i = 0; i < f->n; i++) if (!strcmp(f->cells[i].name, name)) return &f->cells[i];
    return NULL;
}

static const ifc_cell *find_cell_n(const ifc *f, const char *name, size_t len)
{
    size_t i;
    if (!name) return NULL;
    for (i = 0; i < f->n; i++)
        if (strlen(f->cells[i].name) == len
                && memcmp(f->cells[i].name, name, len) == 0)
            return &f->cells[i];
    return NULL;
}

static int manifest_str(axi_arena *arena, const char *s, uint32_t max,
                        axb_mstr *out)
{
    size_t n;
    char *copy;
    if (!s) return 0;
    n = strlen(s);
    if (n == 0 || n > max) return 0;
    copy = axi_arena_alloc(arena, n + 1);
    if (!copy) return 0;
    memcpy(copy, s, n + 1);
    out->p = copy;
    out->len = (uint32_t)n;
    return 1;
}

static int manifest_type(axi_arena *arena, const char *s, int parameter,
                         axb_mtype *out)
{
    static const struct { const char *name; uint8_t tag; } atoms[] = {
        {"u64", AXB_MT_U64}, {"i64", AXB_MT_I64}, {"f64", AXB_MT_F64},
        {"bool", AXB_MT_BOOL}, {"str", AXB_MT_STR}, {"bytes", AXB_MT_BYTES},
        {"json", AXB_MT_JSON}, {"decision", AXB_MT_DECISION},
        {"ok", AXB_MT_OK}
    };
    size_t i;
    memset(out, 0, sizeof *out);
    for (i = 0; i < sizeof atoms / sizeof atoms[0]; i++)
        if (strcmp(s, atoms[i].name) == 0) {
            if (parameter && atoms[i].tag == AXB_MT_OK) return 0;
            out->tag = atoms[i].tag;
            return 1;
        }
    if (parameter && strncmp(s, "cap ", 4) == 0) {
        out->tag = AXB_MT_CAP;
        return manifest_str(arena, s + 4, AXB_MANIFEST_MAX_NAME, &out->name);
    }
    return 0;
}

static char *manifest_type_text_accounted(const axb_mtype *t,
                                           axi_mem_account *account)
{
    static const char *const atoms[] = {
        NULL, "u64", "i64", "f64", "bool", "str", "bytes", "json",
        "decision", "ok"
    };
    char *s;
    if (!t) return NULL;
    if (t->tag > 0 && t->tag < sizeof atoms / sizeof atoms[0])
        return dupn_accounted(atoms[t->tag], strlen(atoms[t->tag]), account);
    if (t->tag != AXB_MT_CAP || !t->name.p) return NULL;
    s = account ? axi_mem_alloc(account, (size_t)t->name.len + 5u)
                : axi_malloc((size_t)t->name.len + 5u);
    if (!s) return NULL;
    memcpy(s, "cap ", 4);
    memcpy(s + 4, t->name.p, t->name.len);
    s[t->name.len + 4] = '\0';
    return s;
}

int axi_manifest_iface_hash_v1_accounted(const char *cell_name,
                                         const axb_manifest *manifest,
                                         uint8_t out[32],
                                         axi_mem_account *account)
{
    ifc_cell c;
    sb b = {0};
    uint8_t hash[32];
    size_t i;
    if (!out) return 1;
    memset(&c, 0, sizeof c);
    if (!cell_name || !manifest || axb_manifest_v1_verify(manifest) != 0)
        return 1;
    c.account = account;
    b.account = account;
    c.name = dupn_accounted(cell_name, strlen(cell_name), account);
    if (!c.name) goto bad;
    c.params = manifest->nparams
        ? (account
            ? axi_mem_calloc(account, manifest->nparams, sizeof *c.params)
            : axi_calloc(manifest->nparams, sizeof *c.params))
        : NULL;
    if (manifest->nparams && !c.params) goto bad;
    c.nparams = manifest->nparams;
    for (i = 0; i < c.nparams; i++) {
        c.params[i].name = dupn_accounted(manifest->params[i].name.p,
                                          manifest->params[i].name.len,
                                          account);
        c.params[i].type = manifest_type_text_accounted(
            &manifest->params[i].type, account);
        if (!c.params[i].name || !c.params[i].type) goto bad;
    }
    for (i = 0; i < manifest->nreturns; i++)
        if (!push_str_accounted(&c.rets, &c.nrets,
                manifest_type_text_accounted(&manifest->returns[i], account),
                account)) goto bad;
    for (i = 0; i < manifest->nerrors; i++)
        if (!push_str_accounted(&c.errs, &c.nerrs,
                dupn_accounted(manifest->errors[i].p,
                               manifest->errors[i].len, account), account))
            goto bad;
    for (i = 0; i < manifest->ncaps; i++)
        if (!push_str_accounted(&c.caps, &c.ncaps,
                dupn_accounted(manifest->caps[i].p,
                               manifest->caps[i].len, account), account))
            goto bad;
    for (i = 0; i < manifest->nlaws; i++)
        if (!push_str_accounted(&c.laws, &c.nlaws,
                dupn_accounted(manifest->laws[i].p,
                               manifest->laws[i].len, account), account))
            goto bad;
    if (c.nrets > 1) qsort(c.rets, c.nrets, sizeof *c.rets, cmp_str);
    c.fuel = manifest->fuel_max;
    c.has_fuel = 1;
    c.pure = !!(manifest->flags & AXB_MANIFEST_FLAG_PURE);
    c.policy = !!(manifest->flags & AXB_MANIFEST_FLAG_POLICY);
    sb_grow(&b, 1);
    render_cell_block(&b, &c);
    if (b.failed) goto bad;
    axi_sha256(b.p, b.n, hash);
    if (!iface_free_owned(account, b.p)) goto bad_cell;
    b.p = NULL;
    ifc_cell_free(&c);
    memcpy(out, hash, sizeof hash);
    return 0;
bad_cell:
    b.p = NULL;
bad:
    (void)iface_free_owned(account, b.p);
    ifc_cell_free(&c);
    return 1;
}

int axi_manifest_iface_hash_v1(const char *cell_name,
                               const axb_manifest *manifest,
                               uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    return axi_manifest_iface_hash_v1_accounted(
        cell_name, manifest, out, NULL);
}

/* INV-382 / AXI-INV-122: one source projection feeds both the legacy iface
 * identity and manifest facts. body_hash is deliberately not a source fact. */
int axi_iface_manifest_v1(const axi_node *unit,
                          const char *cell_name, size_t cell_name_len,
                          axb_manifest *out, struct axi_arena *arena)
{
    ifc model;
    const ifc_cell *cell;
    axb_manifest m;
    size_t i, j;
    if (!out) return 1;
    memset(out, 0, sizeof *out);
    if (!unit || !unit->contract_checked || !arena) return 1;
    if (project(unit, &model) != 0) return 1;
    cell = find_cell_n(&model, cell_name, cell_name_len);
    if (!cell || !cell->has_fuel
            || cell->nparams > AXB_MANIFEST_MAX_PARAMS
            || cell->nrets > AXB_MANIFEST_MAX_RETURNS
            || cell->nerrs > AXB_MANIFEST_MAX_ERRORS
            || cell->ncaps > AXB_MANIFEST_MAX_CAPS
            || cell->nlaws > AXB_MANIFEST_MAX_LAWS) {
        ifc_free(&model);
        return 1;
    }
    memset(&m, 0, sizeof m);
    m.version = AXB_MANIFEST_VERSION;
    m.flags = (cell->pure ? AXB_MANIFEST_FLAG_PURE : 0u)
            | (cell->policy ? AXB_MANIFEST_FLAG_POLICY : 0u);
    m.fuel_max = cell->fuel;
    m.nparams = (uint32_t)cell->nparams;
    for (i = 0; i < cell->nparams; i++)
        if (!manifest_str(arena, cell->params[i].name,
                          AXB_MANIFEST_MAX_NAME, &m.params[i].name)
                || !manifest_type(arena, cell->params[i].type, 1,
                                  &m.params[i].type))
            goto bad;
    m.nreturns = (uint32_t)cell->nrets;
    for (i = 0; i < cell->nrets; i++)
        if (!manifest_type(arena, cell->rets[i], 0, &m.returns[i])) goto bad;
    for (i = 1; i < m.nreturns; i++) {
        axb_mtype atom = m.returns[i];
        for (j = i; j > 0 && m.returns[j - 1].tag > atom.tag; j--)
            m.returns[j] = m.returns[j - 1];
        m.returns[j] = atom;
    }
    m.nerrors = (uint32_t)cell->nerrs;
    for (i = 0; i < cell->nerrs; i++)
        if (!manifest_str(arena, cell->errs[i], AXB_MANIFEST_MAX_NAME,
                          &m.errors[i])) goto bad;
    m.ncaps = (uint32_t)cell->ncaps;
    for (i = 0; i < cell->ncaps; i++)
        if (!manifest_str(arena, cell->caps[i], AXB_MANIFEST_MAX_NAME,
                          &m.caps[i])) goto bad;
    m.nlaws = (uint32_t)cell->nlaws;
    for (i = 0; i < cell->nlaws; i++)
        if (!manifest_str(arena, cell->laws[i], AXB_MANIFEST_MAX_LAW,
                          &m.laws[i])) goto bad;
    memcpy(m.iface_hash, cell->hash_bytes, sizeof m.iface_hash);
    if (axb_manifest_v1_verify(&m) != 0) goto bad;
    *out = m;
    ifc_free(&model);
    return 0;
bad:
    ifc_free(&model);
    return 1;
}

static void diff_cell(const ifc_cell *o, const ifc_cell *n, chgs *cs)
{
    char m[600];
    size_t i;

    /* same contract hash = same contract: nothing to say */
    if (!strcmp(o->hash, n->hash)) return;

    if (o->nparams != n->nparams) {
        snprintf(m, sizeof m, "parameter count %lu -> %lu",
                 (unsigned long)o->nparams, (unsigned long)n->nparams);
        chg_add(cs, 1, n->name, m);
    } else {
        for (i = 0; i < o->nparams; i++) {
            if (strcmp(o->params[i].type, n->params[i].type)) {
                snprintf(m, sizeof m, "parameter %lu type %s -> %s",
                         (unsigned long)i, o->params[i].type, n->params[i].type);
                chg_add(cs, 1, n->name, m);
            } else if (strcmp(o->params[i].name, n->params[i].name)) {
                /* AXI-INV-024: the parameter name is IN the interface hash, so
                 * it is part of the contract, so a rename must be BREAKING.
                 * Calling it "compatible" made rename compatible in both
                 * directions between two cells with different hashes, which
                 * L3/L4 refuse.  An agent reads the contract to write the
                 * call; renaming the field it reads breaks that agent even
                 * though the machine ABI is positional. */
                snprintf(m, sizeof m, "parameter %lu renamed %s -> %s",
                         (unsigned long)i, o->params[i].name, n->params[i].name);
                chg_add(cs, 1, n->name, m);
            }
        }
    }

    for (i = 0; i < n->nrets; i++)
        if (!has_str(o->rets, o->nrets, n->rets[i])) {
            snprintf(m, sizeof m, "return atom %s appeared", n->rets[i]);
            chg_add(cs, 1, n->name, m);
        }
    for (i = 0; i < o->nrets; i++)
        if (!has_str(n->rets, n->nrets, o->rets[i])) {
            snprintf(m, sizeof m, "return atom %s vanished", o->rets[i]);
            chg_add(cs, 1, n->name, m);
        }

    for (i = 0; i < n->nerrs; i++)
        if (!has_str(o->errs, o->nerrs, n->errs[i])) {
            snprintf(m, sizeof m, "error err.%s appeared (callers must handle it)",
                     n->errs[i]);
            chg_add(cs, 1, n->name, m);
        }
    for (i = 0; i < o->nerrs; i++)
        if (!has_str(n->errs, n->nerrs, o->errs[i])) {
            snprintf(m, sizeof m, "error err.%s removed (narrowing)", o->errs[i]);
            chg_add(cs, 0, n->name, m);
        }

    for (i = 0; i < n->ncaps; i++)
        if (!has_str(o->caps, o->ncaps, n->caps[i])) {
            snprintf(m, sizeof m,
                     "cap %s demanded (more authority than the old contract)",
                     n->caps[i]);
            chg_add(cs, 1, n->name, m);
        }
    for (i = 0; i < o->ncaps; i++)
        if (!has_str(n->caps, n->ncaps, o->caps[i])) {
            snprintf(m, sizeof m, "cap %s dropped (less authority)", o->caps[i]);
            chg_add(cs, 0, n->name, m);
        }

    if (o->has_fuel && n->has_fuel && o->fuel != n->fuel) {
        snprintf(m, sizeof m, "fuel %llu -> %llu (%s)",
                 (unsigned long long)o->fuel, (unsigned long long)n->fuel,
                 n->fuel > o->fuel ? "a bigger bill than promised" : "cheaper");
        chg_add(cs, n->fuel > o->fuel, n->name, m);
    }

    if (o->pure && !n->pure) chg_add(cs, 1, n->name, "purity lost");
    if (!o->pure && n->pure) chg_add(cs, 0, n->name, "purity gained");

    for (i = 0; i < o->nlaws; i++)
        if (!has_str(n->laws, n->nlaws, o->laws[i])) {
            snprintf(m, sizeof m, "law withdrawn: %s", o->laws[i]);
            chg_add(cs, 1, n->name, m);
        }
    for (i = 0; i < n->nlaws; i++)
        if (!has_str(o->laws, o->nlaws, n->laws[i])) {
            snprintf(m, sizeof m, "law added: %s", n->laws[i]);
            chg_add(cs, 0, n->name, m);
        }
}

int axi_iface_diff(const axi_node *old, const axi_node *nw, FILE *out, int json)
{
    ifc a, b;
    chgs cs = {NULL, 0};
    size_t i;
    int worst = 0; /* 0 identical, 1 compatible, 2 breaking */

    if (project(old, &a) != 0) {
        fprintf(AXI_ERR, "AXI-D999 iface: out of memory\n");
        return 2;
    }
    if (project(nw, &b) != 0) {
        fprintf(AXI_ERR, "AXI-D999 iface: out of memory\n");
        ifc_free(&a);
        return 2;
    }

    for (i = 0; i < a.n; i++)
        if (!find_cell(&b, a.cells[i].name))
            chg_add(&cs, 1, a.cells[i].name, "cell removed");
    for (i = 0; i < b.n; i++) {
        const ifc_cell *o = find_cell(&a, b.cells[i].name);
        if (!o) chg_add(&cs, 0, b.cells[i].name, "cell added");
        else    diff_cell(o, &b.cells[i], &cs);
    }

    for (i = 0; i < cs.n; i++) {
        int lev = cs.v[i].breaking ? 2 : 1;
        if (lev > worst) worst = lev;
    }

    if (json) {
        sb e = {0};
        sb_grow(&e, 1);
        sb_str(&e, "{\"verdict\":\"");
        sb_str(&e, worst == 2 ? "breaking" : worst == 1 ? "compatible" : "identical");
        sb_str(&e, "\",\"changes\":[");
        for (i = 0; i < cs.n; i++) {
            if (i) sb_ch(&e, ',');
            sb_str(&e, "{\"level\":\"");
            sb_str(&e, cs.v[i].breaking ? "breaking" : "compatible");
            sb_str(&e, "\",\"cell\":");
            sb_jstr(&e, cs.v[i].cell);
            sb_str(&e, ",\"what\":");
            sb_jstr(&e, cs.v[i].what);
            sb_ch(&e, '}');
        }
        sb_str(&e, "]}\n");
        if (e.failed) {
            fprintf(AXI_ERR, "AXI-D999 iface: out of memory\n");
            free(e.p);
            worst = 2;
            goto done;
        }
        fputs(e.p, out);
        free(e.p);
    } else {
        for (i = 0; i < cs.n; i++)
            fprintf(out, "%-10s %s: %s\n",
                    cs.v[i].breaking ? "BREAKING" : "compat",
                    cs.v[i].cell, cs.v[i].what);
        fprintf(out, "verdict: %s\n",
                 worst == 2 ? "BREAKING" : worst == 1 ? "COMPATIBLE" : "IDENTICAL");
    }
done:
    chgs_free(&cs);
    ifc_free(&a);
    ifc_free(&b);
    return worst;
}
