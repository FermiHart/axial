#include "axi_builtin_registry.h"
/* axial — type checker (W06). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * Contract (SPEC-GRAMMAR §6):
 *  - Zero coercion. Ever. Mixed operand types are an error with the exact
 *    rewrite in the fix. Implicit conversion is where agent repair loops
 *    go to guess; axial refuses to make them guess.
 *  - opt and result are NOT new syntax: they are rettype unions.
 *      -> u64 | ok       opt   (ok is the unit/none member)
 *      -> u64 | err.Io   result
 *  - A union value must be handled with `?` at the call site, immediately.
 *    `?` re-raises every non-payload member into the caller, so the
 *    caller's rettype must declare each one (fix says exactly what to add).
 *  - err.Name is a first-class atom (the constructor); an error set nobody
 *    can inhabit is decorative.
 *  - W07: the checker is TOTAL. No opaque types — every expression has an
 *    exact type. Cap effects are one-way (return ok); authority is named,
 *    tracked by declaration path (T022), and must be USED (T026).
 *  - unary minus on u64 is refused: u64 has no sign. Ancestral nod to
 *    INV-002 (bear's unsigned-cmp codegen bug) — sign confusion is a
 *    lineage bug in this house, so it dies in the type system.
 */
#include "axi.h"
#include "axi_ast.h"
#include "axi_bc.h"
#include "axi_cap_infer.h"
#include "axi_cap_table.h"
#include "axi_alloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    TY_BAD,   /* already diagnosed — stays silent downstream */
    TY_U64, TY_I64, TY_F64, TY_BOOL, TY_STR, TY_BYTES,
    TY_JSON,  /* policy input surface: represented as str at runtime */
    TY_DECISION, /* policy verdict: bool at runtime, distinct in signatures */
    TY_UNIT,  /* the ok member */
    TY_ERR,   /* err.Name value; name in lex/lexlen */
    TY_CAP,   /* a cap parameter itself */
    TY_UNION  /* unhandled multi-member result; rt = callee rettype list */
} tykind;

typedef struct {
    tykind          k;
    const char     *lex;   /* TY_ERR: error name slice */
    uint32_t        lexlen;
    const axi_node *rt;    /* TY_UNION: rettype N_LIST */
} ty;

static ty mkty(tykind k) { ty t; t.k = k; t.lex = 0; t.lexlen = 0; t.rt = 0; return t; }

static int manifest_dotted_name_ok(const axi_node *n);

static const char *tyname(ty t)
{
    switch (t.k) {
    case TY_U64: return "u64";   case TY_I64: return "i64";
    case TY_F64: return "f64";   case TY_BOOL: return "bool";
    case TY_STR: return "str";   case TY_BYTES: return "bytes";
    case TY_JSON: return "json"; case TY_DECISION: return "decision";
    case TY_UNIT: return "ok";
    case TY_ERR: return "err";   case TY_CAP: return "cap";
    case TY_UNION: return "union";
    default: return "?";
    }
}

/* ---- scope ---------------------------------------------------------------- */

#define ENV_MAX 128

typedef struct {
    const char *lex; uint32_t lexlen;
    ty          t;
    const axi_node *at;   /* declaration site (T026 points here) */
    int             used; /* T026: dead authority detector */
} binding;

typedef struct {
    /* unit-level */
    const axi_node *cells[256];
    axi_cap_set     summaries[256];
    int             ncells;
    axi_diags      *ds;
    const char     *src;
    /* per-cell */
    const axi_node *cell;      /* current cell */
    binding         env[ENV_MAX];
    int             nenv;
    int             is_pure;
    int             in_proof;  /* W12: inside proof{}, laws are closed+pure */
} ck;

static int lex_eq(const char *a, uint32_t al, const char *b, uint32_t bl)
{
    return al == bl && memcmp(a, b, al) == 0;
}

static int lex_is(const axi_node *n, const char *kw)
{
    return n->lex && lex_eq(n->lex, n->lexlen, kw, (uint32_t)strlen(kw));
}

static void tdiag(ck *c, const char *code, const axi_node *n,
                   const char *msg, const char *fix)
{
    if (c->src && n->pos)
        axi_diag_add_source(c->ds, code, c->src,
                            (uint32_t)(n->pos - c->src),
                            n->lexlen ? n->lexlen : 1, msg, fix);
    else
        axi_diag_add(c->ds, code, 0, 0, 0, msg, fix);
}

/* ---- signature shape ------------------------------------------------------ */

static ty type_of_typenode(ck *c, const axi_node *tn)
{
    if (tn->ival == 1) {                              /* cap path (G4) */
        ty t = mkty(TY_CAP);
        t.lex = tn->lex; t.lexlen = tn->lexlen;       /* identity = path (T022) */
        return t;
    }
    if (lex_is(tn, "u64"))   return mkty(TY_U64);
    if (lex_is(tn, "i64"))   return mkty(TY_I64);
    if (lex_is(tn, "f64"))   return mkty(TY_F64);
    if (lex_is(tn, "bool"))  return mkty(TY_BOOL);
    if (lex_is(tn, "str"))   return mkty(TY_STR);
    if (lex_is(tn, "bytes")) return mkty(TY_BYTES);
    if (lex_is(tn, "json"))     return mkty(TY_JSON);
    if (lex_is(tn, "decision")) return mkty(TY_DECISION);
    tdiag(c, "AXI-T004", tn, "named type does not exist in v0",
          "v0 types are the scalars (u64 i64 f64 bool str bytes), json, decision, and cap paths");
    return mkty(TY_BAD);
}

/* rettype list analysis: at most one payload N_TYPE (v0), extras = ok/err */
typedef struct {
    const axi_node *payload;   /* N_TYPE or NULL */
    int             has_ok;
    int             nerr;
    const axi_node *errs[16];
} rshape;

static void rshape_of(ck *c, const axi_node *rt, rshape *rs, int diagnose)
{
    const axi_node *m;
    memset(rs, 0, sizeof *rs);
    for (m = rt->list; m; m = m->next) {
        if (m->kind == N_OKT) {
            if (rs->has_ok && diagnose)
                tdiag(c, "AXI-T006", m, "duplicate member in rettype union",
                      "keep one `ok`");
            rs->has_ok = 1;
        } else if (m->kind == N_ERRT) {
            int i, dup = 0;
            for (i = 0; i < rs->nerr; i++)
                if (lex_eq(rs->errs[i]->lex, rs->errs[i]->lexlen,
                           m->lex, m->lexlen)) dup = 1;
            if (dup && diagnose)
                tdiag(c, "AXI-T006", m, "duplicate member in rettype union",
                      "each err.Name appears once");
            if (rs->nerr < 16) rs->errs[rs->nerr++] = m;
            else if (diagnose)
                tdiag(c, "AXI-T002", m, "error set exceeds 16 atoms",
                      "manifest v1 carries at most 16 distinct errors");
        } else { /* N_TYPE payload */
            if (rs->payload && diagnose)
                tdiag(c, "AXI-T005", m,
                      "rettype union carries more than one payload type in v0",
                      "keep one payload; model alternatives as err members");
            if (!rs->payload) rs->payload = m;
            if (diagnose) {
                /* INV-322 / AXI-INV-104: the runtime carries exactly
                 * u64/i64/f64/bool/str; json travels as str and decision as
                 * bool — the surface type lives in the static rettype. The
                 * checker may not promise a payload with NO representation
                 * (bytes, cap). */
                ty pt = type_of_typenode(c, m); /* validate the name */
                if (pt.k != TY_BAD && pt.k != TY_U64 && pt.k != TY_I64 &&
                    pt.k != TY_F64 && pt.k != TY_BOOL && pt.k != TY_STR &&
                    pt.k != TY_JSON && pt.k != TY_DECISION) {
                    char m2[AXI_DIAG_MSG];
                    snprintf(m2, sizeof m2,
                             "union payload %s has no runtime representation in v0",
                             tyname(pt));
                    tdiag(c, "AXI-T029", m, m2,
                          "v0 unions carry u64, i64, f64, bool, str, json "
                          "(as str) or decision (as bool)");
                }
            }
        }
    }
}

static int rshape_has_err(const rshape *rs, const char *lex, uint32_t len)
{
    int i;
    for (i = 0; i < rs->nerr; i++)
        if (lex_eq(rs->errs[i]->lex, rs->errs[i]->lexlen, lex, len)) return 1;
    return 0;
}

/* ---- unit-level cell table ------------------------------------------------ */

static int find_cell_index(ck *c, const char *lex, uint32_t len)
{
    int i;
    for (i = 0; i < c->ncells; i++)
        if (lex_eq(c->cells[i]->lex, c->cells[i]->lexlen, lex, len))
            return i;
    return -1;
}

static const axi_node *find_cell(ck *c, const char *lex, uint32_t len)
{
    int i = find_cell_index(c, lex, len);
    return i < 0 ? NULL : c->cells[i];
}

static int cell_index(ck *c, const axi_node *cell)
{
    int i;
    for (i = 0; i < c->ncells; i++)
        if (c->cells[i] == cell) return i;
    return -1;
}

static int cell_is_pure(const axi_node *cell)
{
    const axi_node *m;
    for (m = cell->list; m; m = m->next)
        if (m->kind == N_PURE) return 1;
    return 0;
}

/* ---- capability inference -------------------------------------------------- */

static axi_cap_kind cap_kind_of_typenode(const axi_node *t)
{
    if (t && t->kind == N_TYPE && t->ival == 1 && t->lex)
        return axi_cap_kind_by_name(t->lex, t->lexlen);
    return CAP_NONE;
}

static int cell_has_cap_clause(const axi_node *cell)
{
    const axi_node *m;
    for (m = cell->list; m; m = m->next)
        if (m->kind == N_CAP) return 1;
    return 0;
}

static void gather_cap_env(const axi_node *cell, axi_cap_binding *out, int *nout)
{
    const axi_node *param;
    *nout = 0;
    for (param = cell->a->list; param; param = param->next) {
        axi_cap_kind k = cap_kind_of_typenode(param->a);
        if (k == CAP_NONE) continue;
        if (*nout >= AXI_INFERRED_CAP_MAX) continue;
        out[*nout].name = param->lex;
        out[*nout].namelen = param->lexlen;
        out[*nout].kind = k;
        (*nout)++;
    }
}

static void gather_declared_caps(const axi_node *cell, axi_cap_kind *out, const axi_node **sites, int *nout)
{
    const axi_node *m, *id;
    *nout = 0;
    for (m = cell->list; m; m = m->next) {
        if (m->kind != N_CAP) continue;
        for (id = m->list; id; id = id->next) {
            if (id->kind != N_ID || !id->lex) continue;
            if (*nout >= AXI_INFERRED_CAP_MAX) continue;
            out[*nout] = axi_cap_kind_by_name(id->lex, id->lexlen);
            sites[*nout] = id;
            (*nout)++;
        }
    }
}

typedef struct {
    const axi_node *site;
    int callee;
} cap_call;

typedef struct {
    cap_call *calls;
    size_t n, cap;
    size_t first[257];
    int failed;
} cap_graph;

static void collect_cap_calls(ck *c, const axi_node *n, cap_graph *g,
                              unsigned char seen[256])
{
    const axi_node *current;
    for (current = n; current && !g->failed; current = current->next) {
        if (current->kind == N_CALL && current->a
                && current->a->kind == N_ID) {
            int index = find_cell_index(
                c, current->a->lex, current->a->lexlen);
            if (index >= 0 && !seen[index]) {
                if (g->n == g->cap) {
                    size_t cap = g->cap ? g->cap * 2 : 32;
                    cap_call *calls;
                    /* At most 256 distinct callees for each of 256 cells. */
                    if (cap > 256u * 256u) { g->failed = 1; return; }
                    calls = axi_realloc(g->calls, cap * sizeof *calls);
                    if (!calls) { g->failed = 1; return; }
                    g->calls = calls; g->cap = cap;
                }
                g->calls[g->n].site = current;
                g->calls[g->n++].callee = index;
                seen[index] = 1;
            }
        }
        collect_cap_calls(c, current->a, g, seen);
        collect_cap_calls(c, current->b, g, seen);
        collect_cap_calls(c, current->c, g, seen);
        collect_cap_calls(c, current->list, g, seen);
    }
}

static void infer_unit_caps(ck *c)
{
    int i, pass, changed = 1;
    cap_graph graph;
    memset(&graph, 0, sizeof graph);
    for (i = 0; i < c->ncells; i++) {
        axi_cap_binding env[AXI_INFERRED_CAP_MAX];
        axi_cap_infer_result direct;
        unsigned char seen[256] = {0};
        int nenv;
        gather_cap_env(c->cells[i], env, &nenv);
        axi_cap_infer_env ie = { env, nenv };
        axi_cap_infer_init(&direct);
        if (axi_cap_infer(c->cells[i]->b, &ie, c->ds, &direct) == 0)
            c->summaries[i] = direct.caps;
        graph.first[i] = graph.n;
        collect_cap_calls(c, c->cells[i]->b, &graph, seen);
        if (graph.failed) {
            tdiag(c, "AXI-T002", c->cells[i],
                  "cannot build capability call graph under memory pressure",
                  "retry with enough memory to prove every call edge");
            free(graph.calls);
            return;
        }
    }
    graph.first[c->ncells] = graph.n;
    /* Preserve the same monotone fixed-point order and first-use sites,
     * while resolving names and traversing the AST only once per cell. */
    for (pass = 0; pass < c->ncells && changed; pass++) {
        changed = 0;
        for (i = 0; i < c->ncells; i++) {
            axi_cap_set *summary = &c->summaries[i];
            for (size_t e = graph.first[i]; e < graph.first[i + 1]; e++) {
                const cap_call *edge = &graph.calls[e];
                const axi_cap_set *callee = &c->summaries[edge->callee];
                for (int k = 0; k < callee->n; k++) {
                    int before = summary->n;
                    axi_cap_set_add(summary, callee->caps[k], edge->site);
                    if (summary->n != before) changed = 1;
                }
            }
        }
    }
    free(graph.calls);
    for (i = 0; i < c->ncells; i++) {
        uint32_t mask = 0;
        int j;
        for (j = 0; j < c->summaries[i].n; j++)
            mask |= UINT32_C(1) << c->summaries[i].caps[j];
        ((axi_node *)c->cells[i])->inferred_caps_mask = mask;
    }
}

static const axi_cap_set *cell_cap_summary(ck *c, const axi_node *cell)
{
    int index = cell_index(c, cell);
    return index >= 0 ? &c->summaries[index] : NULL;
}

static void check_inferred_caps(ck *c, const axi_node *cell,
                                const axi_cap_infer_result *inf)
{
    axi_cap_kind declared[AXI_INFERRED_CAP_MAX];
    const axi_node *decl_sites[AXI_INFERRED_CAP_MAX];
    int ndeclared = 0, i, j;
    int has_clause = cell_has_cap_clause(cell);
    char msg[AXI_DIAG_MSG], fix[AXI_DIAG_MSG];

    gather_declared_caps(cell, declared, decl_sites, &ndeclared);

    /* inferred caps must be covered by declared caps when a cap clause exists */
    for (i = 0; i < inf->caps.n; i++) {
        axi_cap_kind k = inf->caps.caps[i];
        int covered = !has_clause;
        for (j = 0; j < ndeclared && !covered; j++)
            if (declared[j] == k) covered = 1;
        if (covered) continue;
        snprintf(msg, sizeof msg, "capability '%s' used but not declared",
                 axi_cap_name(k));
        snprintf(fix, sizeof fix, "add `cap %s` or remove the call",
                 axi_cap_name(k));
        tdiag(c, "AXI-T022", inf->caps.sites[i], msg, fix);
    }

    /* declared caps that are never inferred are dead authority */
    for (j = 0; j < ndeclared; j++) {
        if (declared[j] == CAP_NONE) continue;
        int used = 0;
        for (i = 0; i < inf->caps.n && !used; i++)
            if (inf->caps.caps[i] == declared[j]) used = 1;
        if (used) continue;
        snprintf(msg, sizeof msg, "capability '%s' declared but never used",
                 axi_cap_name(declared[j]));
        snprintf(fix, sizeof fix, "unused authority is attack surface: "
                 "drop `cap %s` or use it",
                 axi_cap_name(declared[j]));
        tdiag(c, "AXI-T026", decl_sites[j], msg, fix);
    }
}

/* ---- environment ----------------------------------------------------------- */

static binding *env_find(ck *c, const char *lex, uint32_t len)
{
    int i;
    for (i = 0; i < c->nenv; i++)
        if (lex_eq(c->env[i].lex, c->env[i].lexlen, lex, len))
            return &c->env[i];
    return NULL;
}

static void env_bind(ck *c, const axi_node *at, const char *lex, uint32_t len,
                     ty t)
{
    if (env_find(c, lex, len)) {
        tdiag(c, "AXI-T002", at, "name already declared in this cell",
              "rename it; shadowing hides intent from the repair loop");
        return;
    }
    if (c->nenv >= ENV_MAX) {
        tdiag(c, "AXI-T002", at, "cell exceeds 128 names (v0 honesty cap)",
              "split the cell; small cells seal and attest better");
        return;
    }
    c->env[c->nenv].lex = lex;
    c->env[c->nenv].lexlen = len;
    c->env[c->nenv].t = t;
    c->env[c->nenv].at = at;
    c->env[c->nenv].used = 0;
    c->nenv++;
}

/* ---- expressions ------------------------------------------------------------ */

static ty check_expr(ck *c, const axi_node *n);

static int is_numeric(tykind k)
{
    return k == TY_U64 || k == TY_I64 || k == TY_F64;
}

static int is_scalarty(tykind k)
{
    return is_numeric(k) || k == TY_BOOL || k == TY_STR || k == TY_BYTES ||
           k == TY_DECISION;
}

/* json is a policy input surface type represented as str at runtime.
 * Allow it to meet str expectations and to compare against str literals. */
static int json_str_compat(tykind a, tykind b)
{
    return (a == TY_JSON && b == TY_STR) || (a == TY_STR && b == TY_JSON);
}

/* decision is a semantic alias for bool at runtime, but it carries the
 * policy contract in the signature. Allow bool literals and bool-typed
 * expressions to flow into a decision slot. */
static int decision_compat(tykind a, tykind b)
{
    return (a == TY_DECISION && b == TY_BOOL) ||
           (a == TY_BOOL && b == TY_DECISION);
}

/* a union value escaped without `?` */
static ty union_leak(ck *c, const axi_node *n)
{
    tdiag(c, "AXI-T013", n,
          "this call returns a union (opt/result); it must be handled here",
          "suffix the call with `?` to unwrap and re-raise");
    return mkty(TY_BAD);
}

/* ---- policy builtins (ADR-001 v0 surface) -------------------------------- */

typedef struct {
    const char *name;
    int arity;
    tykind params[3];
    tykind ret;
    int impure;   /* 1 if the builtin is capability-gated */
} bltinfo;

#define TYPE_ROW(name, arity, p0, p1, p2, ret, cap, capstr, impure) \
    { name, arity, { TY_##p0, TY_##p1, TY_##p2 }, TY_##ret, impure },
static const bltinfo BUILTINS[] = {
    AXI_BUILTIN_REGISTRY(TYPE_ROW)
    { NULL, 0, { 0 }, TY_BAD, 0 }
};
#undef TYPE_ROW

static const bltinfo *find_builtin(const char *name, uint32_t len)
{
    for (int i = 0; BUILTINS[i].name; i++) {
        if (strlen(BUILTINS[i].name) == len &&
            memcmp(BUILTINS[i].name, name, len) == 0)
            return &BUILTINS[i];
    }
    return NULL;
}

/* Build a dotted name from a field callee: base.lex + "." + field.lex */
static int builtin_name_of(const axi_node *callee, char *out, size_t cap)
{
    if (callee->kind == N_FIELD && callee->a && callee->a->kind == N_ID &&
        callee->lex && callee->lexlen > 0) {
        uint32_t bl = callee->a->lexlen, fl = callee->lexlen;
        if (bl + 1 + fl >= cap) return 0;
        memcpy(out, callee->a->lex, bl);
        out[bl] = '.';
        memcpy(out + bl + 1, callee->lex, fl);
        out[bl + 1 + fl] = '\0';
        return 1;
    }
    if (callee->kind == N_ID && callee->lex) {
        if ((uint32_t)callee->lexlen >= cap) return 0;
        memcpy(out, callee->lex, callee->lexlen);
        out[callee->lexlen] = '\0';
        return 1;
    }
    return 0;
}

static ty check_builtin_call(ck *c, const axi_node *n, const bltinfo *bi)
{
    const axi_node *arg;
    int i = 0;
    char msg[AXI_DIAG_MSG], fix[AXI_DIAG_MSG];

    if (bi->impure && c->is_pure)
        tdiag(c, "AXI-T019", n, "pure cell calls an impure builtin",
              "drop `pure` or remove the builtin call");

    for (arg = n->list; arg; arg = arg->next) {
        ty at = check_expr(c, arg);
        if (at.k == TY_UNION) { union_leak(c, arg); i++; continue; }
        if (at.k == TY_BAD) { i++; continue; }
        if (i >= bi->arity) {
            snprintf(msg, sizeof msg, "builtin %s takes %d argument(s)",
                     bi->name, bi->arity);
            tdiag(c, "AXI-T011", n, msg, "match the builtin signature");
            break;
        }
        tykind want = bi->params[i];
        if (want == TY_STR && at.k == TY_JSON) {
            /* json is represented as str at runtime; allow the common case */
        } else if (at.k != want) {
            snprintf(msg, sizeof msg, "builtin %s argument %d has type %s",
                     bi->name, i + 1, tyname(at));
            snprintf(fix, sizeof fix, "expected %s", tyname(mkty(want)));
            tdiag(c, "AXI-T012", arg, msg, fix);
        }
        i++;
    }
    if (i < bi->arity) {
        snprintf(msg, sizeof msg, "builtin %s takes %d argument(s), got %d",
                 bi->name, bi->arity, i);
        tdiag(c, "AXI-T011", n, msg, "match the builtin signature");
    }
    return mkty(bi->ret);
}

static ty check_call(ck *c, const axi_node *n)
{
    const axi_node *callee = n->a;

    /* cap method call = an EFFECT: one-way in v0 (W07).
     * Takes fully-typed scalars, returns ok. Data coming back OUT of a cap
     * arrives with W15 interface projection — until then, effects emit, they
     * do not answer. This is what makes the checker total: no opaque values,
     * every expression has an exact type. */
    if (callee->kind == N_FIELD) {
        char bname[80];
        if (builtin_name_of(callee, bname, sizeof bname)) {
            const bltinfo *bi = find_builtin(bname, (uint32_t)strlen(bname));
            if (bi) return check_builtin_call(c, n, bi);
        }
        ty base = check_expr(c, callee->a);
        const axi_node *arg;
        for (arg = n->list; arg; arg = arg->next) {
            ty at = check_expr(c, arg);
            if (at.k == TY_UNION) { union_leak(c, arg); continue; }
            if (at.k == TY_BAD) continue;
            if (!is_scalarty(at.k)) {
                char m[AXI_DIAG_MSG];
                snprintf(m, sizeof m, "effect argument is %s", tyname(at));
                tdiag(c, "AXI-T025", arg, m,
                      "effects take scalars in v0; authority and unions "
                      "do not flow through caps");
            }
        }
        if (base.k == TY_CAP) {
            /* INV-315 / AXI-INV-100: the method must exist in the generated
             * table for THIS capability. A field a cap does not have is a
             * refusal, never a silent no-op in the AXB. */
            axi_cap_kind kind = axi_cap_kind_by_name(base.lex, base.lexlen);
            const axi_cap_method *m = kind == CAP_NONE ? NULL
                : axi_cap_method_find(kind, callee->lex, callee->lexlen);
            int narg = 0;
            for (arg = n->list; arg; arg = arg->next) narg++;
            if (!m) {
                char m2[AXI_DIAG_MSG];
                snprintf(m2, sizeof m2, "cap %.*s has no method `%.*s`",
                         (int)base.lexlen, base.lex,
                         (int)callee->lexlen, callee->lex);
                tdiag(c, "AXI-T027", n, m2,
                      "the closed method table is in docs/CAP-METHODS.tsv; "
                      "effects with compound frames have no method in v0");
                return mkty(TY_BAD);
            }
            if (narg != 1) {
                char m2[AXI_DIAG_MSG];
                snprintf(m2, sizeof m2, "cap method `%.*s` takes 1 argument, got %d",
                         (int)callee->lexlen, callee->lex, narg);
                tdiag(c, "AXI-T027", n, m2,
                      "v0 effect ABI: one scalar str argument per method");
                return mkty(TY_BAD);
            }
            for (arg = n->list; arg; arg = arg->next) {
                ty at = check_expr(c, arg);
                if (at.k == TY_BAD || at.k == TY_UNION) continue;
                if (at.k != TY_STR) {
                    char m2[AXI_DIAG_MSG];
                    snprintf(m2, sizeof m2, "cap method argument is %s, wants str",
                             tyname(at));
                    tdiag(c, "AXI-T027", arg, m2,
                          "v0 effect frames carry one str payload");
                }
            }
            if (c->is_pure)
                tdiag(c, "AXI-T019", n, "pure cell touches a cap",
                      "drop `pure` or drop the cap effect (G4)");
            if (strcmp(m->ret, "str") == 0) return mkty(TY_STR);
            return mkty(TY_U64);
        }
        if (base.k != TY_BAD)
            tdiag(c, "AXI-T021", n,
                  "only plain cell names, builtins and cap paths are callable in v0",
                  "call a cell by name, a builtin, or route the effect through a cap");
        return mkty(TY_BAD);
    }

    if (callee->kind != N_ID) {
        tdiag(c, "AXI-T021", n,
              "only plain cell names, builtins and cap paths are callable in v0",
              "call a cell by name, a builtin, or route the effect through a cap");
        return mkty(TY_BAD);
    }

    {
        const bltinfo *bi = find_builtin(callee->lex, callee->lexlen);
        if (bi) return check_builtin_call(c, n, bi);
    }

    /* a local name shadows nothing: locals are not callable in v0 */
    if (env_find(c, callee->lex, callee->lexlen)) {
        tdiag(c, "AXI-T021", callee,
              "locals are not callable in v0 (cells are not values)",
              "call a declared cell by its name");
        return mkty(TY_BAD);
    }

    {
        const axi_node *target = find_cell(c, callee->lex, callee->lexlen);
        const axi_node *param, *arg;
        rshape rs;
        int nparam = 0, narg = 0, i = 0;
        char msg[AXI_DIAG_MSG], fix[AXI_DIAG_MSG];

        if (!target) {
            tdiag(c, "AXI-T010", callee, "call to unknown cell",
                  "declare the cell in this unit (imports arrive with W14/W15)");
            for (arg = n->list; arg; arg = arg->next) (void)check_expr(c, arg);
            return mkty(TY_BAD);
        }

        if (c->in_proof && !cell_is_pure(target))
            tdiag(c, "AXI-S003", n, "a law calls a non-pure cell",
                  "laws are deterministic facts: mark the callee pure, or "
                  "prove the pure logic and leave effects to the body");
        else if (c->is_pure && !cell_is_pure(target))
            tdiag(c, "AXI-T019", n, "pure cell calls a non-pure cell",
                  "purity is transitive: mark the callee pure or drop yours");

        for (param = target->a->list; param; param = param->next) nparam++;
        for (arg = n->list; arg; arg = arg->next) narg++;
        if (nparam != narg) {
            snprintf(msg, sizeof msg, "wrong arity: expected %d, got %d",
                     nparam, narg);
            tdiag(c, "AXI-T011", n, msg, "match the cell signature exactly");
        }

        param = target->a->list;
        for (arg = n->list; arg && param; arg = arg->next, param = param->next) {
            ty want = type_of_typenode(c, param->a);
            ty got  = check_expr(c, arg);
            i++;
            if (got.k == TY_UNION) { union_leak(c, arg); continue; }
            if (got.k == TY_BAD || want.k == TY_BAD) continue;
            if (want.k == TY_CAP) {
                if (got.k != TY_CAP) {
                    snprintf(msg, sizeof msg,
                             "argument %d must be a cap, got %s", i, tyname(got));
                    tdiag(c, "AXI-T012", arg, msg,
                          "caps only enter through signatures (G4)");
                } else if (!lex_eq(got.lex, got.lexlen, want.lex, want.lexlen)) {
                    snprintf(msg, sizeof msg,
                             "cap identity mismatch: argument %d is cap %.*s",
                             i, (int)got.lexlen, got.lex);
                    snprintf(fix, sizeof fix,
                             "parameter %.*s wants cap %.*s; authority is "
                             "named, never converted (G4)",
                             (int)param->lexlen, param->lex,
                             (int)want.lexlen, want.lex);
                    tdiag(c, "AXI-T022", arg, msg, fix);
                }
                continue;
            }
            if (got.k == TY_CAP) {
                snprintf(msg, sizeof msg,
                         "argument %d passes a cap where %s is expected",
                         i, tyname(want));
                tdiag(c, "AXI-T022", arg, msg,
                      "caps only flow into declared cap parameters (G4)");
                continue;
            }
            if (got.k != want.k && !(want.k == TY_STR && got.k == TY_JSON)) {
                snprintf(msg, sizeof msg, "argument %d has type %s",
                         i, tyname(got));
                snprintf(fix, sizeof fix,
                         "parameter %.*s expects %s; no coercion, rewrite the "
                         "value", (int)param->lexlen, param->lex, tyname(want));
                tdiag(c, "AXI-T012", arg, msg, fix);
            }
        }
        while (arg) { (void)check_expr(c, arg); arg = arg->next; } /* extras */

        rshape_of(c, target->a->b, &rs, 0);
        if (rs.nerr == 0 && !(rs.has_ok && rs.payload)) {
            /* single-member rettype: a plain value */
            if (rs.payload) return type_of_typenode(c, rs.payload);
            return mkty(TY_UNIT);
        }
        { ty u = mkty(TY_UNION); u.rt = target->a->b; return u; }
    }
}

static ty check_try(ck *c, const axi_node *n)
{
    ty inner = check_expr(c, n->a);
    rshape rs, mine;
    char fix[AXI_DIAG_MSG];
    int i;

    if (inner.k == TY_BAD) return inner;
    if (inner.k != TY_UNION) {
        tdiag(c, "AXI-T014", n, "`?` on a value that is not a union",
              "only opt/result values unwrap; drop the `?`");
        return mkty(TY_BAD);
    }

    rshape_of(c, inner.rt, &rs, 0);
    rshape_of(c, c->cell->a->b, &mine, 0);

    for (i = 0; i < rs.nerr; i++) {
        if (!rshape_has_err(&mine, rs.errs[i]->lex, rs.errs[i]->lexlen)) {
            snprintf(fix, sizeof fix, "add `| err.%.*s` to this cell's rettype",
                     (int)rs.errs[i]->lexlen, rs.errs[i]->lex);
            tdiag(c, "AXI-T015", n,
                  "`?` re-raises an error the caller does not declare", fix);
        }
    }
    if (rs.has_ok && rs.payload && !mine.has_ok)
        tdiag(c, "AXI-T015", n,
              "`?` re-raises `ok` (none) and the caller does not declare it",
              "add `| ok` to this cell's rettype");

    if (rs.payload) return type_of_typenode(c, rs.payload);
    return mkty(TY_UNIT);
}

static ty check_bin(ck *c, const axi_node *n)
{
    ty l = check_expr(c, n->a);
    ty r = check_expr(c, n->b);
    int cmp = (n->op == T_LT || n->op == T_LE || n->op == T_GT ||
               n->op == T_GE);
    int eq  = (n->op == T_EQ || n->op == T_NE);
    char msg[AXI_DIAG_MSG], fix[AXI_DIAG_MSG];

    if (l.k == TY_UNION) { union_leak(c, n->a); l = mkty(TY_BAD); }
    if (r.k == TY_UNION) { union_leak(c, n->b); r = mkty(TY_BAD); }
    if (l.k == TY_BAD || r.k == TY_BAD)
        return mkty((cmp || eq) ? TY_BOOL : TY_BAD);

    if (eq) {
        if (!(is_scalarty(l.k) && l.k == r.k) &&
            !json_str_compat(l.k, r.k) &&
            !decision_compat(l.k, r.k)) {
            snprintf(msg, sizeof msg, "cannot compare %s with %s",
                     tyname(l), tyname(r));
            tdiag(c, "AXI-T008", n, msg,
                  "==/!= wants two scalars of the same type; json may compare with str; decision with bool");
        }
        return mkty(TY_BOOL);
    }
    if (cmp) {
        if (!is_numeric(l.k) || l.k != r.k) {
            snprintf(msg, sizeof msg, "cannot order %s against %s",
                     tyname(l), tyname(r));
            tdiag(c, "AXI-T008", n, msg,
                  "< <= > >= want two numbers of the same type; no coercion");
        }
        return mkty(TY_BOOL);
    }

    /* arithmetic — INV-316 / AXI-INV-101: the accepted arithmetic tokens are
     * named here so the op matrix can prove this layer sees them. */
    if (n->op != T_PLUS && n->op != T_MINUS && n->op != T_STAR &&
        n->op != T_SLASH && n->op != T_PERCENT) {
        tdiag(c, "AXI-T008", n, "operator has no type rule",
              "the op matrix (tools/axi_op_matrix.py) should have caught this");
        return mkty(TY_BAD);
    }
    if (!is_numeric(l.k) || !is_numeric(r.k)) {
        ty bad = is_numeric(l.k) ? r : l;
        snprintf(msg, sizeof msg, "arithmetic on %s", tyname(bad));
        tdiag(c, "AXI-T009", n, msg,
              "+-*/% work on u64, i64 or f64 only");
        return mkty(TY_BAD);
    }
    if (l.k != r.k) {
        snprintf(msg, sizeof msg, "mixed operand types: %s and %s",
                 tyname(l), tyname(r));
        snprintf(fix, sizeof fix,
                 "no coercion, ever: make both %s or both %s explicitly",
                 tyname(l), tyname(r));
        tdiag(c, "AXI-T008", n, msg, fix);
        return mkty(TY_BAD);
    }
    if (n->op == T_PERCENT && l.k == TY_F64) {
        tdiag(c, "AXI-T009", n, "% is integer-only",
              "u64/i64 remainder; for f64 build it from / and *");
        return mkty(TY_BAD);
    }
    return l;
}

static ty check_expr(ck *c, const axi_node *n)
{
    switch (n->kind) {
    case N_INT:   return mkty(TY_U64);
    case N_FLOAT: return mkty(TY_F64);
    case N_STR:   return mkty(TY_STR);
    case N_TRUE: case N_FALSE: return mkty(TY_BOOL);
    case N_OK:    return mkty(TY_UNIT);
    case N_ERRT: {
        if (!manifest_dotted_name_ok(n)) {
            tdiag(c, "AXI-T002", n, "error atom is outside manifest v1",
                  "use at most two non-empty path segments and 63 ASCII bytes");
            return mkty(TY_BAD);
        }
        ty t = mkty(TY_ERR);
        t.lex = n->lex; t.lexlen = n->lexlen;
        return t;
    }
    case N_ID: {
        binding *b = env_find(c, n->lex, n->lexlen);
        if (b) {
            b->used = 1;
            if (b->t.k == TY_CAP && c->is_pure)
                tdiag(c, "AXI-T019", n, "pure cell touches a cap",
                      "drop `pure` or drop the cap effect (G4)");
            return b->t;
        }
        if (n->lexlen == 0) return mkty(TY_BAD); /* parser poison node */
        if (find_cell(c, n->lex, n->lexlen)) {
            tdiag(c, "AXI-T003", n, "cells are not values in v0",
                  "call it: name(...)");
            return mkty(TY_BAD);
        }
        tdiag(c, "AXI-T003", n, "unknown name",
              "declare it with `let` or as a parameter");
        return mkty(TY_BAD);
    }
    case N_UN: {
        ty v = check_expr(c, n->a);
        if (v.k == TY_UNION) return union_leak(c, n->a);
        if (v.k == TY_BAD) return v;
        if (n->op == T_BANG) {
            if (v.k != TY_BOOL)
                tdiag(c, "AXI-T009", n, "! wants a bool",
                      "compare explicitly; truthiness does not exist here");
            return mkty(TY_BOOL);
        }
        /* unary minus — named so the op matrix can prove the layer sees it */
        if (n->op != T_MINUS) {
            tdiag(c, "AXI-T009", n, "unary operator has no type rule",
                  "the op matrix (tools/axi_op_matrix.py) should have caught this");
            return mkty(TY_BAD);
        }
        if (n->a->kind == N_INT) { /* -5 is an i64 literal */
            if (n->a->ival > (UINT64_C(1) << 63)) {
                tdiag(c, "AXI-T009", n, "negative integer literal is outside i64",
                      "i64 minimum is -9_223_372_036_854_775_808");
                return mkty(TY_BAD);
            }
            ((axi_node *)n)->tyann = 1;    /* AXI-INV-101 */
            return mkty(TY_I64);
        }
        if (v.k == TY_U64) {
            tdiag(c, "AXI-T009", n, "unary - on u64: u64 has no sign",
                  "use i64 or f64 (sign confusion is a lineage bug: INV-002)");
            return mkty(TY_BAD);
        }
        if (v.k != TY_I64 && v.k != TY_F64) {
            tdiag(c, "AXI-T009", n, "unary - wants i64 or f64",
                  "negate numbers only");
            return mkty(TY_BAD);
        }
        /* AXI-INV-101: the codegen expands -x as 0 - x and must not guess
         * which zero; the checker annotates the exact kind it proved. */
        ((axi_node *)n)->tyann = v.k == TY_I64 ? 1 : 2;
        return v;
    }
    case N_BIN:   return check_bin(c, n);
    case N_CALL:  return check_call(c, n);
    case N_TRY:   return check_try(c, n);
    case N_FIELD: {
        ty base = check_expr(c, n->a);
        if (base.k == TY_CAP) {
            tdiag(c, "AXI-T025", n, "cap methods are not values",
                  "call it: path.method(...); effects fire, they are not held");
            return mkty(TY_BAD);
        }
        if (base.k != TY_BAD)
            tdiag(c, "AXI-T020", n, "field access needs a cap in v0",
                  "v0 has no records; effects and views live behind caps");
        return mkty(TY_BAD);
    }
    case N_INDEX: {
        ty base = check_expr(c, n->a);
        (void)check_expr(c, n->b);
        if (base.k == TY_CAP) {
            tdiag(c, "AXI-T025", n, "caps have methods, not elements",
                  "call it: path.method(...)");
            return mkty(TY_BAD);
        }
        if (base.k != TY_BAD)
            tdiag(c, "AXI-T020", n, "indexing needs a cap in v0",
                  "v0 has no collections; stage them behind a cap");
        return mkty(TY_BAD);
    }
    case N_LIST: {
        const axi_node *k;
        for (k = n->list; k; k = k->next) (void)check_expr(c, k);
        tdiag(c, "AXI-T020", n, "list literals have no type in v0",
              "v0 has no collections; stage them behind a cap");
        return mkty(TY_BAD);
    }
    default:
        return mkty(TY_BAD);
    }
}

/* ---- statements & cells ------------------------------------------------------ */

static void check_ret(ck *c, const axi_node *n, const rshape *mine)
{
    char msg[AXI_DIAG_MSG], fix[AXI_DIAG_MSG];
    ty v;

    if (!n->a) { /* bare ret = ok */
        ((axi_node *)n)->tyann = mine->has_ok && mine->payload
            ? AXI_RET_NONE : AXI_RET_PLAIN;
        if (!mine->has_ok)
            tdiag(c, "AXI-T016", n, "bare `ret` returns ok, "
                  "but the rettype has no ok member",
                  "add `| ok` or return a value");
        return;
    }
    v = check_expr(c, n->a);
    ((axi_node *)n)->tyann = mine->has_ok && mine->payload && v.k != TY_ERR
        ? (v.k == TY_UNIT ? AXI_RET_NONE : AXI_RET_SOME) : AXI_RET_PLAIN;
    switch (v.k) {
    case TY_BAD: return;
    case TY_UNION: (void)union_leak(c, n->a); return;
    case TY_UNIT:
        if (!mine->has_ok)
            tdiag(c, "AXI-T016", n->a, "`ok` returned, "
                  "but the rettype has no ok member", "add `| ok`");
        return;
    case TY_ERR:
        if (!rshape_has_err(mine, v.lex, v.lexlen)) {
            snprintf(msg, sizeof msg, "err.%.*s is not in this cell's "
                     "error set", (int)v.lexlen, v.lex);
            snprintf(fix, sizeof fix, "add `| err.%.*s` to the rettype",
                     (int)v.lexlen, v.lex);
            tdiag(c, "AXI-T018", n->a, msg, fix);
        }
        return;
    case TY_CAP:
        tdiag(c, "AXI-T016", n->a, "caps cannot be returned (G4)",
              "caps flow down through signatures, never up");
        return;
    default: {
        ty want = mine->payload ? type_of_typenode(c, mine->payload)
                                : mkty(TY_UNIT);
        if (want.k == TY_UNIT) {
            snprintf(msg, sizeof msg, "returning %s, but the rettype has no "
                     "payload type", tyname(v));
            tdiag(c, "AXI-T016", n->a, msg, "declare the payload in the rettype");
            return;
        }
        if (want.k != TY_BAD && v.k != want.k && !decision_compat(want.k, v.k)) {
            snprintf(msg, sizeof msg, "returning %s where the rettype says %s",
                     tyname(v), tyname(want));
            tdiag(c, "AXI-T016", n->a, msg,
                  "no coercion: rewrite the value to the declared type");
        }
        return;
    } }
}

static void check_block(ck *c, const axi_node *blk, const rshape *mine);

static void check_stmt(ck *c, const axi_node *s, const rshape *mine)
{
    switch (s->kind) {
    case N_LET: {
        ty v = check_expr(c, s->a);
        if (v.k == TY_UNION) { (void)union_leak(c, s->a); v = mkty(TY_BAD); }
        env_bind(c, s, s->lex, s->lexlen, v);
        return;
    }
    case N_RET:
        check_ret(c, s, mine);
        return;
    case N_IF: {
        ty cond = check_expr(c, s->a);
        if (cond.k != TY_BOOL && cond.k != TY_BAD)
            tdiag(c, "AXI-T007", s->a, "if condition must be a bool",
                  "compare explicitly; truthiness does not exist here");
        if (s->b) check_block(c, s->b, mine);
        if (s->c) check_block(c, s->c, mine); /* INV-276; AXI-INV-074 */
        return;
    }
    case N_EXPRSTMT: {
        ty v = check_expr(c, s->a);
        if (v.k == TY_UNION) (void)union_leak(c, s->a);
        return;
    }
    default: return;
    }
}

static void check_block(ck *c, const axi_node *blk, const rshape *mine)
{
    const axi_node *s;
    /* INV-319 / AXI-INV-102: a block is a scope. Bindings born here die here;
     * env is a stack of borrowed slices, so restoring nenv is the whole
     * operation. Names visible from outer scopes stay visible (T002 keeps
     * refusing shadowing), and a name from a closed branch is simply unknown
     * afterward — no path reads a value that branch never defined. */
    int saved = c->nenv;
    for (s = blk->list; s; s = s->next) check_stmt(c, s, mine);
    c->nenv = saved;
}

typedef struct {
    const char *p;
    uint32_t n;
} manifest_slice;

static int manifest_wire_add(size_t *wire, size_t add)
{
    if (add > AXB_MANIFEST_MAX_BYTES - *wire) return 0;
    *wire += add;
    return 1;
}

static int manifest_dotted_name_ok(const axi_node *n)
{
    uint32_t i;
    int dots = 0;
    if (!n || !n->lex || n->lexlen == 0 || n->lexlen > AXB_MANIFEST_MAX_NAME)
        return 0;
    for (i = 0; i < n->lexlen; i++) if (n->lex[i] == '.' && ++dots > 1) return 0;
    return 1;
}

static void manifest_cap_add(manifest_slice caps[AXB_MANIFEST_MAX_CAPS],
                             int *ncaps, const char *p, uint32_t n,
                             int *oversized)
{
    int i;
    for (i = 0; i < *ncaps; i++)
        if (caps[i].n == n && memcmp(caps[i].p, p, n) == 0) return;
    if (*ncaps >= (int)AXB_MANIFEST_MAX_CAPS) { *oversized = 1; return; }
    caps[*ncaps].p = p;
    caps[*ncaps].n = n;
    (*ncaps)++;
}

/* INV-383 / AXI-INV-123: type-green is the source-side admission token for
 * manifest projection, so every bounded wire fact must fit before it is set. */
static void check_manifest_domain(ck *c, const axi_node *cell)
{
    const axi_node *n;
    manifest_slice caps[AXB_MANIFEST_MAX_CAPS];
    char *laws[AXB_MANIFEST_MAX_LAWS] = {0};
    size_t wire = 4 + 4 + 8 + 4;
    int ncaps = 0, nlaws = 0, oversized = 0, canon_oom = 0;

    if (!cell->a) return;
    for (n = cell->a->list; n; n = n->next) {
        if (!manifest_wire_add(&wire, 4 + n->lexlen + 1)) oversized = 1;
        if (n->a && n->a->ival == 1) {
            if (!manifest_dotted_name_ok(n->a))
                tdiag(c, "AXI-T002", n->a, "capability name is outside manifest v1",
                      "use at most two non-empty path segments and 63 ASCII bytes");
            if (!manifest_wire_add(&wire, 4 + n->a->lexlen)) oversized = 1;
            manifest_cap_add(caps, &ncaps, n->a->lex, n->a->lexlen, &oversized);
        }
    }

    {
        size_t nreturns = 0;
        if (cell->a->b)
            for (n = cell->a->b->list; n; n = n->next)
                if (n->kind != N_ERRT) nreturns++;
        if (!manifest_wire_add(&wire, 4 + nreturns + 4)) oversized = 1;
        if (cell->a->b)
            for (n = cell->a->b->list; n; n = n->next) {
                if (n->kind != N_ERRT) continue;
                if (!manifest_dotted_name_ok(n))
                    tdiag(c, "AXI-T002", n, "error atom is outside manifest v1",
                          "use at most two non-empty path segments and 63 ASCII bytes");
                if (!manifest_wire_add(&wire, 4 + n->lexlen)) oversized = 1;
            }
    }

    for (int kind = 1; kind < CAP__COUNT; kind++)
        if (cell->inferred_caps_mask & (UINT32_C(1) << kind)) {
            const char *name = axi_cap_name((axi_cap_kind)kind);
            manifest_cap_add(caps, &ncaps, name, (uint32_t)strlen(name), &oversized);
        }
    if (!manifest_wire_add(&wire, 4)) oversized = 1;
    for (int i = 0; i < ncaps; i++)
        if (!manifest_wire_add(&wire, 4 + caps[i].n)) oversized = 1;

    if (!manifest_wire_add(&wire, 4)) oversized = 1;
    if (cell->c) for (n = cell->c->list; n; n = n->next) {
        char *law;
        size_t len;
        int duplicate = 0;
        if (!n->a) continue;
        law = axi_canon_expr_str_fallible(n->a);
        if (!law) { canon_oom = 1; continue; }
        len = strlen(law);
        if (len == 0 || len > AXB_MANIFEST_MAX_LAW)
            tdiag(c, "AXI-T002", n, "canonical law exceeds 4096 bytes",
                  "split the proof into smaller independent laws");
        for (int i = 0; i < nlaws; i++)
            if (strcmp(laws[i], law) == 0) duplicate = 1;
        if (duplicate)
            tdiag(c, "AXI-T006", n, "duplicate canonical proof law",
                  "keep one copy of each law");
        if (!manifest_wire_add(&wire, 4 + len)) oversized = 1;
        if (nlaws < (int)AXB_MANIFEST_MAX_LAWS) laws[nlaws++] = law;
        else { oversized = 1; free(law); }
    }
    if (!manifest_wire_add(&wire, 64)) oversized = 1;

    if (canon_oom)
        tdiag(c, "AXI-T002", cell, "cannot canonicalize contract under memory pressure",
              "retry with enough memory to prove the published contract");
    if (oversized)
        tdiag(c, "AXI-T002", cell, "contract exceeds the 16 KiB manifest v1 bound",
              "shrink names or split the contract into smaller cells");
    for (int i = 0; i < nlaws; i++) free(laws[i]);
}

static void check_cell(ck *c, const axi_node *cell)
{
    const axi_node *param, *s, *last;
    rshape mine;

    c->cell = cell;
    c->nenv = 0;
    c->is_pure = cell_is_pure(cell);

    int nparams = 0;
    for (param = cell->a->list; param; param = param->next) {
        ty t = type_of_typenode(c, param->a);
        if (t.k == TY_CAP && c->is_pure)
            tdiag(c, "AXI-T019", param, "pure cell declares a cap parameter",
                  "pure means no effects: drop `pure` or drop the cap (G4)");
        /* INV-321 / AXI-INV-103: the v0 call window is 16 argument slots;
         * a 17th parameter cannot be passed, so it cannot be declared. */
        if (++nparams > 16)
            tdiag(c, "AXI-T028", param, "cell declares more than 16 parameters",
                  "the v0 call window is 16 slots; group the rest in a record "
                   "when records land");
        if (param->lexlen > 63 || (param->a && param->a->lexlen > 63))
            tdiag(c, "AXI-T002", param, "contract name exceeds 63 bytes",
                  "manifest v1 names are bounded to 63 ASCII bytes");
        env_bind(c, param, param->lex, param->lexlen, t);
    }
    for (s = cell->list; s; s = s->next)
        if (s->kind == N_FUEL && s->ival == 0)
            tdiag(c, "AXI-T002", s, "fuel budget must be positive",
                  "manifest v1 refuses zero fuel; declare at least `fuel 1`");

    rshape_of(c, cell->a->b, &mine, 1); /* validate union shape once */

    if (cell->b) check_block(c, cell->b, &mine);

    /* ADR-007 / AXI-INV-065: infer required capabilities from the body and
     * verify them against the declared cap clause (when present). */
    {
        const axi_cap_set *summary = cell_cap_summary(c, cell);
        axi_cap_infer_result inf;
        axi_cap_infer_init(&inf);
        if (summary) inf.caps = *summary;
        check_inferred_caps(c, cell, &inf);
    }

    /* termination: the body must not fall off the end (v0: last stmt = ret) */
    last = NULL;
    if (cell->b)
        for (s = cell->b->list; s; s = s->next) last = s;
    if (!last || last->kind != N_RET)
        tdiag(c, "AXI-T017", last ? last : cell,
              "control can fall off the end of the body",
              "the last statement of a cell is `ret` (v0 rule)");

    /* T026: dead authority. A cap you hold and never use is attack surface
     * pretending to be a parameter. Ambient blindness cuts both ways: no
     * hidden authority in, no unused authority held. */
    {
        int i;
        for (i = 0; i < c->nenv; i++) {
            if (c->env[i].t.k != TY_CAP || c->env[i].used) continue;
            {
                char m[AXI_DIAG_MSG];
                snprintf(m, sizeof m, "cap %.*s is never used",
                         (int)c->env[i].lexlen, c->env[i].lex);
                tdiag(c, "AXI-T026",
                      c->env[i].at ? c->env[i].at : cell, m,
                      "unused authority is attack surface: drop the "
                      "parameter or use the cap (G4)");
            }
        }
    }

    check_manifest_domain(c, cell);

}

/* AXI-INV-066: policy is always impure and its cap clause is an upper bound. */
static void check_policy(ck *c, const axi_node *cell)
{
    const axi_node *param, *s, *last, *m;
    rshape mine;

    c->cell = cell;
    c->nenv = 0;
    c->is_pure = 0;  /* policy is always impure */

    /* policy rejects uses and pure clauses */
    for (m = cell->list; m; m = m->next) {
        if (m->kind == N_USES)
            tdiag(c, "AXI-T022", m, "policy does not declare uses",
                  "capabilities are inferred from the body (ADR-007)");
        else if (m->kind == N_PURE)
            tdiag(c, "AXI-T019", m, "policy cannot be pure",
                  "a policy decides about effects, so it is never pure");
    }

    {
        int nparams = 0;
        for (param = cell->a->list; param; param = param->next) {
            ty t = type_of_typenode(c, param->a);
            if (++nparams > 16)
                tdiag(c, "AXI-T028", param,
                      "policy declares more than 16 parameters",
                      "the v0 call window and manifest v1 carry 16 slots");
            if (param->lexlen > 63 || (param->a && param->a->lexlen > 63))
                tdiag(c, "AXI-T002", param, "contract name exceeds 63 bytes",
                      "manifest v1 names are bounded to 63 ASCII bytes");
            env_bind(c, param, param->lex, param->lexlen, t);
        }
    }

    for (m = cell->list; m; m = m->next)
        if (m->kind == N_FUEL && m->ival == 0)
            tdiag(c, "AXI-T002", m, "fuel budget must be positive",
                  "manifest v1 refuses zero fuel; declare at least `fuel 1`");

    rshape_of(c, cell->a->b, &mine, 1);
    if (cell->b) check_block(c, cell->b, &mine);

    {
        const axi_cap_set *summary = cell_cap_summary(c, cell);
        axi_cap_infer_result inf;
        axi_cap_infer_init(&inf);
        if (summary) inf.caps = *summary;
        check_inferred_caps(c, cell, &inf);
    }

    last = NULL;
    if (cell->b)
        for (s = cell->b->list; s; s = s->next) last = s;
    if (!last || last->kind != N_RET)
        tdiag(c, "AXI-T017", last ? last : cell,
              "control can fall off the end of the policy body",
              "the last statement of a policy is `ret` (v0 rule)");

    /* INV-364 / AXI-INV-113: parse_policy owns proof in N_POLICY->c. Laws are
     * closed bool terms and may only call pure cells; checking N_CELL->c left
     * every source-level policy proof outside this authority boundary. */
    if (cell->c) {
        const axi_node *law;
        int nlaws = 0;
        c->nenv = 0;
        c->in_proof = 1;
        for (law = cell->c->list; law; law = law->next) {
            ty t;
            if (++nlaws > 64)
                tdiag(c, "AXI-T002", law, "proof exceeds 64 laws",
                      "manifest v1 carries at most 64 canonical laws");
            if (law->kind != N_EXPRSTMT || !law->a) continue; /* P010'd */
            t = check_expr(c, law->a);
            if (t.k != TY_BOOL && t.k != TY_BAD)
                tdiag(c, "AXI-S002", law->a, "a law must be a bool",
                      "state a checkable fact: `cell(args) == expected`");
        }
        c->in_proof = 0;
    }
    check_manifest_domain(c, cell);
}

void axi_type_check(const axi_node *unit, axi_diags *ds)
{
    ck c;
    const axi_node *n;

    ((axi_node *)unit)->contract_checked = 0;
    memset(&c, 0, sizeof c);
    c.ds = ds;
    c.src = unit->pos;

    for (n = unit->list; n; n = n->next) {
        if ((n->kind != N_CELL && n->kind != N_POLICY) || n->lexlen == 0) continue;
        if (find_cell(&c, n->lex, n->lexlen)) {
            tdiag(&c, "AXI-T001", n, "duplicate cell name",
                  "one name, one cell, one hash (W14): rename it");
            continue;
        }
        if (c.ncells < 256) {
            c.cells[c.ncells++] = n;
        } else {
            tdiag(&c, "AXI-T002", n, "unit exceeds 256 cells",
                  "split the unit; every cell must enter capability analysis");
        }
    }
    infer_unit_caps(&c); /* AXI-INV-078: finite monotone call-graph fixpoint. */
    for (n = unit->list; n; n = n->next) {
        if (n->kind == N_CELL) check_cell(&c, n);
        else if (n->kind == N_POLICY) check_policy(&c, n);
    }
    if (ds->n == 0) ((axi_node *)unit)->contract_checked = 1;
}
