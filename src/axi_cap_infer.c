/* axial — capability inference engine (ADR-007). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * Infers required capabilities from cell body AST.
 * Walks the AST and collects all effectful operations.
 */
#include "axi_cap_infer.h"
#include "axi_cap_table.h"
#include "axi_ast.h"
#include "axi.h"
#include <string.h>
#include <stdlib.h>

void axi_cap_infer_init(axi_cap_infer_result *r)
{
    r->caps.n = 0;
    r->uses.n = 0;
    r->pure = 0;
}

int axi_cap_set_add(axi_cap_set *s, axi_cap_kind k, const axi_node *site)
{
    if (k == CAP_NONE) return 0;
    for (int i = 0; i < s->n; i++)
        if (s->caps[i] == k) return 0;  /* already present */
    if (s->n >= AXI_INFERRED_CAP_MAX) return -1;
    s->caps[s->n] = k;
    s->sites[s->n] = site;
    s->n++;
    return 0;
}

void axi_cap_set_merge(axi_cap_set *s1, const axi_cap_set *s2)
{
    for (int i = 0; i < s2->n; i++)
        axi_cap_set_add(s1, s2->caps[i], s2->sites[i]);
}

int axi_cap_set_empty(const axi_cap_set *s)
{
    return s->n == 0;
}

int axi_cap_set_has(const axi_cap_set *s, axi_cap_kind k)
{
    for (int i = 0; i < s->n; i++)
        if (s->caps[i] == k) return 1;
    return 0;
}

void axi_cap_set_print(const axi_cap_set *s, FILE *out)
{
    for (int i = 0; i < s->n; i++) {
        if (i) fputs(", ", out);
        fputs(axi_cap_name(s->caps[i]), out);
    }
}

/* Forward declarations for recursive walk */
static int infer_expr(const axi_node *n, const axi_cap_infer_env *env,
                      axi_diags *ds, axi_cap_set *out_caps);
static int infer_stmt(const axi_node *s, const axi_cap_infer_env *env,
                      axi_diags *ds, axi_cap_set *out_caps);
static int infer_block(const axi_node *blk, const axi_cap_infer_env *env,
                       axi_diags *ds, axi_cap_set *out_caps);

/* Built-ins that are not cap methods but still require authority (ADR-001 v0). */
static const struct {
    const char *name;
    axi_cap_kind kind;
} builtin_caps[] = {
    { "fs.path_under",   CAP_FS_READ },
    { NULL, CAP_NONE }
};

static axi_cap_kind infer_builtin_cap(const char *name, size_t len)
{
    for (int i = 0; builtin_caps[i].name; i++) {
        size_t bl = strlen(builtin_caps[i].name);
        if (bl == len && memcmp(builtin_caps[i].name, name, len) == 0)
            return builtin_caps[i].kind;
    }
    return CAP_NONE;
}

static axi_cap_kind infer_cap_param(const axi_cap_infer_env *env,
                                    const char *name, size_t len)
{
    if (!env) return CAP_NONE;
    for (int i = 0; i < env->nbindings; i++) {
        if (env->bindings[i].namelen == len &&
            memcmp(env->bindings[i].name, name, len) == 0)
            return env->bindings[i].kind;
    }
    return CAP_NONE;
}

/* Main inference entry point */
int axi_cap_infer(const axi_node *cell_body, const axi_cap_infer_env *env,
                  axi_diags *ds, axi_cap_infer_result *out)
{
    axi_cap_infer_init(out);
    if (!cell_body) return 0;

    int err = infer_block(cell_body, env, ds, &out->caps);
    if (err) return -1;

    /* In v0, uses == caps (1:1 mapping) */
    out->uses = out->caps;
    out->pure = axi_cap_set_empty(&out->caps);
    return 0;
}

/* ---- expression walker ---------------------------------------------------- */

static int infer_expr(const axi_node *n, const axi_cap_infer_env *env,
                      axi_diags *ds, axi_cap_set *out_caps)
{
    if (!n) return 0;

    switch (n->kind) {
    case N_CALL: {
        const axi_node *callee = n->a;
        if (callee && callee->kind == N_FIELD) {
            const axi_node *base = callee->a;
            if (base && base->kind == N_ID) {
                axi_cap_kind k = infer_cap_param(env, base->lex, base->lexlen);
                if (k != CAP_NONE) {
                    /* INV-315 / AXI-INV-100: inference credits a method only
                     * when the generated table says the cap HAS that method;
                     * the typechecker refuses the call either way. */
                    if (axi_cap_method_find(k, callee->lex, callee->lexlen))
                        axi_cap_set_add(out_caps, k, n);
                } else if (callee->lex && callee->lexlen > 0 && base->lex) {
                    /* namespaced built-in: fs.path_under, env.get, etc. */
                    char full[64];
                    size_t bl = base->lexlen, fl = callee->lexlen;
                    if (bl + 1 + fl < sizeof full) {
                        memcpy(full, base->lex, bl);
                        full[bl] = '.';
                        memcpy(full + bl + 1, callee->lex, fl);
                        full[bl + 1 + fl] = '\0';
                        k = infer_builtin_cap(full, bl + 1 + fl);
                        if (k != CAP_NONE)
                            axi_cap_set_add(out_caps, k, n);
                    }
                }
            }
            /* Recurse into base even if not a cap param */
            if (infer_expr(base, env, ds, out_caps)) return -1;
        } else if (callee && callee->kind == N_ID) {
            axi_cap_kind k = infer_builtin_cap(callee->lex, callee->lexlen);
            if (k != CAP_NONE)
                axi_cap_set_add(out_caps, k, n);
        }
        /* Recurse into arguments */
        for (const axi_node *arg = n->list; arg; arg = arg->next) {
            if (infer_expr(arg, env, ds, out_caps)) return -1;
        }
        break;
    }
    case N_FIELD: {
        if (n->a) infer_expr(n->a, env, ds, out_caps);
        break;
    }
    case N_BIN: {
        if (n->a) infer_expr(n->a, env, ds, out_caps);
        if (n->b) infer_expr(n->b, env, ds, out_caps);
        break;
    }
    case N_UN: {
        if (n->a) infer_expr(n->a, env, ds, out_caps);
        break;
    }
    case N_TRY: {
        if (n->a) infer_expr(n->a, env, ds, out_caps);
        break;
    }
    case N_INDEX: {
        if (n->a) infer_expr(n->a, env, ds, out_caps);
        if (n->b) infer_expr(n->b, env, ds, out_caps);
        break;
    }
    case N_LIST: {
        for (const axi_node *k = n->list; k; k = k->next)
            infer_expr(k, env, ds, out_caps);
        break;
    }
    case N_ID:
    case N_INT:
    case N_FLOAT:
    case N_STR:
    case N_TRUE:
    case N_FALSE:
    case N_OK:
    case N_ERRT:
        /* Literals and names don't infer caps directly */
        break;
    default:
        break;
    }
    return 0;
}

/* ---- statement walker ----------------------------------------------------- */

static int infer_stmt(const axi_node *s, const axi_cap_infer_env *env,
                      axi_diags *ds, axi_cap_set *out_caps)
{
    if (!s) return 0;

    switch (s->kind) {
    case N_LET:
        if (s->a) infer_expr(s->a, env, ds, out_caps);
        break;
    case N_RET:
        if (s->a) infer_expr(s->a, env, ds, out_caps);
        break;
    case N_IF:
        if (s->a) infer_expr(s->a, env, ds, out_caps);
        if (s->b) infer_block(s->b, env, ds, out_caps);
        if (s->c) infer_block(s->c, env, ds, out_caps);
        break;
    case N_EXPRSTMT:
        if (s->a) infer_expr(s->a, env, ds, out_caps);
        break;
    case N_POLICY:
        /* Policy condition expression */
        if (s->a) infer_expr(s->a, env, ds, out_caps);
        break;
    default:
        break;
    }
    return 0;
}

static int infer_block(const axi_node *blk, const axi_cap_infer_env *env,
                       axi_diags *ds, axi_cap_set *out_caps)
{
    if (!blk) return 0;
    for (const axi_node *s = blk->list; s; s = s->next) {
        if (infer_stmt(s, env, ds, out_caps)) return -1;
    }
    return 0;
}
