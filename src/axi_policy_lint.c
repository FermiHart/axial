/* AX30 — limited, opt-in diagnostics for risky policy authorship.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 * No dataflow, theorem proving, fact attestation or automatic rewriting.
 * Only type-checked ASTs from this frontend, with the source alive, are accepted.
 */
#include "axi_policy_lint.h"
#include <string.h>
static int named(const axi_node *n, const char *s)
{
    return n && n->lex && n->lexlen == strlen(s) && !memcmp(n->lex,s,n->lexlen);
}
static int call_is(const axi_node *n, const char *base, const char *field)
{
    return n->kind == N_CALL && n->a && n->a->kind == N_FIELD
        && named(n->a,field) && n->a->a && n->a->a->kind == N_ID && named(n->a->a,base);
}
static int arithmetic(const axi_node *n)
{
    if (!n) return 0;
    return n->kind == N_BIN && (n->op == T_PLUS || n->op == T_MINUS || n->op == T_STAR);
}
static void emit(axi_diags *d, const axi_node *n, const char *base,
                 const char *code, const char *message, const char *fix)
{
    axi_diag_add_at(d,code,n->line,n->col,1,
                    n->pos ? (uint32_t)(n->pos-base) : AXI_NO_OFF,message,fix);
}
static void walk(const axi_node *n, const char *base, axi_diags *d)
{
    for (; n && d->n < AXI_DIAG_MAX; n=n->next) {
        if (n->kind == N_BIN && (n->op==T_LE || n->op==T_LT || n->op==T_GE || n->op==T_GT)
                && (arithmetic(n->a)||arithmetic(n->b)))
            emit(d,n,base,"AXI-LN001","arithmetic directly inside a limit comparison may wrap",
                 "use budget.fits / fits_product or explicit checked arithmetic; review signedness");
        if (call_is(n,"json","get"))
            emit(d,n,base,"AXI-LN002","textual JSON getter erases the fact type",
                 "use json.bool/u64/i64/string and a trusted fact producer");
        if (call_is(n,"fs","path_under") || (n->kind==N_CALL && named(n->a,"fs.path_under")))
            emit(d,n,base,"AXI-LN003","lexical path membership is not filesystem containment",
                 "effect owner must resolve and retain the authorized object; verify identity/version");
        walk(n->a,base,d);walk(n->b,base,d);walk(n->c,base,d);walk(n->list,base,d);
    }
}
void axi_policy_lint(const axi_node *unit, axi_diags *diags)
{
    if (!unit || !diags || !unit->pos) return;
    walk(unit,unit->pos,diags);
}
