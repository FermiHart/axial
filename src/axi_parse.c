/* axial — recursive-descent parser (W04). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * Laws honored:
 *  - G6 LL(1): `cur` is the single lookahead token, nothing else.
 *  - G8 caged diagnostics: every error emits AXI-P0xx + fix, then applies
 *    the documented recovery (skip to sync token). The parser never wedges:
 *    every loop consumes or breaks (bear INV-212/213 ancestry).
 *  - G5 fuel is syntax: a cell without `fuel` is a parse-time diagnostic.
 *  - Expression depth is capped (AXI-P009): fail-closed on hostile nesting,
 *    same doctrine as the blibc-regex ReDoS lesson.
 */
#include "axi_ast.h"
#include "axi_alloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "axi_osif.h"   /* AXI-INV-064: one door for the streams */

#define P_MAX_DEPTH 64

typedef struct parsed_node parsed_node;

typedef struct {
    axi_lexer   lx;
    axi_token   cur;        /* the one lookahead (G6) */
    axi_diags  *ds;
    int         depth;
    int         block_depth;
    unsigned    expr_operators;
    const char *last_error;
    parsed_node *allocated;
    int oom;
    axi_compile_budget *budget;
} parser;

/* The node is the first member: ordinary axi_ast_free/free(node) still owns
 * a successful tree. The private link makes every partial allocation
 * reclaimable if any later allocation fails, even before AST attachment. */
struct parsed_node {
    axi_node node;
    parsed_node *next;
};

/* ---- node helpers ------------------------------------------------------- */

/* W16: a node's position is always born from a token, never re-typed by
 * hand. One door: there is no way to make a node with a (line,col) that
 * no token vouches for, so the byte anchor can never drift from the
 * human coordinates (AXI-INV-027). */
static axi_node *nnew_at(parser *p, axi_nkind k, const axi_token *t)
{
    parsed_node *allocated;
    axi_node *n;
    if (p->oom) return NULL;
    allocated = (parsed_node *)axi_compile_calloc(p->budget, 1, sizeof *allocated);
    if (!allocated) { p->oom = 1; return NULL; }
    allocated->next = p->allocated;
    p->allocated = allocated;
    n = &allocated->node;
    n->budget = p->budget;
    n->kind = k; n->line = t->line; n->col = t->col; n->pos = t->start;
    return n;
}

static axi_node *nnew_tok(parser *p, axi_nkind k, const axi_token *t)
{
    axi_node *n = nnew_at(p, k, t);
    if (!n) return NULL;
    n->lex = t->start; n->lexlen = t->len;
    return n;
}

static void list_push(axi_node *parent, axi_node ***tail, axi_node *item)
{
    if (!item) return;
    if (*tail == NULL) *tail = &parent->list;
    **tail = item;
    *tail = &item->next;
}

/* ---- token helpers ------------------------------------------------------ */

static void advance(parser *p) { axi_lex_next(&p->lx, &p->cur); }

static int at(parser *p, axi_tok_kind k) { return p->cur.kind == k; }

static int accept(parser *p, axi_tok_kind k)
{
    if (!at(p, k)) return 0;
    advance(p);
    return 1;
}

static void diag_ptr(parser *p, const char *code, const char *at, uint32_t len,
                     const char *msg, const char *fix)
{
    if (p->oom) return;
    if (at)
        axi_diag_add_source(p->ds, code, p->lx.src,
                            (uint32_t)(at - p->lx.src), len, msg, fix);
    else
        axi_diag_add(p->ds, code, 0, 0, 0, msg, fix);
}

static void diag_here(parser *p, const char *code, const char *msg,
                       const char *fix)
{
    if (p->oom) return;
    /* AX30: one primary diagnostic for an unconsumed token. Coordinates
     * remain derived from the lexer, the sole byte consumer. */
    if (p->last_error == p->cur.start) return;
    p->last_error = p->cur.start;
    axi_diag_add_at(p->ds, code, p->cur.line, p->cur.col, p->cur.len,
                    (uint32_t)(p->cur.start - p->lx.src), msg, fix);
}

static int expect(parser *p, axi_tok_kind k, const char *code,
                  const char *what, const char *fix)
{
    char msg[AXI_DIAG_MSG];
    if (accept(p, k)) return 1;
    snprintf(msg, sizeof msg, "expected %s, got %s",
             what, axi_tok_name(p->cur.kind));
    diag_here(p, code, msg, fix);
    return 0;
}

/* recovery: eat until a sync token (never consumes EOF) */
static void sync_to(parser *p, const axi_tok_kind *set, int nset)
{
    while (!at(p, T_EOF)) {
        int i;
        for (i = 0; i < nset; i++)
            if (at(p, set[i])) return;
        advance(p);
    }
}

/* ---- forward ------------------------------------------------------------ */

static axi_node *parse_expr(parser *p);
static axi_node *parse_block(parser *p);

/* ---- types & signature (SPEC §3) ---------------------------------------- */

/* path = ID { "." ID } ; lex slice covers the whole dotted path.
 * v0 paths are at most two parts (Category.Verb); stop before a second dot
 * so module-level .eff declarations do not get swallowed by a greedy path. */
static axi_node *parse_path(parser *p, axi_nkind k)
{
    axi_token first = p->cur;
    const char *end;
    axi_node *n;
    if (!expect(p, T_ID, "AXI-P001", "a name", "write an identifier here"))
        return nnew_at(p, k, &first);
    end = first.start + first.len;
    if (at(p, T_DOT)) {
        advance(p);
        if (!at(p, T_ID)) {
            diag_here(p, "AXI-P001", "expected name after '.'",
                      "paths are ID.ID, e.g. io.Write");
        } else {
            end = p->cur.start + p->cur.len;
            advance(p);
        }
    }
    n = nnew_at(p, k, &first);
    if (!n) return NULL;
    n->lex = first.start;
    n->lexlen = (uint32_t)(end - first.start);
    return n;
}

static int is_scalar(axi_tok_kind k)
{
    return k == T_U64 || k == T_I64 || k == T_F64 || k == T_BOOL ||
           k == T_BYTES || k == T_STRTY || k == T_DECISION;
}

static axi_node *parse_type(parser *p)
{
    if (is_scalar(p->cur.kind)) {
        axi_node *n = nnew_tok(p, N_TYPE, &p->cur); if (!n) return NULL;
        advance(p);
        return n;
    }
    if (at(p, T_CAP)) {
        axi_node *n;
        advance(p);
        n = parse_path(p, N_TYPE);
        if (!n) return NULL;
        n->ival = 1; /* cap-qualified (G4: caps live in signatures only) */
        return n;
    }
    if (at(p, T_ID)) return parse_path(p, N_TYPE);
    diag_here(p, "AXI-P010", "expected a type",
              "scalar (u64 i64 f64 bool bytes str decision), cap path, or path");
    return nnew_at(p, N_TYPE, &p->cur);
}

/* rettype = rtatom { "|" rtatom } ; rtatom = ok | err "." ID | type */
static axi_node *parse_rettype(parser *p)
{
    axi_node *rt = nnew_at(p, N_LIST, &p->cur); if (!rt) return NULL;
    axi_node **tail = NULL;
    do {
        axi_node *atom;
        if (at(p, T_OK)) {
            atom = nnew_tok(p, N_OKT, &p->cur);
            if (!atom) return NULL;
            advance(p);
        } else if (at(p, T_ERR)) {
            axi_token e = p->cur;
            advance(p);
            if (!expect(p, T_DOT, "AXI-P011", "'.' after err",
                        "error atoms are named: err.Io"))
                { atom = nnew_at(p, N_ERRT, &e); list_push(rt, &tail, atom); break; }
            atom = parse_path(p, N_ERRT);
            if (!atom) return NULL;
            atom->line = e.line; atom->col = e.col;
        } else {
            atom = parse_type(p);
        }
        list_push(rt, &tail, atom);
    } while (accept(p, T_PIPE));
    return rt;
}

/* sig = "fn" "(" [ param { "," param } ] ")" "->" rettype */
static axi_node *parse_sig(parser *p)
{
    axi_node *sig = nnew_at(p, N_SIG, &p->cur); if (!sig) return NULL;
    axi_node **tail = NULL;
    if (!expect(p, T_FN, "AXI-P004", "'fn'",
                "a cell signature is: fn(args) -> type"))
        return sig;
    expect(p, T_LPAREN, "AXI-P001", "'('", "open the parameter list");
    if (!at(p, T_RPAREN)) {
        do {
            axi_node *param;
            axi_token name = p->cur;
            if (!expect(p, T_ID, "AXI-P001", "parameter name",
                        "parameters are name: type")) {
                break;
            }
            param = nnew_at(p, N_PARAM, &name);
            if (!param) return NULL;
            param->lex = name.start; param->lexlen = name.len;
            expect(p, T_COLON, "AXI-P001", "':' after parameter name",
                   "parameters are name: type");
            param->a = parse_type(p);
            list_push(sig, &tail, param);
        } while (accept(p, T_COMMA));
    }
    expect(p, T_RPAREN, "AXI-P001", "')'", "close the parameter list");
    if (!expect(p, T_ARROW, "AXI-P004", "'->'",
                "every cell declares its return: -> type"))
        return sig;
    sig->b = parse_rettype(p);
    return sig;
}

/* cap_list = cap_path { "," cap_path } ; used by 'cap' and 'uses' clauses */
static axi_node *parse_cap_list(parser *p, axi_nkind k)
{
    axi_node *list = nnew_at(p, k, &p->cur); if (!list) return NULL;
    axi_node **tail = NULL;
    do {
        list_push(list, &tail, parse_path(p, N_ID));
    } while (accept(p, T_COMMA));
    return list;
}

/* ---- expressions (SPEC §3, precedence: cmp < add < mul < unary < postfix) */

static axi_node *parse_atom(parser *p)
{
    axi_token t = p->cur;
    switch (t.kind) {
    case T_INT: {
        axi_node *n = nnew_tok(p, N_INT, &t); if (!n) return NULL; n->ival = t.ival;
        advance(p); return n;
    }
    case T_FLOAT: {
        axi_node *n = nnew_tok(p, N_FLOAT, &t); if (!n) return NULL; n->fval = t.fval;
        advance(p); return n;
    }
    case T_STR: { axi_node *n = nnew_tok(p, N_STR, &t); if (!n) return NULL; advance(p); return n; }
    case T_TRUE:  { axi_node *n = nnew_tok(p, N_TRUE, &t); if (!n) return NULL;  advance(p); return n; }
    case T_FALSE: { axi_node *n = nnew_tok(p, N_FALSE, &t); if (!n) return NULL; advance(p); return n; }
    case T_OK:    { axi_node *n = nnew_tok(p, N_OK, &t); if (!n) return NULL;    advance(p); return n; }
    case T_ERR: { /* err.Name as a VALUE — an error set nobody can inhabit
                   * is decorative; this is the constructor (W06). */
        axi_node *n;
        advance(p);
        if (!expect(p, T_DOT, "AXI-P011", "'.' after err",
                    "error atoms are named: err.Io"))
            return nnew_at(p, N_ERRT, &t);
        n = parse_path(p, N_ERRT);
        if (!n) return NULL;
        n->line = t.line; n->col = t.col;
        return n;
    }
    case T_ID:    { axi_node *n = nnew_tok(p, N_ID, &t); if (!n) return NULL;    advance(p); return n; }
    case T_LPAREN: {
        axi_node *inner;
        advance(p);
        inner = parse_expr(p);
        expect(p, T_RPAREN, "AXI-P001", "')'", "close the parenthesis");
        return inner;
    }
    case T_LBRACK: {
        axi_node *lst = nnew_at(p, N_LIST, &t); if (!lst) return NULL;
        axi_node **tail = NULL;
        advance(p);
        if (!at(p, T_RBRACK)) {
            do list_push(lst, &tail, parse_expr(p));
            while (accept(p, T_COMMA));
        }
        expect(p, T_RBRACK, "AXI-P001", "']'", "close the list literal");
        return lst;
    }
    default:
        diag_here(p, "AXI-P006", "expected an expression",
                  "a value, name, call, or ( ... ) goes here");
        advance(p); /* consume the offender: never wedge (G8) */
        return nnew_at(p, N_ID, &t); /* poison node, empty lex */
    }
}

static int expression_operator(parser *p)
{
    if (p->expr_operators >= 256u) {
        diag_here(p, "AXI-P009", "expression exceeds 256 structural operators",
                  "split the expression into bounded let bindings");
        return 0;
    }
    p->expr_operators++;
    return 1;
}

static axi_node *parse_postfix(parser *p)
{
    axi_node *n = parse_atom(p);
    if (!n) return NULL;
    for (;;) {
        if (p->oom) return NULL;
        if ((at(p, T_DOT) || at(p, T_LPAREN) || at(p, T_LBRACK) || at(p, T_QUESTION))
                && !expression_operator(p)) break;
        if (at(p, T_DOT)) {
            axi_node *f;
            advance(p);
            f = nnew_at(p, N_FIELD, &p->cur);
            if (!f) return NULL;
            /* Typed builtin members may use scalar type words after a dot.
             * They remain reserved as variable/cell names. */
            if (at(p, T_ID) || is_scalar(p->cur.kind)) {
                f->lex = p->cur.start; f->lexlen = p->cur.len; advance(p);
            }
            else diag_here(p, "AXI-P001", "expected field name after '.'",
                           "fields are names: value.field");
            f->a = n; n = f;
        } else if (at(p, T_LPAREN)) {
            axi_node *call = nnew_at(p, N_CALL, &p->cur); if (!call) return NULL;
            axi_node **tail = NULL;
            advance(p);
            call->a = n;
            if (!at(p, T_RPAREN)) {
                do list_push(call, &tail, parse_expr(p));
                while (accept(p, T_COMMA));
            }
            expect(p, T_RPAREN, "AXI-P001", "')'", "close the call");
            n = call;
        } else if (at(p, T_LBRACK)) {
            axi_node *ix = nnew_at(p, N_INDEX, &p->cur); if (!ix) return NULL;
            advance(p);
            ix->a = n; ix->b = parse_expr(p);
            expect(p, T_RBRACK, "AXI-P001", "']'", "close the index");
            n = ix;
        } else if (at(p, T_QUESTION)) {
            axi_node *tr = nnew_at(p, N_TRY, &p->cur); if (!tr) return NULL;
            advance(p);
            tr->a = n; n = tr;
        } else break;
    }
    return n;
}

static axi_node *parse_unary(parser *p)
{
    if (at(p, T_BANG) || at(p, T_MINUS)) {
        if (p->depth >= P_MAX_DEPTH || !expression_operator(p)) {
            diag_here(p, "AXI-P009", "unary expression exceeds nesting limit",
                      "split unary chains into let bindings");
            while (at(p, T_BANG) || at(p, T_MINUS)) advance(p);
            return parse_postfix(p);
        }
        axi_node *n = nnew_at(p, N_UN, &p->cur); if (!n) return NULL;
        n->op = p->cur.kind;
        advance(p);
        p->depth++;
        n->a = parse_unary(p);
        p->depth--;
        return n;
    }
    return parse_postfix(p);
}

static axi_node *bin(parser *p, axi_node *lhs, axi_node *rhs, const axi_token *t)
{
    axi_node *n = nnew_at(p, N_BIN, t); if (!n) return NULL;
    n->op = t->kind; n->a = lhs; n->b = rhs;
    return n;
}

static axi_node *parse_mul(parser *p)
{
    axi_node *n = parse_unary(p);
    if (!n) return NULL;
    while (at(p, T_STAR) || at(p, T_SLASH) || at(p, T_PERCENT)) {
        if (!expression_operator(p)) break;
        axi_token t = p->cur; advance(p);
        n = bin(p, n, parse_unary(p), &t);
    }
    return n;
}

static axi_node *parse_add(parser *p)
{
    axi_node *n = parse_mul(p);
    if (!n) return NULL;
    while (at(p, T_PLUS) || at(p, T_MINUS)) {
        if (!expression_operator(p)) break;
        axi_token t = p->cur; advance(p);
        n = bin(p, n, parse_mul(p), &t);
    }
    return n;
}

/* Build a call node: fn(arg1, arg2). Used by 'under' desugaring. */
static axi_node *make_call2(parser *p, const axi_token *t, const char *fn, uint32_t fnlen,
                            axi_node *a1, axi_node *a2)
{
    axi_node *call = nnew_at(p, N_CALL, t); if (!call) return NULL;
    axi_node *callee = nnew_at(p, N_ID, t); if (!callee) return NULL;
    callee->lex = fn;
    callee->lexlen = fnlen;
    call->a = callee;
    axi_node **tail = NULL;
    list_push(call, &tail, a1);
    list_push(call, &tail, a2);
    return call;
}

static axi_node *parse_expr(parser *p)
{
    axi_node *n;
    if (p->depth >= P_MAX_DEPTH) {
        diag_here(p, "AXI-P009", "expression nests deeper than 64",
                  "flatten it with let bindings");
        advance(p); /* consume; fail-closed, never wedge */
        return nnew_at(p, N_ID, &p->cur);
    }
    if (p->depth == 0) p->expr_operators = 0;
    p->depth++;
    n = parse_add(p);
    while (at(p, T_LT) || at(p, T_GT) || at(p, T_LE) || at(p, T_GE) ||
           at(p, T_EQ) || at(p, T_NE) || at(p, T_UNDER)) {
        if (!expression_operator(p)) break;
        axi_token t = p->cur;
        if (t.kind == T_UNDER) {
            /* ADR-008: 'a under b' desugars to 'fs.path_under(a, b)' */
            advance(p);
            n = make_call2(p, &t, "fs.path_under", 13, n, parse_add(p));
        } else {
            advance(p);
            n = bin(p, n, parse_add(p), &t);
        }
    }
    p->depth--;
    return n;
}

/* ---- statements ---------------------------------------------------------- */

static const axi_tok_kind stmt_sync[] = {
    T_LET, T_RET, T_IF, T_RBRACE, T_CELL
};

static axi_node *parse_stmt(parser *p)
{
    axi_token t = p->cur;
    if (at(p, T_LET)) {
        axi_node *n = nnew_at(p, N_LET, &t); if (!n) return NULL;
        advance(p);
        if (at(p, T_ID)) { n->lex = p->cur.start; n->lexlen = p->cur.len; advance(p); }
        else diag_here(p, "AXI-P001", "expected name after let",
                       "let name = expr");
        expect(p, T_ASSIGN, "AXI-P001", "'='", "let name = expr");
        n->a = parse_expr(p);
        return n;
    }
    if (at(p, T_RET)) {
        axi_node *n = nnew_at(p, N_RET, &t); if (!n) return NULL;
        advance(p);
        if (!at(p, T_RBRACE) && !at(p, T_LET) && !at(p, T_RET) &&
            !at(p, T_IF) && !at(p, T_EOF))
            n->a = parse_expr(p);
        return n;
    }
    if (at(p, T_IF)) {
        axi_node *n = nnew_at(p, N_IF, &t); if (!n) return NULL;
        advance(p);
        n->a = parse_expr(p);
        n->b = parse_block(p);
        if (accept(p, T_ELSE)) n->c = parse_block(p);
        return n;
    }
    {
        axi_node *n = nnew_at(p, N_EXPRSTMT, &t); if (!n) return NULL;
        n->a = parse_expr(p);
        return n;
    }
}

static void skip_nested_block(parser *p)
{
    int braces = 0;
    if (!at(p, T_LBRACE)) return;
    do {
        if (at(p, T_LBRACE)) braces++;
        else if (at(p, T_RBRACE)) braces--;
        advance(p);
    } while (braces > 0 && !at(p, T_EOF));
}

static axi_node *parse_block(parser *p)
{
    axi_node *blk = nnew_at(p, N_BLOCK, &p->cur); if (!blk) return NULL;
    axi_node **tail = NULL;
    /* Refuse before AST consumers inherit attacker-controlled recursion.
     * INV-287 / AXI-INV-082. */
    if (p->block_depth >= P_MAX_DEPTH) {
        diag_here(p, "AXI-P009", "statement blocks nest deeper than 64",
                  "flatten the control flow into named cells");
        skip_nested_block(p);
        return blk;
    }
    if (!expect(p, T_LBRACE, "AXI-P005", "'{'", "open the body block")) {
        sync_to(p, stmt_sync, 5);
        return blk;
    }
    p->block_depth++;
    while (!p->oom && !at(p, T_RBRACE) && !at(p, T_EOF)) {
        int before = p->ds->n;
        const char *before_token = p->cur.start;
        list_push(blk, &tail, parse_stmt(p));
        if (p->oom) break;
        if (p->ds->n > before)
            sync_to(p, stmt_sync, 5); /* panic-mode: realign on stmt start */
        if (p->cur.start == before_token && !at(p, T_EOF)) advance(p);
    }
    if (p->oom) { p->block_depth--; return NULL; }
    blk->ival = p->cur.line; /* '}' line — W05 flushes comments up to here */
    expect(p, T_RBRACE, "AXI-P005", "'}'", "close the body block");
    p->block_depth--;
    return blk;
}

/* ---- cell & unit ---------------------------------------------------------- */

static axi_node *parse_cell(parser *p)
{
    axi_node *cell = nnew_at(p, N_CELL, &p->cur); if (!cell) return NULL;
    axi_node **tail = NULL;
    int have_fuel = 0, have_pure = 0, have_cap = 0, have_uses = 0;
    advance(p); /* 'cell' */
    if (at(p, T_ID)) { cell->lex = p->cur.start; cell->lexlen = p->cur.len; advance(p); }
    else diag_here(p, "AXI-P001", "expected cell name",
                   "cell name : fn(...) -> type");
    expect(p, T_COLON, "AXI-P001", "':' after cell name",
           "cell name : fn(...) -> type");
    cell->a = parse_sig(p);
    for (;;) {
        if (at(p, T_FUEL)) {
            axi_node *m = nnew_at(p, N_FUEL, &p->cur); if (!m) return NULL;
            advance(p);
            if (at(p, T_INT)) { m->ival = p->cur.ival; advance(p); }
            else diag_here(p, "AXI-P003", "fuel expects an integer",
                           "fuel 10_000");
            if (have_fuel)
                diag_ptr(p, "AXI-P007", m->pos, 4,
                         "duplicate fuel meta", "keep exactly one");
            have_fuel = 1;
            list_push(cell, &tail, m);
        } else if (at(p, T_PURE)) {
            axi_node *m = nnew_at(p, N_PURE, &p->cur); if (!m) return NULL;
            if (have_pure)
                diag_ptr(p, "AXI-P007", m->pos, 4,
                         "duplicate pure meta", "keep exactly one");
            have_pure = 1;
            advance(p);
            list_push(cell, &tail, m);
        } else if (at(p, T_CAP)) {
            axi_token t = p->cur;
            advance(p);
            if (have_cap)
                diag_ptr(p, "AXI-P007", t.start, 3,
                         "duplicate cap meta", "keep exactly one");
            have_cap = 1;
            list_push(cell, &tail, parse_cap_list(p, N_CAP));
        } else if (at(p, T_USES)) {
            axi_token t = p->cur;
            advance(p);
            if (have_uses)
                diag_ptr(p, "AXI-P007", t.start, 4,
                         "duplicate uses meta", "keep exactly one");
            have_uses = 1;
            list_push(cell, &tail, parse_cap_list(p, N_USES));
        } else break;
    }
    if (!have_fuel)
        diag_ptr(p, "AXI-P008", cell->pos, 4,
                 "cell has no fuel budget (G5: fuel is syntax)",
                 "add a `fuel N` line after the signature");
    cell->b = parse_block(p);

    return cell;
}

/* policy = "policy" ID ":" sig { cap | fuel } block [ proof ] */
static axi_node *parse_policy(parser *p)
{
    axi_node *cell = nnew_at(p, N_POLICY, &p->cur); if (!cell) return NULL;
    axi_node **tail = NULL;
    int have_fuel = 0, have_cap = 0;
    advance(p); /* 'policy' */
    if (at(p, T_ID)) { cell->lex = p->cur.start; cell->lexlen = p->cur.len; advance(p); }
    else diag_here(p, "AXI-P001", "expected policy cell name",
                   "policy name : fn(...) -> type");
    expect(p, T_COLON, "AXI-P001", "':' after policy name",
           "policy name : fn(...) -> type");
    cell->a = parse_sig(p);
    for (;;) {
        if (at(p, T_FUEL)) {
            axi_node *m = nnew_at(p, N_FUEL, &p->cur); if (!m) return NULL;
            advance(p);
            if (at(p, T_INT)) { m->ival = p->cur.ival; advance(p); }
            else diag_here(p, "AXI-P003", "fuel expects an integer",
                           "fuel 500_000");
            if (have_fuel)
                diag_ptr(p, "AXI-P007", m->pos, 4,
                         "duplicate fuel meta", "keep exactly one");
            have_fuel = 1;
            list_push(cell, &tail, m);
        } else if (at(p, T_CAP)) {
            axi_token t = p->cur;
            advance(p);
            if (have_cap)
                diag_ptr(p, "AXI-P007", t.start, 3,
                         "duplicate cap meta", "keep exactly one");
            have_cap = 1;
            list_push(cell, &tail, parse_cap_list(p, N_CAP));
        } else if (at(p, T_PURE)) {
            /* P021 deferred to type checker so the AST stays complete */
            axi_node *m = nnew_at(p, N_PURE, &p->cur); if (!m) return NULL;
            advance(p);
            list_push(cell, &tail, m);
        } else if (at(p, T_USES)) {
            /* P020 deferred to type checker */
            advance(p);
            list_push(cell, &tail, parse_cap_list(p, N_USES));
        } else break;
    }
    if (!have_fuel) {
        /* policy has a default fuel (ADR-008), synthesize a node */
        axi_node *m = nnew_at(p, N_FUEL, &p->cur); if (!m) return NULL;
        m->ival = 500000;
        list_push(cell, &tail, m);
    }
    cell->b = parse_block(p);

    /* W12: proof { law* } — laws are bare bool expressions, one per line.
     * No let, no if, no effects: a law is a closed fact, not a program.
     * The block is optional HERE (grammar) — sealing without it is the
     * type/seal layer's refusal (AXI-S001), so the parser stays total. */
    if (at(p, T_PROOF)) {
        axi_node *proof = nnew_at(p, N_BLOCK, &p->cur); if (!proof) return NULL;
        axi_node **ptail = &proof->list;
        advance(p);
        expect(p, T_LBRACE, "AXI-P001", "`{`", "proof opens with `{`");
        while (!p->oom && !at(p, T_RBRACE) && !at(p, T_EOF)) {
            if (at(p, T_LET) || at(p, T_IF) || at(p, T_RET)) {
                static const axi_tok_kind proof_sync[] = { T_RBRACE };
                diag_here(p, "AXI-P010",
                          "a law is a bare bool expression",
                          "proof states facts, it does not compute: "
                          "move logic into a pure cell and call it");
                sync_to(p, proof_sync, 1);
                break;
            }
            {
                axi_node *law = nnew_at(p, N_EXPRSTMT, &p->cur); if (!law) return NULL;
                law->a = parse_expr(p);
                list_push(proof, &ptail, law);
            }
        }
        expect(p, T_RBRACE, "AXI-P001", "`}`",
               "close the proof block with `}`");
        cell->c = proof;
    }
    return cell;
}

/* eff_decl = ".eff" cap_path ; module-level authority declaration */
static axi_node *parse_eff(parser *p)
{
    axi_token t = p->cur;
    axi_node *eff = nnew_at(p, N_EFF, &t); if (!eff) return NULL;
    advance(p); /* '.' */
    if (at(p, T_ID) && p->cur.len == 3 && memcmp(p->cur.start, "eff", 3) == 0) {
        advance(p); /* 'eff' */
        if (at(p, T_ID)) {
            eff->a = parse_path(p, N_ID);
        } else {
            diag_here(p, "AXI-P001", "expected effect name after '.eff'",
                      "spell it: .eff Name.Verb");
        }
    } else {
        diag_here(p, "AXI-P002",
                  "only .eff declarations, cells and policies live at top level (G7)",
                  "wrap code in a cell; nothing executes outside one");
        if (!at(p, T_CELL) && !at(p, T_POLICY) && !at(p, T_EOF))
            advance(p);
    }
    return eff;
}

axi_node *axi_parse_unit(const char *src, size_t len, const char *path,
                         axi_diags *diags)
{
    return axi_parse_unit_budget(src, len, path, diags, NULL);
}

axi_node *axi_parse_unit_budget(const char *src, size_t len, const char *path,
                                axi_diags *diags, axi_compile_budget *budget)
{
    parser p;
    /* W16: even the unit's position is a token's, not a literal — byte 0,
     * line 1, col 1, all from one place (AXI-INV-027). */
    axi_token u0;
    axi_node *unit;
    if (!src || !diags || !axi_compile_reserve(budget, sizeof p)) {
        if (diags) axi_diag_add(diags, axi_compile_failure_code(budget),
            0, 0, 0, "parser workspace unavailable", "increase the compiler budget");
        return NULL;
    }
    memset(&u0, 0, sizeof u0);
    u0.kind = T_EOF; u0.line = 1; u0.col = 1; u0.start = src; u0.len = 0;
    memset(&p, 0, sizeof p);
    p.budget = budget;
    unit = nnew_at(&p, N_UNIT, &u0);
    axi_node **tail = NULL;
    (void)path;
    p.ds = diags; p.depth = 0; p.block_depth = 0;
    p.expr_operators = 0; p.last_error = NULL;
    axi_lex_init(&p.lx, src, len, diags);
    if (!p.oom) advance(&p);
    while (!p.oom && !at(&p, T_EOF)) {
        if (at(&p, T_CELL)) {
            list_push(unit, &tail, parse_cell(&p));
        } else if (at(&p, T_POLICY)) {
            list_push(unit, &tail, parse_policy(&p));
        } else if (at(&p, T_DOT)) {
            list_push(unit, &tail, parse_eff(&p));
        } else {
            diag_here(&p, "AXI-P002",
                      "only .eff declarations, cells and policies live at top level (G7)",
                      "wrap code in a cell; nothing executes outside one");
            {
                const axi_tok_kind sync[] = { T_CELL, T_POLICY, T_DOT };
                advance(&p);
                sync_to(&p, sync, 3);
            }
        }
    }
    if (p.oom) {
        parsed_node *allocated = p.allocated;
        while (allocated) {
            parsed_node *next = allocated->next;
            (void)axi_compile_free(budget, allocated);
            allocated = next;
        }
        axi_diag_add(diags, budget ? axi_compile_failure_code(budget) : "AXI-D999", 0, 0, 0,
                     "parser allocation failed; no tree was published",
                     "retry with enough memory to parse the source");
        (void)axi_compile_release(budget, sizeof p);
        return NULL;
    }
    (void)axi_compile_release(budget, sizeof p);
    return unit;
}

/* INV-309 / AXI-INV-096: fixed children are depth-bounded by the parser, but
 * sibling lists may be large. Recurse through children and iterate siblings so
 * releasing a wide valid unit does not turn ownership cleanup into stack use. */
void axi_ast_free(axi_node *n)
{
    while (n) {
        axi_node *next = n->next;
        axi_ast_free(n->a);
        axi_ast_free(n->b);
        axi_ast_free(n->c);
        axi_ast_free(n->list);
        (void)axi_compile_free(n->budget, n);
        n = next;
    }
}

/* ---- dump (golden format: stable, grep-friendly) -------------------------- */

static const char *op_str(axi_tok_kind k)
{
    switch (k) {
    case T_EQ: return "=="; case T_NE: return "!=";
    case T_LT: return "<";  case T_LE: return "<=";
    case T_GT: return ">";  case T_GE: return ">=";
    case T_PLUS: return "+"; case T_MINUS: return "-";
    case T_STAR: return "*"; case T_SLASH: return "/";
    case T_PERCENT: return "%"; case T_BANG: return "!";
    default: return "?op";
    }
}

static void ind(int n) { while (n-- > 0) fputc(' ', AXI_OUT); }

static void dump_list(const axi_node *first, int indent)
{
    const axi_node *k;
    for (k = first; k; k = k->next) axi_ast_dump(k, indent);
}

void axi_ast_dump(const axi_node *n, int indent)
{
    if (!n) return;
    ind(indent);
    switch (n->kind) {
    case N_UNIT:
        printf("(unit\n"); dump_list(n->list, indent + 2);
        ind(indent); printf(")\n"); return;
    case N_CELL:
        printf("(cell %.*s @%u:%u\n", (int)n->lexlen, n->lex ? n->lex : "",
               n->line, n->col);
        axi_ast_dump(n->a, indent + 2);
        dump_list(n->list, indent + 2);
        axi_ast_dump(n->b, indent + 2);
        if (n->c) {
            ind(indent + 2); printf("(proof\n");
            dump_list(n->c->list, indent + 4);
            ind(indent + 2); printf(")\n");
        }
        ind(indent); printf(")\n"); return;
    case N_SIG:
        printf("(sig\n"); dump_list(n->list, indent + 2);
        axi_ast_dump(n->b, indent + 2);
        ind(indent); printf(")\n"); return;
    case N_PARAM:
        printf("(param %.*s\n", (int)n->lexlen, n->lex ? n->lex : "");
        axi_ast_dump(n->a, indent + 2);
        ind(indent); printf(")\n"); return;
    case N_TYPE:
        printf("(type%s %.*s @%u:%u)\n", n->ival ? " cap" : "",
               (int)n->lexlen, n->lex ? n->lex : "", n->line, n->col);
        return;
    case N_OKT:  printf("(ok-t @%u:%u)\n", n->line, n->col); return;
    case N_ERRT:
        printf("(err-t %.*s @%u:%u)\n", (int)n->lexlen, n->lex ? n->lex : "",
               n->line, n->col);
        return;
    case N_FUEL:
        printf("(fuel %llu @%u:%u)\n", (unsigned long long)n->ival,
               n->line, n->col);
        return;
    case N_PURE: printf("(pure @%u:%u)\n", n->line, n->col); return;
    case N_USES:
        printf("(uses @%u:%u\n", n->line, n->col);
        dump_list(n->list, indent + 2);
        ind(indent); printf(")\n"); return;
    case N_CAP:
        printf("(cap @%u:%u\n", n->line, n->col);
        dump_list(n->list, indent + 2);
        ind(indent); printf(")\n"); return;
    case N_EFF:
        printf("(.eff %.*s @%u:%u)\n",
               (int)(n->a ? n->a->lexlen : 0),
               n->a ? n->a->lex : "",
               n->line, n->col); return;
    case N_POLICY:
        printf("(policy %.*s @%u:%u\n", (int)n->lexlen, n->lex ? n->lex : "",
               n->line, n->col);
        axi_ast_dump(n->a, indent + 2);
        dump_list(n->list, indent + 2);
        axi_ast_dump(n->b, indent + 2);
        if (n->c) {
            ind(indent + 2); printf("(proof\n");
            dump_list(n->c->list, indent + 4);
            ind(indent + 2); printf(")\n");
        }
        ind(indent); printf(")\n"); return;
    case N_BLOCK:
        printf("(block @%u:%u\n", n->line, n->col);
        dump_list(n->list, indent + 2);
        ind(indent); printf(")\n"); return;
    case N_LET:
        printf("(let %.*s @%u:%u\n", (int)n->lexlen, n->lex ? n->lex : "",
               n->line, n->col);
        axi_ast_dump(n->a, indent + 2);
        ind(indent); printf(")\n"); return;
    case N_RET:
        printf("(ret @%u:%u\n", n->line, n->col);
        axi_ast_dump(n->a, indent + 2);
        ind(indent); printf(")\n"); return;
    case N_IF:
        printf("(if @%u:%u\n", n->line, n->col);
        axi_ast_dump(n->a, indent + 2);
        axi_ast_dump(n->b, indent + 2);
        if (n->c) { ind(indent + 2); printf("(else\n");
                    axi_ast_dump(n->c, indent + 4);
                    ind(indent + 2); printf(")\n"); }
        ind(indent); printf(")\n"); return;
    case N_EXPRSTMT:
        printf("(stmt\n"); axi_ast_dump(n->a, indent + 2);
        ind(indent); printf(")\n"); return;
    case N_INT:
        printf("(int %llu @%u:%u)\n", (unsigned long long)n->ival,
               n->line, n->col);
        return;
    case N_FLOAT: printf("(float %.17g @%u:%u)\n", n->fval, n->line, n->col);
        return;
    case N_STR:
        printf("(str %.*s @%u:%u)\n", (int)n->lexlen, n->lex ? n->lex : "",
               n->line, n->col);
        return;
    case N_TRUE:  printf("(true @%u:%u)\n", n->line, n->col);  return;
    case N_FALSE: printf("(false @%u:%u)\n", n->line, n->col); return;
    case N_OK:    printf("(ok @%u:%u)\n", n->line, n->col);    return;
    case N_ID:
        printf("(id %.*s @%u:%u)\n", (int)n->lexlen, n->lex ? n->lex : "",
               n->line, n->col);
        return;
    case N_BIN:
        printf("(bin %s @%u:%u\n", op_str(n->op), n->line, n->col);
        axi_ast_dump(n->a, indent + 2);
        axi_ast_dump(n->b, indent + 2);
        ind(indent); printf(")\n"); return;
    case N_UN:
        printf("(un %s @%u:%u\n", op_str(n->op), n->line, n->col);
        axi_ast_dump(n->a, indent + 2);
        ind(indent); printf(")\n"); return;
    case N_CALL:
        printf("(call @%u:%u\n", n->line, n->col);
        axi_ast_dump(n->a, indent + 2);
        dump_list(n->list, indent + 2);
        ind(indent); printf(")\n"); return;
    case N_INDEX:
        printf("(index @%u:%u\n", n->line, n->col);
        axi_ast_dump(n->a, indent + 2);
        axi_ast_dump(n->b, indent + 2);
        ind(indent); printf(")\n"); return;
    case N_FIELD:
        printf("(field %.*s @%u:%u\n", (int)n->lexlen, n->lex ? n->lex : "",
               n->line, n->col);
        axi_ast_dump(n->a, indent + 2);
        ind(indent); printf(")\n"); return;
    case N_TRY:
        printf("(try @%u:%u\n", n->line, n->col);
        axi_ast_dump(n->a, indent + 2);
        ind(indent); printf(")\n"); return;
    case N_LIST:
        printf("(list @%u:%u\n", n->line, n->col);
        dump_list(n->list, indent + 2);
        ind(indent); printf(")\n"); return;
    }
    printf("(?node)\n");
}
