/* axial — canonical form renderer (W05). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * G2: the canonical output is DERIVABLE FROM THE GRAMMAR. This file is the
 * formatter with no opinions: AST in, the one true text out. `axi check`
 * byte-compares source against this render; every divergence is an
 * AXI-C0xx diagnostic whose fix IS the canonical text (§4 of the SPEC).
 *
 * Laws implemented here (SPEC-GRAMMAR §4, extended in W05):
 *  - sig on the cell line; metas (fuel, then pure) indent 2, one per line;
 *    body braces in column 1; body indent 2; nested indent +2.
 *  - one space around binary ops; none before , : ? ( [ ; one after , : .
 *  - integers: `_` every 3 digits iff ≥ 5 digits; forbidden below (G1).
 *  - floats: shortest round-trip decimal; always with '.' or exponent.
 *  - one stmt per line; single-stmt else-less `if` is inline (the blessed
 *    exemplar form); zero blank lines inside bodies; exactly one blank
 *    line between cells; comments live on their own line, at the indent
 *    of the point they precede; parens only where precedence demands.
 *  - minimal parens: redundant grouping is not canonical.
 */
#include "axi.h"
#include "axi_ast.h"
#include "axi_alloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CANON_TRIV_MAX 512

/* ---- string builder ------------------------------------------------------ */

typedef struct {
    char  *p;
    size_t n, cap;
    int failed;
} sb;

static void sb_grow(sb *b, size_t need)
{
    size_t cap;
    char *p;
    if (b->failed) return;
    if (need > (size_t)-1 - b->n - 1) { b->failed = 1; return; }
    if (b->n + need + 1 <= b->cap) return;
    cap = b->cap ? b->cap : 1024;
    while (b->n + need + 1 > cap) {
        if (cap > (size_t)-1 / 2) { b->failed = 1; return; }
        cap *= 2;
    }
    p = (char *)axi_realloc(b->p, cap);
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

static void sb_indent(sb *b, int ind)
{
    int i;
    for (i = 0; i < ind; i++) sb_ch(b, ' ');
}

/* ---- literals ------------------------------------------------------------ */

/* `_` every 3 digits iff ≥5 digits — one spelling per number (G1). */
static void sb_int(sb *b, uint64_t v)
{
    char digits[21];
    int nd = 0, i;
    if (v == 0) { sb_ch(b, '0'); return; }
    while (v > 0) { digits[nd++] = (char)('0' + (int)(v % 10u)); v /= 10u; }
    for (i = nd - 1; i >= 0; i--) {
        sb_ch(b, digits[i]);
        if (nd >= 5 && i > 0 && i % 3 == 0) sb_ch(b, '_');
    }
}

/* AXI-INV-025: the same spelling, for surfaces outside this file (iface). */
void axi_canon_int_str(uint64_t v, char *out, size_t cap)
{
    sb b;
    if (!out || cap == 0) return;
    if (cap < 32) { out[0] = '\0'; return; }
    b.p = out; b.n = 0; b.cap = cap; b.failed = 0;
    sb_int(&b, v);
    if (b.failed) out[0] = '\0';
}

/* AXI-INV-025 (JSON face): JSON's grammar has no `_` in numbers, so the
 * machine projection needs plain digits. That is a different GRAMMAR, not a
 * different AUTHORITY: both spellings are minted here, and no other file
 * owns a digit loop. A caller that wants digits asks; it never counts. */
void axi_canon_int_json(uint64_t v, char *out, size_t cap)
{
    if (!out || cap == 0) return;
    if (snprintf(out, cap, "%llu", (unsigned long long)v) < 0) out[0] = '\0';
}

/* shortest decimal that round-trips (the one true float spelling) */
static void sb_float(sb *b, double f)
{
    char tmp[64];
    int prec;
    for (prec = 1; prec <= 17; prec++) {
        snprintf(tmp, sizeof tmp, "%.*g", prec, f);
        if (strtod(tmp, NULL) == f) break;
    }
    sb_str(b, tmp);
    if (!strpbrk(tmp, ".eE")) sb_str(b, ".0"); /* 2 → 2.0: floats look float */
}

/* ---- trivia (comments) --------------------------------------------------- */

typedef struct {
    axi_trivia tv[CANON_TRIV_MAX];
    int        n, i;      /* count, cursor */
    int        dropped;
} triv_ctx;

/* Re-lex purely to harvest comments; parse already validated the stream. */
static void triv_collect(triv_ctx *tc, const char *src, size_t len)
{
    axi_lexer lx;
    axi_diags scratch;
    axi_token t;
    axi_diags_init(&scratch);
    axi_lex_init(&lx, src, len, &scratch);
    lx.triv = tc->tv;
    lx.triv_cap = CANON_TRIV_MAX;
    do { axi_lex_next(&lx, &t); } while (t.kind != T_EOF);
    tc->n = lx.triv_n;
    tc->i = 0;
    tc->dropped = lx.triv_dropped;
}

/* Emit every comment that lives strictly before `line`, one per line,
 * at the given indent. Trailing comments are hoisted onto their own
 * line here — that hoist IS their canonical fix. */
static void triv_flush(sb *b, triv_ctx *tc, uint32_t line, int ind)
{
    while (tc->i < tc->n && tc->tv[tc->i].line < line) {
        sb_indent(b, ind);
        sb_put(b, tc->tv[tc->i].start, tc->tv[tc->i].len);
        sb_ch(b, '\n');
        tc->i++;
    }
}

static int triv_pending_before(const triv_ctx *tc, uint32_t line)
{
    return tc->i < tc->n && tc->tv[tc->i].line < line;
}

/* ---- expressions ---------------------------------------------------------- */

/* precedence mirror of the parser: cmp(1) < add(2) < mul(3) < un(4) <
 * postfix(5) < atom(6). Parens appear exactly when a child sits below
 * the level its slot demands. */
static int expr_lev(const axi_node *n)
{
    switch (n->kind) {
    case N_BIN:
        switch (n->op) {
        case T_EQ: case T_NE: case T_LT: case T_LE: case T_GT: case T_GE:
            return 1;
        case T_PLUS: case T_MINUS:
            return 2;
        default: /* T_STAR, T_SLASH, T_PERCENT */
            return 3;
        }
    case N_UN:    return 4;
    case N_CALL: case N_INDEX: case N_FIELD: case N_TRY:
        return 5;
    default:
        return 6;
    }
}

static const char *op_text(axi_tok_kind k)
{
    switch (k) {
    case T_EQ: return "=="; case T_NE: return "!=";
    case T_LT: return "<";  case T_LE: return "<=";
    case T_GT: return ">";  case T_GE: return ">=";
    case T_PLUS: return "+"; case T_MINUS: return "-";
    case T_STAR: return "*"; case T_SLASH: return "/";
    case T_PERCENT: return "%"; case T_BANG: return "!";
    default: return "?op?";
    }
}

static void render_expr(sb *b, const axi_node *n, int min_lev);

static void render_lex(sb *b, const axi_node *n)
{
    if (n->lex && n->lexlen) sb_put(b, n->lex, n->lexlen);
}

static void render_expr_naked(sb *b, const axi_node *n)
{
    const axi_node *k;
    switch (n->kind) {
    case N_INT:   sb_int(b, n->ival); return;
    case N_FLOAT: sb_float(b, n->fval); return;
    case N_STR:   render_lex(b, n); return; /* slice keeps quotes+escapes */
    case N_TRUE:  sb_str(b, "true");  return;
    case N_FALSE: sb_str(b, "false"); return;
    case N_OK:    sb_str(b, "ok");    return;
    case N_ERRT:  sb_str(b, "err."); render_lex(b, n); return; /* W06 atom */
    case N_ID:    render_lex(b, n);   return;
    case N_LIST:
        sb_ch(b, '[');
        for (k = n->list; k; k = k->next) {
            if (k != n->list) sb_str(b, ", ");
            render_expr(b, k, 1);
        }
        sb_ch(b, ']');
        return;
    case N_BIN: {
        int lev = expr_lev(n);
        render_expr(b, n->a, lev);          /* left-assoc: same level ok   */
        sb_ch(b, ' ');
        sb_str(b, op_text(n->op));
        sb_ch(b, ' ');
        render_expr(b, n->b, lev + 1);      /* right child must sit higher */
        return;
    }
    case N_UN:
        sb_str(b, op_text(n->op));
        render_expr(b, n->a, 4);
        return;
    case N_CALL:
        render_expr(b, n->a, 5);
        sb_ch(b, '(');
        for (k = n->list; k; k = k->next) {
            if (k != n->list) sb_str(b, ", ");
            render_expr(b, k, 1);
        }
        sb_ch(b, ')');
        return;
    case N_INDEX:
        render_expr(b, n->a, 5);
        sb_ch(b, '[');
        render_expr(b, n->b, 1);
        sb_ch(b, ']');
        return;
    case N_FIELD:
        render_expr(b, n->a, 5);
        sb_ch(b, '.');
        render_lex(b, n);
        return;
    case N_TRY:
        render_expr(b, n->a, 5);
        sb_ch(b, '?');
        return;
    default:
        sb_str(b, "?expr?"); /* unreachable on a parse-green tree */
        return;
    }
}

static void render_expr(sb *b, const axi_node *n, int min_lev)
{
    int parens = expr_lev(n) < min_lev;
    if (parens) sb_ch(b, '(');
    render_expr_naked(b, n);
    if (parens) sb_ch(b, ')');
}

/* ---- signature ------------------------------------------------------------ */

static void render_type(sb *b, const axi_node *t)
{
    if (t->ival) sb_str(b, "cap ");
    render_lex(b, t);
}

static void render_sig_line(sb *b, const axi_node *cell, const char *kw)
{
    const axi_node *sig = cell->a;
    const axi_node *k;
    sb_str(b, kw);
    sb_ch(b, ' ');
    render_lex(b, cell);
    sb_str(b, " : fn(");
    if (sig) {
        for (k = sig->list; k; k = k->next) {
            if (k != sig->list) sb_str(b, ", ");
            render_lex(b, k);
            sb_str(b, ": ");
            if (k->a) render_type(b, k->a);
        }
        sb_str(b, ") -> ");
        if (sig->b) {
            for (k = sig->b->list; k; k = k->next) {
                if (k != sig->b->list) sb_str(b, " | ");
                switch (k->kind) {
                case N_OKT:  sb_str(b, "ok"); break;
                case N_ERRT: sb_str(b, "err."); render_lex(b, k); break;
                default:     render_type(b, k); break;
                }
            }
        }
    } else {
        sb_str(b, ") -> ?sig?");
    }
    sb_ch(b, '\n');
}

/* ---- statements & blocks --------------------------------------------------- */

static void render_stmt(sb *b, triv_ctx *tc, const axi_node *s, int ind);

static void render_block_body(sb *b, triv_ctx *tc, const axi_node *blk,
                              int ind)
{
    const axi_node *s;
    for (s = blk->list; s; s = s->next) {
        triv_flush(b, tc, s->line, ind);
        render_stmt(b, tc, s, ind);
    }
    if (blk->ival) /* '}' line recorded by the parser */
        triv_flush(b, tc, (uint32_t)blk->ival, ind);
}

/* one simple statement, no indent, no newline */
static void render_simple_stmt(sb *b, const axi_node *s)
{
    switch (s->kind) {
    case N_LET:
        sb_str(b, "let ");
        render_lex(b, s);
        sb_str(b, " = ");
        render_expr(b, s->a, 1);
        return;
    case N_RET:
        sb_str(b, "ret");
        if (s->a) { sb_ch(b, ' '); render_expr(b, s->a, 1); }
        return;
    case N_EXPRSTMT:
        render_expr(b, s->a, 1);
        return;
    default:
        sb_str(b, "?stmt?");
        return;
    }
}

static int block_stmt_count(const axi_node *blk)
{
    int n = 0;
    const axi_node *s;
    for (s = blk->list; s; s = s->next) n++;
    return n;
}

static void render_stmt(sb *b, triv_ctx *tc, const axi_node *s, int ind)
{
    if (s->kind == N_IF) {
        const axi_node *then_blk = s->b;
        int inline_ok = then_blk
            && block_stmt_count(then_blk) == 1
            && then_blk->list->kind != N_IF
            && !s->c
            && !(then_blk->ival
                 && triv_pending_before(tc, (uint32_t)then_blk->ival));
        sb_indent(b, ind);
        sb_str(b, "if ");
        render_expr(b, s->a, 1);
        if (inline_ok) { /* the blessed exemplar: if n < 2 { ret n } */
            sb_str(b, " { ");
            render_simple_stmt(b, then_blk->list);
            sb_str(b, " }\n");
            return;
        }
        sb_str(b, " {\n");
        if (then_blk) render_block_body(b, tc, then_blk, ind + 2);
        sb_indent(b, ind);
        if (s->c) {
            sb_str(b, "} else {\n");
            render_block_body(b, tc, s->c, ind + 2);
            sb_indent(b, ind);
        }
        sb_str(b, "}\n");
        return;
    }
    sb_indent(b, ind);
    render_simple_stmt(b, s);
    sb_ch(b, '\n');
}

/* ---- cell & unit ----------------------------------------------------------- */

static void render_cap_list(sb *b, const axi_node *list)
{
    const axi_node *k;
    for (k = list->list; k; k = k->next) {
        if (k != list->list) sb_str(b, ", ");
        render_lex(b, k);
    }
}

static void render_cell(sb *b, triv_ctx *tc, const axi_node *cell)
{
    const axi_node *m;
    const char *kw = (cell->kind == N_POLICY) ? "policy" : "cell";
    int is_policy = cell->kind == N_POLICY;
    render_sig_line(b, cell, kw);
    /* metas in grammar order — cap, uses, fuel, then pure — regardless of source */
    for (m = cell->list; m; m = m->next)
        if (m->kind == N_CAP) {
            triv_flush(b, tc, m->line, 2);
            sb_str(b, "  cap ");
            render_cap_list(b, m);
            sb_ch(b, '\n');
        }
    for (m = cell->list; m; m = m->next)
        if (m->kind == N_USES && !is_policy) {
            /* policy cells synthesize uses; only print for normal cells */
            triv_flush(b, tc, m->line, 2);
            sb_str(b, "  uses ");
            render_cap_list(b, m);
            sb_ch(b, '\n');
        }
    for (m = cell->list; m; m = m->next)
        if (m->kind == N_FUEL) {
            triv_flush(b, tc, m->line, 2);
            sb_str(b, "  fuel ");
            sb_int(b, m->ival);
            sb_ch(b, '\n');
        }
    for (m = cell->list; m; m = m->next)
        if (m->kind == N_PURE && !is_policy) {
            triv_flush(b, tc, m->line, 2);
            sb_str(b, "  pure\n");
        }
    if (cell->b) {
        triv_flush(b, tc, cell->b->line, 0);
        sb_str(b, "{\n");
        render_block_body(b, tc, cell->b, 2);
        sb_str(b, "}\n");
    }
    /* W12: proof block — same one-true-form discipline as the body */
    if (cell->c) {
        const axi_node *law;
        triv_flush(b, tc, cell->c->line, 0);
        sb_str(b, "proof {\n");
        for (law = cell->c->list; law; law = law->next) {
            triv_flush(b, tc, law->line, 2);
            sb_str(b, "  ");
            render_expr(b, law->a, 0);
            sb_str(b, "\n");
        }
        sb_str(b, "}\n");
    }
}

/* W15: the interface projection needs law/type text in the one true
 * spelling. Canon OWNS rendering; exporting the two atoms here keeps a
 * single printer in the tree. A second pretty-printer is a second dialect
 * with a delay fuse: it agrees today and drifts on the next operator. */
char *axi_canon_expr_str_fallible(const axi_node *e)
{
    /* INV-383 / AXI-INV-123: library projection refuses OOM; it never exits. */
    sb b = {0, 0, 0, 0};
    sb_grow(&b, 1);
    render_expr(&b, e, 0);
    if (b.failed) { free(b.p); return NULL; }
    return b.p;
}

char *axi_canon_expr_str(const axi_node *e)
{
    char *s = axi_canon_expr_str_fallible(e);
    if (!s) {
        fprintf(AXI_ERR, "AXI-D999 canon: out of memory\n");
        exit(2);
    }
    return s;
}

char *axi_canon_type_str(const axi_node *t)
{
    sb b = {0, 0, 0, 0};
    sb_grow(&b, 1);
    render_type(&b, t);
    if (b.failed) {
        free(b.p);
        fprintf(AXI_ERR, "AXI-D999 canon: out of memory\n");
        exit(2);
    }
    return b.p;
}

char *axi_canon_render(const char *src, size_t len, const axi_node *unit)
{
    sb b = {0, 0, 0, 0};
    triv_ctx tc;
    const axi_node *c;

    triv_collect(&tc, src, len);
    sb_grow(&b, 1); /* guarantee a buffer even for the empty unit */

    for (c = unit->list; c; c = c->next) {
        if (c != unit->list) {
            const axi_node *prev = c;
            /* find previous non-trivia node */
            for (prev = unit->list; prev && prev->next != c; prev = prev->next) {}
            /* .eff declarations stay contiguous; cells separate with a blank line */
            if (!(prev && prev->kind == N_EFF && c->kind == N_EFF))
                sb_ch(&b, '\n'); /* exactly one blank line */
        }
        triv_flush(&b, &tc, c->line, 0);
        if (c->kind == N_EFF) {
            sb_str(&b, ".eff ");
            if (c->a) render_lex(&b, c->a);
            sb_ch(&b, '\n');
        } else {
            render_cell(&b, &tc, c);
        }
    }
    /* file-trailing comments */
    triv_flush(&b, &tc, 0xFFFFFFFFu, 0);
    if (b.failed) {
        free(b.p);
        fprintf(AXI_ERR, "AXI-D999 canon: out of memory\n");
        exit(2);
    }
    /* INV-323 / AXI-INV-105: trivia beyond the cap is a refusal, never a
     * silent drop — the canonical form may not lose a single comment. */
    if (tc.dropped > 0) {
        free(b.p);
        return NULL;
    }
    return b.p;
}
