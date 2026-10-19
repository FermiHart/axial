#include "axi_builtin.h"
/* axial — minimal axial source -> .axs codegen (M3). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 */
#include "axi_codegen.h"
#include "axi_alloc.h"
#include "axi_ast.h"
#include "axi_cap_table.h"
#include "axi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>

#define MAX_BIND 128
#define MAX_CONST 128
#define MAX_BUILTIN 32
#define MAX_EFF 32
#define MAX_REG 64

typedef struct {
    char *buf;
    size_t len, cap;
    int failed;
} outbuf;

typedef struct {
    const char *name;
    uint32_t namelen;
    int reg;
    const char *cap;   /* non-NULL when the binding is a cap parameter: the
                        * capability's own name ("fs.Read"), from the signature */
    uint32_t caplen;
} bind;

typedef struct {
    int tag; /* 0=u64, 1=str, 2=i64, 3=f64 */
    uint64_t u;
    char *s;
    uint32_t slen;
} konst;

typedef struct {
    bind env[MAX_BIND];
    int nenv;
    konst k[MAX_CONST];
    int nk;
    char *builtins[MAX_BUILTIN];
    int nbuiltins;
    char *effs[MAX_EFF];
    int neffs;
    int reg_used[MAX_REG];
    int max_reg;
    int unit_reg;
    int err;
    int oom;
} cg;

static void clear_consts(cg *c)
{
    int i;
    for (i = 0; i < c->nk; i++) {
        if (c->k[i].tag == 1) free(c->k[i].s);
        c->k[i].s = NULL;
        c->k[i].slen = 0;
    }
    c->nk = 0;
}

/* INV-309 / AXI-INV-096: codegen owns constants and interned table names only
 * for the invocation that derives the returned assembly buffer. */
static void cg_free(cg *c)
{
    int i;
    clear_consts(c);
    for (i = 0; i < c->nbuiltins; i++) free(c->builtins[i]);
    for (i = 0; i < c->neffs; i++) free(c->effs[i]);
}

static void ob_init(outbuf *o)
{
    o->buf = axi_malloc(256);
    o->len = 0;
    o->cap = o->buf ? 256 : 0;
    o->failed = o->buf == NULL;
}

static void ob_grow(outbuf *o, size_t need)
{
    char *buf;
    if (o->failed) return;
    if (need > (size_t)-1 - o->len - 1) { o->failed = 1; return; }
    if (o->len + need + 1 <= o->cap) return;
    while (o->len + need + 1 > o->cap) {
        if (o->cap > (size_t)-1 / 2) { o->failed = 1; return; }
        o->cap *= 2;
    }
    buf = axi_realloc(o->buf, o->cap);
    if (!buf) { o->failed = 1; return; }
    o->buf = buf;
}

static void ob_putc(outbuf *o, char c)
{
    ob_grow(o, 1);
    if (o->failed) return;
    o->buf[o->len++] = c;
    o->buf[o->len] = '\0';
}

static void ob_puts(outbuf *o, const char *s)
{
    size_t n = strlen(s);
    ob_grow(o, n);
    if (o->failed) return;
    memcpy(o->buf + o->len, s, n);
    o->len += n;
    o->buf[o->len] = '\0';
}

static void ob_printf(outbuf *o, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char tmp[512];
    int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof tmp) { o->failed = 1; return; }
    ob_grow(o, (size_t)n);
    if (o->failed) return;
    memcpy(o->buf + o->len, tmp, (size_t)n);
    o->len += (size_t)n;
    o->buf[o->len] = '\0';
}

static void ob_indent(outbuf *o, int indent)
{
    for (int i = 0; i < indent; i++) ob_puts(o, "  ");
}

static int alloc_reg(cg *c)
{
    for (int i = 0; i < MAX_REG; i++) {
        if (!c->reg_used[i]) {
            c->reg_used[i] = 1;
            if (i > c->max_reg) c->max_reg = i;
            return i;
        }
    }
    c->err = 1;
    return 0;
}

/* A call window is contiguous and exclusively owned before evaluating any
 * arguments. Picking its first hole and reserving unrelated holes later can
 * overwrite a live binding located in the middle of the supposed window. */
static int alloc_window(cg *c, int argc)
{
    int count = argc > 0 ? argc : 1;
    if (count > MAX_REG) { c->err = 1; return 0; }
    for (int base = 0; base <= MAX_REG - count; base++) {
        int i;
        for (i = 0; i < count && !c->reg_used[base + i]; i++) {}
        if (i != count) { base += i; continue; }
        for (i = 0; i < count; i++) c->reg_used[base + i] = 1;
        if (base + count - 1 > c->max_reg) c->max_reg = base + count - 1;
        return base;
    }
    c->err = 1;
    return 0;
}

static int alloc_unit_reg(cg *c)
{
    if (c->unit_reg >= 0) return c->unit_reg;
    int r = c->max_reg + 1;
    if (r >= MAX_REG) { c->err = 1; return 0; }
    c->reg_used[r] = 1;
    c->max_reg = r;
    c->unit_reg = r;
    return r;
}

static void free_reg(cg *c, int r)
{
    if (r >= 0 && r < MAX_REG && r != c->unit_reg) c->reg_used[r] = 0;
}

static bind *find_bind(cg *c, const char *name, uint32_t len)
{
    for (int i = c->nenv - 1; i >= 0; i--)
        if (c->env[i].namelen == len && memcmp(c->env[i].name, name, len) == 0)
            return &c->env[i];
    return NULL;
}

static void add_bind(cg *c, const char *name, uint32_t len, int reg)
{
    /* INV-314 / AXI-INV-099: saturation is a refusal, never a silent drop. */
    if (c->nenv >= MAX_BIND) { c->err = 1; return; }
    c->env[c->nenv].name = name;
    c->env[c->nenv].namelen = len;
    c->env[c->nenv].reg = reg;
    c->env[c->nenv].cap = NULL;
    c->env[c->nenv].caplen = 0;
    c->nenv++;
}

static int add_k_u64(cg *c, uint64_t v)
{
    for (int i = 0; i < c->nk; i++)
        if (c->k[i].tag == 0 && c->k[i].u == v) return i;
    /* INV-314 / AXI-INV-099: k0 is a real constant (u64 0); returning it for
     * a new value would mint bytecode that lies about the source. */
    if (c->nk >= MAX_CONST) { c->err = 1; return 0; }
    c->k[c->nk].tag = 0;
    c->k[c->nk].u = v;
    c->k[c->nk].s = NULL;
    c->k[c->nk].slen = 0;
    return c->nk++;
}

/* INV-316 / AXI-INV-101: i64/f64 zeros for the canonical -x = 0 - x. */
static int add_k_num(cg *c, int tag, uint64_t bits)
{
    for (int i = 0; i < c->nk; i++)
        if (c->k[i].tag == tag && c->k[i].u == bits) return i;
    if (c->nk >= MAX_CONST) { c->err = 1; return 0; }
    c->k[c->nk].tag = tag;
    c->k[c->nk].u = bits;
    c->k[c->nk].s = NULL;
    c->k[c->nk].slen = 0;
    return c->nk++;
}

/* Strip surrounding quotes and undo the escapes the axial lexer accepts
 * for " and \, so the constant stores the semantic string value. */
static char *unquote_str(const char *s, uint32_t len, uint32_t *outlen)
{
    /* INV-323 / AXI-INV-105: one decoder, one meaning — shared with the
     * assembler through axi_str_unescape. */
    return axi_str_unescape(s, len, outlen);
}

static int add_k_str(cg *c, const char *s, uint32_t len)
{
    uint32_t vlen;
    char *v = unquote_str(s, len, &vlen);
    if (!v) { c->oom = 1; return 0; }
    for (int i = 0; i < c->nk; i++)
        if (c->k[i].tag == 1 && c->k[i].slen == vlen && memcmp(c->k[i].s, v, vlen) == 0) {
            free(v);
            return i;
        }
    if (c->nk >= MAX_CONST) { free(v); c->err = 1; return 0; }
    c->k[c->nk].tag = 1;
    c->k[c->nk].u = 0;
    c->k[c->nk].s = v;
    c->k[c->nk].slen = vlen;
    return c->nk++;
}

static int add_builtin(cg *c, const char *name)
{
    for (int i = 0; i < c->nbuiltins; i++)
        if (strcmp(c->builtins[i], name) == 0) return i;
    if (c->nbuiltins >= MAX_BUILTIN) { c->err = 1; return 0; }
    c->builtins[c->nbuiltins] = axi_strdup(name);
    if (!c->builtins[c->nbuiltins]) { c->oom = 1; return 0; }
    return c->nbuiltins++;
}

static int add_eff(cg *c, const char *name)
{
    for (int i = 0; i < c->neffs; i++)
        if (strcmp(c->effs[i], name) == 0) return i;
    if (c->neffs >= MAX_EFF) { c->err = 1; return 0; }
    c->effs[c->neffs] = axi_strdup(name);
    if (!c->effs[c->neffs]) { c->oom = 1; return 0; }
    return c->neffs++;
}

/* Forward declarations */
static int gen_expr(cg *c, outbuf *o, const axi_node *n, int indent);
static void gen_stmt(cg *c, outbuf *o, const axi_node *n, int indent);
static void gen_block(cg *c, outbuf *o, const axi_node *blk, int indent);

/* Move evaluated arguments into their consecutive call slots.
 * If an argument currently lives inside another argument's slot, copy it to
 * a temporary register first so the later slot move does not clobber it. */
static void emit_arg_moves(cg *c, outbuf *o, int indent,
                           int base, int argc, const int *arg_regs)
{
    int regs[16];
    int tmp[16];
    for (int i = 0; i < argc; i++) { regs[i] = arg_regs[i]; tmp[i] = -1; }
    for (int i = 0; i < argc; i++) {
        if (regs[i] == base + i) continue;
        if (regs[i] >= base && regs[i] < base + argc) {
            int t = alloc_reg(c);
            ob_indent(o, indent);
            ob_printf(o, "mov r%d r%d\n", t, regs[i]);
            tmp[i] = t;
            regs[i] = t;
        }
    }
    for (int i = 0; i < argc; i++) {
        if (regs[i] != base + i) {
            ob_indent(o, indent);
            ob_printf(o, "mov r%d r%d\n", base + i, regs[i]);
        }
    }
    for (int i = 0; i < argc; i++) {
        if (tmp[i] >= 0) free_reg(c, tmp[i]);
    }
}

static int is_builtin_name(const char *name)
{
    return axi_builtin_lookup(name, strlen(name)) != NULL;
}

static void extract_call_name(const axi_node *n, char *name, size_t namesz)
{
    name[0] = '\0';
    if (!n || n->kind != N_CALL || !n->a) return;
    const axi_node *callee = n->a;
    if (callee->kind == N_FIELD && callee->a && callee->a->kind == N_ID &&
        callee->lex && callee->lexlen > 0) {
        size_t bl = callee->a->lexlen, fl = callee->lexlen;
        if (bl + 1 + fl < namesz) {
            memcpy(name, callee->a->lex, bl);
            name[bl] = '.';
            memcpy(name + bl + 1, callee->lex, fl);
            name[bl + 1 + fl] = '\0';
        }
    } else if (callee->kind == N_ID && callee->lex) {
        size_t l = callee->lexlen;
        if (l < namesz) {
            memcpy(name, callee->lex, l);
            name[l] = '\0';
        }
    }
}

static void collect_builtins(cg *c, const axi_node *n)
{
    if (!n) return;
    if (n->kind == N_CALL) {
        char name[80];
        extract_call_name(n, name, sizeof name);
        if (name[0] && is_builtin_name(name))
            (void)add_builtin(c, name);
    }
    collect_builtins(c, n->a);
    collect_builtins(c, n->b);
    collect_builtins(c, n->c);
    collect_builtins(c, n->list);
    collect_builtins(c, n->next);
}

/* The call is a cap method iff the base is a bound cap parameter. Binding
 * identity comes from the cell signature, never from the field name — a local
 * called `fs` must not become a capability by accident. */
static int callee_is_cap_method(cg *c, const axi_node *n)
{
    const axi_node *callee;
    bind *b;
    if (!n || n->kind != N_CALL || !n->a) return 0;
    callee = n->a;
    if (callee->kind != N_FIELD || !callee->a
            || callee->a->kind != N_ID || !callee->lex)
        return 0;
    b = find_bind(c, callee->a->lex, callee->a->lexlen);
    return b && b->cap != NULL;
}

static const char *bin_op_name(axi_tok_kind op)
{
    switch (op) {
    case T_PLUS: return "add";
    case T_MINUS: return "sub";
    case T_STAR: return "mul";
    case T_SLASH: return "div";
    case T_PERCENT: return "mod";
    case T_EQ: return "eq";
    case T_LT: return "lt";
    case T_LE: return "le";
    /* INV-316 / AXI-INV-101: no operator falls back to nop. !=, >, >= are
     * canonical expansions handled by gen_expr; anything else is a refusal. */
    default: return NULL;
    }
}

static int gen_expr(cg *c, outbuf *o, const axi_node *n, int indent)
{
    if (!n) {
        int r = alloc_reg(c);
        ob_indent(o, indent);
        ob_printf(o, "ldk r%d k0\n", r);
        return r;
    }
    switch (n->kind) {
    case N_INT: {
        int k = add_k_u64(c, n->ival);
        int r = alloc_reg(c);
        ob_indent(o, indent);
        ob_printf(o, "ldk r%d k%d\n", r, k);
        return r;
    }
    case N_STR: {
        int k = add_k_str(c, n->lex, n->lexlen);
        int r = alloc_reg(c);
        ob_indent(o, indent);
        ob_printf(o, "ldk r%d k%d\n", r, k);
        return r;
    }
    case N_FLOAT: {
        /* f64 constants travel as raw bits; the assembler reads them back as
         * hex, the same spelling the disassembler prints (one round trip). */
        uint64_t bits;
        memcpy(&bits, &n->fval, 8);
        int k = add_k_num(c, 3, bits);
        int r = alloc_reg(c);
        if (c->err || c->oom) return 0;
        ob_indent(o, indent);
        ob_printf(o, "ldk r%d k%d\n", r, k);
        return r;
    }
    case N_TRUE: {
        /* bool true: 0 == 0 produces a VK_BOOL value. */
        int r0 = alloc_reg(c);
        ob_indent(o, indent);
        ob_printf(o, "ldk r%d k0\n", r0);
        int rd = alloc_reg(c);
        ob_indent(o, indent);
        ob_printf(o, "eq r%d r%d r%d\n", rd, r0, r0);
        free_reg(c, r0);
        return rd;
    }
    case N_FALSE: {
        /* bool false: 0 == 1 produces a VK_BOOL value. */
        int r0 = alloc_reg(c);
        int k1 = add_k_u64(c, 1);
        int r1 = alloc_reg(c);
        ob_indent(o, indent);
        ob_printf(o, "ldk r%d k0\n", r0);
        ob_indent(o, indent);
        ob_printf(o, "ldk r%d k%d\n", r1, k1);
        int rd = alloc_reg(c);
        ob_indent(o, indent);
        ob_printf(o, "eq r%d r%d r%d\n", rd, r0, r1);
        free_reg(c, r0); free_reg(c, r1);
        return rd;
    }
    case N_OK: {
        /* INV-389 / AXI-INV-128: `ok` is the unit value. Loading k0 encoded
         * it as u64 zero; reusing a dead register exposed its previous value. */
        int r = alloc_unit_reg(c);
        return r;
    }
    case N_ID: {
        bind *b = find_bind(c, n->lex, n->lexlen);
        if (b) {
            /* Copy bound values so the caller always owns the returned reg.
             * Parameters and lets stay live in their original registers. */
            int r = alloc_reg(c);
            ob_indent(o, indent);
            ob_printf(o, "mov r%d r%d\n", r, b->reg);
            return r;
        }
        c->err = 1;
        return 0;
    }
    case N_BIN: {
        int rl = gen_expr(c, o, n->a, indent);
        int rr = gen_expr(c, o, n->b, indent);
        int rd = alloc_reg(c);
        if (c->err || c->oom) return 0;
        /* INV-316 / AXI-INV-101: canonical expansions, never a nop.
         * a > b  is lt b a;  a >= b is le b a;  a != b is not (eq a b). */
        if (n->op == T_GT || n->op == T_GE) {
            ob_indent(o, indent);
            ob_printf(o, "%s r%d r%d r%d\n",
                      n->op == T_GT ? "lt" : "le", rd, rr, rl);
        } else if (n->op == T_NE) {
            ob_indent(o, indent);
            ob_printf(o, "eq r%d r%d r%d\n", rd, rl, rr);
            ob_indent(o, indent);
            ob_printf(o, "not r%d r%d\n", rd, rd);
        } else {
            const char *opname = bin_op_name(n->op);
            if (!opname) { c->err = 1; return 0; }
            ob_indent(o, indent);
            ob_printf(o, "%s r%d r%d r%d\n", opname, rd, rl, rr);
        }
        free_reg(c, rl); free_reg(c, rr);
        return rd;
    }
    case N_UN: {
        int ra = gen_expr(c, o, n->a, indent);
        int rd = alloc_reg(c);
        if (c->err || c->oom) return 0;
        if (n->op == T_BANG) {
            ob_indent(o, indent);
            ob_printf(o, "not r%d r%d\n", rd, ra);
        } else if (n->op == T_MINUS && n->a->kind == N_INT) {
            /* INV-316 / AXI-INV-101: -<literal> IS an i64 constant (the
             * checker says so); emit the negated bits directly. Wrap is
             * defined: -2^63 is the i64 min bit pattern. */
            int k = add_k_num(c, 2, (uint64_t)(0 - n->a->ival));
            if (c->err) return 0;
            free_reg(c, ra);
            ob_indent(o, indent);
            ob_printf(o, "ldk r%d k%d\n", rd, k);
            return rd;
        } else if (n->op == T_MINUS) {
            /* INV-316 / AXI-INV-101: -x expands to 0 - x with the zero of the
             * kind the checker proved (tyann); never a mov that drops the
             * sign. Without the note there is nothing honest to emit. */
            int kz;
            if (n->tyann == 1)      kz = add_k_num(c, 2, 0);        /* i64 0 */
            else if (n->tyann == 2) kz = add_k_num(c, 3, 0);        /* f64 0.0 */
            else { c->err = 1; return 0; }
            int rz = alloc_reg(c);
            if (c->err) return 0;
            ob_indent(o, indent);
            ob_printf(o, "ldk r%d k%d\n", rz, kz);
            ob_indent(o, indent);
            ob_printf(o, "sub r%d r%d r%d\n", rd, rz, ra);
            free_reg(c, rz);
        } else {
            c->err = 1;
            return 0;
        }
        free_reg(c, ra);
        return rd;
    }
    case N_CALL: {
        char name[80];
        /* INV-315 / AXI-INV-100: a cap method call resolves through the SAME
         * generated table the typechecker and the inference used. The codegen
         * re-derives the answer because bytecode may arrive without source. */
        if (callee_is_cap_method(c, n)) {
            const axi_node *callee = n->a;
            bind *b = find_bind(c, callee->a->lex, callee->a->lexlen);
            axi_cap_kind kind = axi_cap_kind_by_name(b->cap, b->caplen);
            const axi_cap_method *m =
                axi_cap_method_find(kind, callee->lex, callee->lexlen);
            int argc = 0;
            for (const axi_node *arg = n->list; arg; arg = arg->next) argc++;
            if (!m || argc != 1) { c->err = 1; return 0; }
            int eidx = add_eff(c, m->effect);
            if (c->oom || c->err) return 0;
            int r_arg = gen_expr(c, o, n->list, indent);
            int rd = alloc_reg(c);
            ob_indent(o, indent);
            ob_printf(o, "eff r%d @%s r%d\n", rd, c->effs[eidx], r_arg);
            free_reg(c, r_arg);
            return rd;
        }
        extract_call_name(n, name, sizeof name);
        if (name[0] && is_builtin_name(name)) {
            int bidx = add_builtin(c, name);
            if (c->oom || c->err) return 0;
            int base;
            const axi_node *args[16];
            int arg_regs[16] = {0};
            int argc = 0;
            for (const axi_node *arg = n->list; arg; arg = arg->next) {
                /* INV-321 / AXI-INV-103: the v0 window is 16 args; the 17th
                 * is a refusal, never a silent drop (the typechecker refuses
                 * the declaration first; this is the last door). */
                if (argc >= 16) { c->err = 1; return 0; }
                args[argc++] = arg;
            }
            base = alloc_window(c, argc);
            if (c->err) return 0;
            for (int i = 0; i < argc; i++)
                arg_regs[i] = gen_expr(c, o, args[i], indent);
            if (c->err || c->oom) return 0;
            emit_arg_moves(c, o, indent, base, argc, arg_regs);
            for (int i = 0; i < argc; i++) free_reg(c, arg_regs[i]);
            int rd = alloc_reg(c);
            if (c->err || c->oom) return 0;
            ob_indent(o, indent);
            ob_printf(o, "builtin r%d @%s r%d\n", rd, c->builtins[bidx], base);
            for (int i = 0; i < (argc ? argc : 1); i++) free_reg(c, base + i);
            /* INV-321 / AXI-INV-103: rd stays live — the caller frees it
             * after the last use, never before. */
            return rd;
        }
        /* Cell call */
        if (n->a && n->a->kind == N_ID && n->a->lex) {
            const axi_node *callee = n->a;
            int base;
            const axi_node *args[16];
            int arg_regs[16] = {0};
            int argc = 0;
            for (const axi_node *arg = n->list; arg; arg = arg->next) {
                if (argc >= 16) { c->err = 1; return 0; }  /* INV-321 */
                args[argc++] = arg;
            }
            base = alloc_window(c, argc);
            if (c->err) return 0;
            for (int i = 0; i < argc; i++)
                arg_regs[i] = gen_expr(c, o, args[i], indent);
            if (c->err || c->oom) return 0;
            emit_arg_moves(c, o, indent, base, argc, arg_regs);
            for (int i = 0; i < argc; i++) free_reg(c, arg_regs[i]);
            int rd = base; /* VM places callee return value at the base reg. */
            if (c->err || c->oom) return 0;
            ob_indent(o, indent);
            ob_printf(o, "call r%d @%.*s %d\n", rd, (int)callee->lexlen, callee->lex, argc);
            for (int i = 1; i < argc; i++) free_reg(c, base + i);
            /* INV-321 / AXI-INV-103: rd (the callee's answer) stays live
             * until the caller's last use; freeing it here let the NEXT call
             * reuse the slot and clobber the value still being read. */
            return rd;
        }
        c->err = 1;
        return 0;
    }
    default:
        c->err = 1;
        return 0;
    }
}

static void gen_block(cg *c, outbuf *o, const axi_node *blk, int indent)
{
    if (!blk) return;
    /* INV-319 / AXI-INV-102: the same lifetime frontier as the typechecker —
     * bindings born in this block die at its end, and their registers go
     * back to the pool so a later read cannot observe a dead slot. */
    int saved = c->nenv;
    for (const axi_node *s = blk->list; s; s = s->next)
        gen_stmt(c, o, s, indent);
    while (c->nenv > saved) {
        c->nenv--;
        free_reg(c, c->env[c->nenv].reg);
    }
}

/* Count instructions emitted in a text range (one instruction per line). */
static int count_instrs(const char *s, size_t start, size_t end)
{
    int n = 0;
    for (size_t i = start; i < end; i++)
        if (s[i] == '\n') n++;
    return n;
}

static void patch_offset(outbuf *o, size_t pos, int off)
{
    /* The line is "jf rN +0\n" or "jmp +0\n". Find the offset token and
     * overwrite it (sign included) with the new signed offset. */
    size_t i = pos;
    if (o->failed) return;
    while (i < o->len && o->buf[i] != '+' && o->buf[i] != '-') i++;
    if (i >= o->len) return;
    char num[12];
    snprintf(num, sizeof num, "%+d", off);
    size_t oldlen = 0;
    while (i + oldlen < o->len && o->buf[i + oldlen] != '\n' && o->buf[i + oldlen] != ' ') oldlen++;
    int diff = (int)strlen(num) - (int)oldlen;
    if (diff > 0) {
        ob_grow(o, (size_t)diff);
        if (o->failed) return;
    }
    memmove(o->buf + i + strlen(num), o->buf + i + oldlen, o->len - (i + oldlen));
    memcpy(o->buf + i, num, strlen(num));
    if (diff >= 0) o->len += (size_t)diff;
    else o->len -= (size_t)(-diff);
    o->buf[o->len] = '\0';
}

static void gen_stmt(cg *c, outbuf *o, const axi_node *n, int indent)
{
    if (!n) return;
    switch (n->kind) {
    case N_LET: {
        int rt = gen_expr(c, o, n->a, indent);
        int r = alloc_reg(c);
        ob_indent(o, indent);
        ob_printf(o, "mov r%d r%d\n", r, rt);
        add_bind(c, n->lex, n->lexlen, r);
        free_reg(c, rt);
        break;
    }
    case N_RET: {
        int r = gen_expr(c, o, n->a, indent);
        ob_indent(o, indent);
        ob_printf(o, "ret r%d\n", r);
        break;
    }
    case N_IF: {
        int rc = gen_expr(c, o, n->a, indent);
        size_t jf_pos = o->len;
        ob_indent(o, indent);
        ob_printf(o, "jf r%d +0\n", rc);
        free_reg(c, rc);
        size_t then_start = o->len;
        gen_block(c, o, n->b, indent);
        size_t then_end = o->len;
        if (n->c) {
            size_t jmp_pos = o->len;
            ob_indent(o, indent);
            ob_puts(o, "jmp +0\n");
            size_t else_start = o->len;
            gen_block(c, o, n->c, indent);
            size_t else_end = o->len;
            /* Compute both spans before editing the buffer, then patch the
             * later site first. Widening the earlier displacement shifts
             * every saved byte offset after it; a stale jmp_pos can point at
             * the preceding branch's '+' and leave this jmp at +0. */
            int off_else = (int)count_instrs(o->buf, then_start, else_start);
            int off_end = (int)count_instrs(o->buf, else_start, else_end);
            patch_offset(o, jmp_pos, off_end + 1);
            patch_offset(o, jf_pos, off_else + 1);
        } else {
            int off = (int)count_instrs(o->buf, then_start, then_end);
            patch_offset(o, jf_pos, off + 1);
        }
        break;
    }
    case N_EXPRSTMT: {
        int r = gen_expr(c, o, n->a, indent);
        free_reg(c, r);
        break;
    }
    default:
        c->err = 1;
    }
}

static void gen_cell(cg *c, outbuf *o, const axi_node *cell)
{
    /* Reset per-cell state. */
    c->nenv = 0;
    clear_consts(c);
    c->nk = 1;              /* k0 is always zero */
    memset(c->reg_used, 0, sizeof c->reg_used);
    c->max_reg = -1;
    c->unit_reg = -1;

    /* Map params to regs r0..; cap params carry their capability name so a
     * method call on them resolves through the generated table (CA07). */
    int nparam = 0;
    if (cell->a) {
        for (const axi_node *p = cell->a->list; p; p = p->next) {
            add_bind(c, p->lex, p->lexlen, nparam);
            if (c->err) return;
            if (p->a && p->a->ival == 1 && p->a->lex) {
                c->env[c->nenv - 1].cap = p->a->lex;
                c->env[c->nenv - 1].caplen = p->a->lexlen;
            }
            nparam++;
        }
    }
    for (int i = 0; i < nparam && i < MAX_REG; i++) c->reg_used[i] = 1;
    c->max_reg = nparam - 1;

    /* Generate body first so we know constants and reg usage. */
    outbuf body;
    ob_init(&body);
    if (body.failed) c->oom = 1;
    gen_block(c, &body, cell->b, 1);
    if (body.failed) c->oom = 1;

    int nregs = c->max_reg + 1;
    if (nregs < 1) nregs = 1;

    /* Emit cell header with constants used by this cell. */
    ob_printf(o, "cell %.*s nregs=%d\n", (int)cell->lexlen, cell->lex, nregs);
    for (int i = 0; i < c->nk; i++) {
        if (c->k[i].tag == 0) {
            ob_printf(o, "  k%d u64 %llu\n", i, (unsigned long long)c->k[i].u);
        } else if (c->k[i].tag == 2) {
            ob_printf(o, "  k%d i64 %lld\n", i, (long long)(int64_t)c->k[i].u);
        } else if (c->k[i].tag == 3) {
            ob_printf(o, "  k%d f64 %llx\n", i, (unsigned long long)c->k[i].u);
        } else {
            ob_printf(o, "  k%d str \"", i);
            for (uint32_t j = 0; j < c->k[i].slen; j++) {
                if (c->k[i].s[j] == '"' || c->k[i].s[j] == '\\') ob_puts(o, "\\");
                ob_putc(o, (unsigned char)c->k[i].s[j]);
            }
            ob_puts(o, "\"\n");
        }
    }

    /* Append body. */
    ob_grow(o, body.len);
    if (!o->failed && body.len > 0) {
        memcpy(o->buf + o->len, body.buf, body.len);
        o->len += body.len;
        o->buf[o->len] = '\0';
    }
    free(body.buf);

    ob_indent(o, 0);
    ob_puts(o, "end\n");
    clear_consts(c);
}

char *axi_codegen(const axi_node *unit, size_t *out_len)
{
    outbuf o;
    cg c;
    memset(&c, 0, sizeof c);
    ob_init(&o);

    /* k0 is always 0 (unit / false) */
    c.k[0].tag = 0; c.k[0].u = 0; c.nk = 1;

    /* Pass 1: collect declared effects and used builtins. */
    for (const axi_node *n = unit->list; n; n = n->next) {
        if (n->kind == N_EFF && n->a && n->a->lex) {
            char name[128];
            snprintf(name, sizeof name, "%.*s", (int)n->a->lexlen, n->a->lex);
            add_eff(&c, name);
        }
        if (n->kind == N_CELL || n->kind == N_POLICY)
            collect_builtins(&c, n);
    }

    for (int i = 0; i < c.neffs; i++)
        ob_printf(&o, ".eff %s\n", c.effs[i]);
    for (int i = 0; i < c.nbuiltins; i++)
        ob_printf(&o, ".builtin %s\n", c.builtins[i]);
    if (c.neffs || c.nbuiltins) ob_puts(&o, "\n");

    /* Pass 2: emit cells. */
    for (const axi_node *n = unit->list; n; n = n->next) {
        if (n->kind == N_CELL || n->kind == N_POLICY)
            gen_cell(&c, &o, n);
    }

    /* INV-314 / AXI-INV-099: an internal error is a refusal, never an
     * opcode. c->err covers register exhaustion, unbound names, unknown
     * nodes and every saturated table — none of them may reach publish. */
    if (o.failed || c.oom || c.err) {
        free(o.buf);
        cg_free(&c);
        if (out_len) *out_len = 0;
        return NULL;
    }
    if (out_len) *out_len = o.len;
    cg_free(&c);
    return o.buf;
}
