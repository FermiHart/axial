/* axial lexer — ADR-000 §8. Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * Written in the Bear-compatible C subset (dual-built: host cc for the fast
 * loop, bear for the sovereign chain — gate-tc doctrine, INV-199).
 *
 * Progress law: every call to axi_lex_next consumes at least one byte unless
 * at EOF. (Ancestor bug: bear INV-213, __asm__ handler that forgot to
 * consume its keyword and stalled the parser for 25 minutes.)
 */
#include "axi.h"
#include "axi_alloc.h"
#include "axi_string.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ---- keyword table ------------------------------------------------------- */

typedef struct { const char *word; axi_tok_kind kind; } kw_t;

static const kw_t KW[] = {
    { "cell",   T_CELL   }, { "fn",     T_FN     }, { "fuel",  T_FUEL  },
    { "pure",   T_PURE   }, { "uses",   T_USES   }, { "proof", T_PROOF },
    { "let",    T_LET    }, { "if",     T_IF     }, { "else",  T_ELSE  },
    { "loop",   T_LOOP   }, { "break",  T_BREAK  }, { "ret",   T_RET   },
    { "cap",    T_CAP    }, { "opt",    T_OPT    }, { "ok",    T_OK    },
    { "err",    T_ERR    }, { "true",   T_TRUE   }, { "false", T_FALSE },
    { "assert", T_ASSERT }, { "policy", T_POLICY }, { "under", T_UNDER },
    { "u64",    T_U64    }, { "i64",    T_I64    }, { "f64",   T_F64   },
    { "bool",   T_BOOL   }, { "bytes",  T_BYTES  }, { "str",   T_STRTY },
    { "decision", T_DECISION },
};

static const char *TOK_NAMES[T_COUNT] = {
    "EOF", "INT", "FLOAT", "STR", "ID",
    "cell", "fn", "fuel", "pure", "uses", "proof", "let", "if", "else",
    "loop", "break", "ret", "cap", "opt", "ok", "err", "true", "false",
    "assert", "policy", "under",
    "u64", "i64", "f64", "bool", "bytes", "str", "decision",
    "LPAREN", "RPAREN", "LBRACE", "RBRACE", "LBRACK", "RBRACK",
    "COMMA", "COLON", "QUESTION", "PIPE", "ARROW", "DOT",
    "ASSIGN", "EQ", "NE", "LT", "LE", "GT", "GE",
    "PLUS", "MINUS", "STAR", "SLASH", "PERCENT", "BANG",
};

const char *axi_tok_name(axi_tok_kind k)
{
    if ((unsigned)k >= (unsigned)T_COUNT) return "?";
    return TOK_NAMES[k];
}

/* ---- lexer core ----------------------------------------------------------- */

void axi_lex_init(axi_lexer *lx, const char *src, size_t len, axi_diags *ds)
{
    lx->src = src;
    lx->len = len;
    lx->pos = 0;
    lx->line = 1;
    lx->col = 1;
    lx->diags = ds;
    lx->triv = NULL;
    lx->triv_cap = 0;
    lx->triv_n = 0;
    lx->triv_dropped = 0;
    lx->last_tok_line = 0;
}

static int at_end(const axi_lexer *lx) { return lx->pos >= lx->len; }
static char peek(const axi_lexer *lx)
{
    return at_end(lx) ? '\0' : lx->src[lx->pos];
}
static char peek2(const axi_lexer *lx)
{
    return (lx->pos + 1 >= lx->len) ? '\0' : lx->src[lx->pos + 1];
}

/* The ONLY byte-consumer. Line/col updated here and nowhere else
 * (ancestor bug: bear INV-214, col never incremented ⇒ desync). */
static char advance(axi_lexer *lx)
{
    char c;
    if (at_end(lx)) return '\0';
    c = lx->src[lx->pos++];
    if (c == '\n') { lx->line++; lx->col = 1; }
    else           { lx->col++; }
    return c;
}

static int is_digit(char c) { return c >= '0' && c <= '9'; }
static int is_alpha(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}
static int is_alnum(char c) { return is_alpha(c) || is_digit(c); }

static void skip_ws_and_comments(axi_lexer *lx)
{
    for (;;) {
        char c = peek(lx);
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            advance(lx);
        } else if (c == '#') {
            uint32_t cline = lx->line, ccol = lx->col;
            const char *cstart = lx->src + lx->pos;
            while (!at_end(lx) && peek(lx) != '\n') advance(lx);
            if (lx->triv) { /* W05 sink: comments survive for the canon pass */
                if (lx->triv_n < lx->triv_cap) {
                    axi_trivia *tv = &lx->triv[lx->triv_n++];
                    tv->line = cline;
                    tv->col = ccol;
                    tv->start = cstart;
                    tv->len = (uint32_t)((lx->src + lx->pos) - cstart);
                    tv->own_line = (lx->last_tok_line != cline);
                } else {
                    lx->triv_dropped++;
                }
            }
        } else {
            return;
        }
    }
}

static void tok_fill(axi_token *t, axi_tok_kind k,
                     uint32_t line, uint32_t col,
                     const char *start, size_t len)
{
    t->kind = k;
    t->line = line;
    t->col = col;
    t->len = (uint32_t)len;
    t->start = start;
    t->ival = 0;
    t->fval = 0.0;
}

static void lex_number(axi_lexer *lx, axi_token *t,
                       uint32_t line, uint32_t col, const char *start)
{
    uint64_t v = 0;
    int is_float = 0;
    double f = 0.0, scale = 0.1;
    int overflow = 0;

    while (is_digit(peek(lx)) || peek(lx) == '_') {
        char c = advance(lx);
        if (c == '_') continue;
        {
            /* AX30-LEX: comparing the wrapped value to the prefix misses
             * e.g. 30000000000000000000. Consume the whole token, but never
             * perform an overflowing prefix update. */
            uint64_t digit = (uint64_t)(c - '0');
            if (v > (UINT64_MAX - digit) / UINT64_C(10)) overflow = 1;
            if (!overflow) v = v * UINT64_C(10) + digit;
        }
    }
    if (peek(lx) == '.' && is_digit(peek2(lx))) {
        is_float = 1;
        f = (double)v;
        advance(lx); /* '.' */
        while (is_digit(peek(lx)) || peek(lx) == '_') {
            char c = advance(lx);
            if (c == '_') continue;
            f += (double)(c - '0') * scale;
            scale *= 0.1;
        }
    }
    /* trailing junk like 123abc is one diagnostic, consumed (progress law) */
    if (is_alpha(peek(lx))) {
        uint32_t junk_off = (uint32_t)lx->pos;
        while (is_alnum(peek(lx))) advance(lx);
        axi_diag_add_source(lx->diags, "AXI-L004", lx->src, junk_off,
                            (uint32_t)lx->pos - junk_off,
                            "letters directly after a number literal",
                            "separate the number and the identifier with a space");
    }
    if (overflow) {
        axi_diag_add_source(lx->diags, "AXI-L005", lx->src,
                            (uint32_t)(start - lx->src),
                            (uint32_t)((lx->src + lx->pos) - start),
                            "integer literal overflows u64",
                            "u64 max is 18_446_744_073_709_551_615");
    }
    tok_fill(t, is_float ? T_FLOAT : T_INT, line, col,
             start, (size_t)((lx->src + lx->pos) - start));
    if (is_float) t->fval = f; else t->ival = v;
}

static void lex_string(axi_lexer *lx, axi_token *t,
                       uint32_t line, uint32_t col, const char *start)
{
    /* opening quote already consumed */
    for (;;) {
        char c = peek(lx);
        if (at_end(lx) || c == '\n') {
            axi_diag_add_source(lx->diags, "AXI-L002", lx->src,
                                (uint32_t)(start - lx->src),
                                (uint32_t)((lx->src + lx->pos) - start),
                                "unterminated string literal",
                                "close the string with \" before end of line");
            break;
        }
        advance(lx);
        if (c == '"') break;
        if (c == '\\') {
            char e = peek(lx);
            unsigned char decoded;
            if (axi_string_unescape_byte((unsigned char)e, &decoded)) {
                advance(lx);
            } else {
                axi_diag_add_source(lx->diags, "AXI-L003", lx->src,
                                    (uint32_t)lx->pos, 1,
                                    "unknown escape sequence",
                                    "valid escapes: \\n \\t \\\\ \\\" \\0");
                if (!at_end(lx) && e != '\n') advance(lx);
            }
        } else if (((unsigned char)c < 0x20 && c != '\t') || (unsigned char)c == 0x7f) {
            axi_diag_add_source(lx->diags, "AXI-L003", lx->src,
                                (uint32_t)lx->pos - 1, 1,
                                "unescaped control byte in string literal",
                                "use \\n, \\t or \\0; other controls have no source spelling");
        }
    }
    tok_fill(t, T_STR, line, col, start,
             (size_t)((lx->src + lx->pos) - start));
}

static void lex_next_inner(axi_lexer *lx, axi_token *t)
{
    uint32_t line, col;
    const char *start;
    char c;

restart: /* invalid bytes loop here — NOT recursion: a megabyte of binary
          * garbage must not become a megabyte of stack frames */
    skip_ws_and_comments(lx);

    line = lx->line;
    col = lx->col;
    start = lx->src + lx->pos;

    if (at_end(lx)) {
        tok_fill(t, T_EOF, line, col, start, 0);
        return;
    }

    c = advance(lx);

    if (is_digit(c)) {
        lx->pos--; lx->col--; /* re-lex the digit inside lex_number */
        lex_number(lx, t, line, col, start);
        return;
    }
    if (is_alpha(c)) {
        size_t n;
        size_t i;
        while (is_alnum(peek(lx))) advance(lx);
        n = (size_t)((lx->src + lx->pos) - start);
        for (i = 0; i < sizeof KW / sizeof KW[0]; i++) {
            if (strlen(KW[i].word) == n && memcmp(KW[i].word, start, n) == 0) {
                tok_fill(t, KW[i].kind, line, col, start, n);
                return;
            }
        }
        tok_fill(t, T_ID, line, col, start, n);
        return;
    }
    if (c == '"') { lex_string(lx, t, line, col, start); return; }

    switch (c) {
    case '(': tok_fill(t, T_LPAREN,   line, col, start, 1); return;
    case ')': tok_fill(t, T_RPAREN,   line, col, start, 1); return;
    case '{': tok_fill(t, T_LBRACE,   line, col, start, 1); return;
    case '}': tok_fill(t, T_RBRACE,   line, col, start, 1); return;
    case '[': tok_fill(t, T_LBRACK,   line, col, start, 1); return;
    case ']': tok_fill(t, T_RBRACK,   line, col, start, 1); return;
    case ',': tok_fill(t, T_COMMA,    line, col, start, 1); return;
    case ':': tok_fill(t, T_COLON,    line, col, start, 1); return;
    case '?': tok_fill(t, T_QUESTION, line, col, start, 1); return;
    case '|': tok_fill(t, T_PIPE,     line, col, start, 1); return;
    case '.': tok_fill(t, T_DOT,      line, col, start, 1); return;
    case '+': tok_fill(t, T_PLUS,     line, col, start, 1); return;
    case '*': tok_fill(t, T_STAR,     line, col, start, 1); return;
    case '/': tok_fill(t, T_SLASH,    line, col, start, 1); return;
    case '%': tok_fill(t, T_PERCENT,  line, col, start, 1); return;
    case '-':
        if (peek(lx) == '>') { advance(lx); tok_fill(t, T_ARROW, line, col, start, 2); return; }
        tok_fill(t, T_MINUS, line, col, start, 1); return;
    case '=':
        if (peek(lx) == '=') { advance(lx); tok_fill(t, T_EQ, line, col, start, 2); return; }
        tok_fill(t, T_ASSIGN, line, col, start, 1); return;
    case '!':
        if (peek(lx) == '=') { advance(lx); tok_fill(t, T_NE, line, col, start, 2); return; }
        tok_fill(t, T_BANG, line, col, start, 1); return;
    case '<':
        if (peek(lx) == '=') { advance(lx); tok_fill(t, T_LE, line, col, start, 2); return; }
        tok_fill(t, T_LT, line, col, start, 1); return;
    case '>':
        if (peek(lx) == '=') { advance(lx); tok_fill(t, T_GE, line, col, start, 2); return; }
        tok_fill(t, T_GT, line, col, start, 1); return;
    default:
        axi_diag_add_source(lx->diags, "AXI-L001", lx->src,
                            (uint32_t)(start - lx->src), 1,
                            "byte is not part of the axial alphabet",
                            "remove it; axial has exactly one spelling for everything");
        /* byte already consumed by advance() — progress law holds */
        goto restart;
    }
}

void axi_lex_next(axi_lexer *lx, axi_token *t)
{
    lex_next_inner(lx, t);
    /* own_line bookkeeping for the trivia sink: a comment is "own line"
     * iff no real token was produced earlier on its line (W05). */
    lx->last_tok_line = t->line;
}

int axi_str_decoded_length(const char *lexeme, size_t len, uint32_t *outlen)
{
    size_t j = 0;
    if (!lexeme || !outlen || len < 2 || len - 2 > UINT32_MAX
            || lexeme[0] != '"' || lexeme[len - 1] != '"') return 1;
    for (size_t i = 1; i + 1 < len; i++) {
        unsigned char ch = (unsigned char)lexeme[i];
        if (ch == '\\') {
            if (i + 2 >= len
                    || !axi_string_unescape_byte((unsigned char)lexeme[++i], &ch)) return 1;
        } else if (ch == '"' || (ch < 0x20 && ch != '\t') || ch == 0x7f) {
            return 1;
        }
        j++;
    }
    *outlen = (uint32_t)j;
    return 0;
}

static void str_decode_validated(const char *lexeme, size_t len, char *dst)
{
    size_t j = 0;
    for (size_t i = 1; i + 1 < len; i++) {
        unsigned char ch = (unsigned char)lexeme[i];
        if (ch == '\\') (void)axi_string_unescape_byte((unsigned char)lexeme[++i], &ch);
        dst[j++] = (char)ch;
    }
    dst[j] = '\0';
}

int axi_str_decode_into(const char *lexeme, size_t len, char *dst,
                         size_t capacity, uint32_t *outlen)
{
    uint32_t n;
    uintptr_t src_at = (uintptr_t)lexeme, dst_at = (uintptr_t)dst;
    if (!dst || !outlen || axi_str_decoded_length(lexeme, len, &n)
            || capacity <= n || len > UINTPTR_MAX - src_at
            || (size_t)n + 1 > UINTPTR_MAX - dst_at
            || (dst_at < src_at + len && src_at < dst_at + (size_t)n + 1)) return 1;
    str_decode_validated(lexeme, len, dst);
    *outlen = n;
    return 0;
}

char *axi_str_unescape(const char *lexeme, size_t len, uint32_t *outlen)
{
    uint32_t n;
    char *dst;
    if (axi_str_decoded_length(lexeme, len, &n)) return NULL;
    dst = (char *)axi_malloc((size_t)n + 1);
    if (!dst) return NULL;
    str_decode_validated(lexeme, len, dst);
    if (outlen) *outlen = n;
    return dst;
}
