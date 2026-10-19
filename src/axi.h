/* axial — the agent-first, capability-native, attested language.
 * Bear Core. SPDX-License-Identifier: LicenseRef-SPL-1.0
 * ADR-000 (toolchain/axial/docs). Tool name: axi. Extension: .axi
 *
 * House laws honored here:
 *  - G1..G6 grammar laws (ADR-000 §8): lexer keeps exact 1-based line/col
 *    spans (bear's INV-214 column-desync bug is the ancestor warning).
 *  - No gambiarra: diagnostics carry machine-actionable data from birth.
 */
#ifndef AXI_H
#define AXI_H

#include <stdint.h>
#include <stddef.h>
#include "axi_diag.h"

/* AXI-INV-064: the stream handles live behind one door — axi_osif.h. */
#include "axi_osif.h"

#define AXI_VERSION "0.0.1"

/* ---- tokens ------------------------------------------------------------ */

typedef enum {
    T_EOF = 0,
    /* literals & names */
    T_INT, T_FLOAT, T_STR, T_ID,
    /* keywords */
    T_CELL, T_FN, T_FUEL, T_PURE, T_USES, T_PROOF, T_LET, T_IF, T_ELSE,
    T_LOOP, T_BREAK, T_RET, T_CAP, T_OPT, T_OK, T_ERR, T_TRUE, T_FALSE,
    T_ASSERT, T_POLICY, T_UNDER,
    /* type keywords */
    T_U64, T_I64, T_F64, T_BOOL, T_BYTES, T_STRTY, T_DECISION,
    /* punctuation */
    T_LPAREN, T_RPAREN, T_LBRACE, T_RBRACE, T_LBRACK, T_RBRACK,
    T_COMMA, T_COLON, T_QUESTION, T_PIPE, T_ARROW, T_DOT,
    T_ASSIGN, T_EQ, T_NE, T_LT, T_LE, T_GT, T_GE,
    T_PLUS, T_MINUS, T_STAR, T_SLASH, T_PERCENT, T_BANG,
    T_COUNT
} axi_tok_kind;

typedef struct {
    axi_tok_kind kind;
    uint32_t     line;   /* 1-based */
    uint32_t     col;    /* 1-based, column of first byte */
    uint32_t     len;    /* byte length of lexeme */
    const char  *start;  /* into source buffer (not NUL-terminated) */
    uint64_t     ival;   /* T_INT */
    double       fval;   /* T_FLOAT */
} axi_token;

/* ---- diagnostics (typed cells from birth — ADR-000 G6) ------------------ */

/* W16 — a diagnostic is a *repair request*, not a complaint.
 *
 *   line/col/len  coordinates for the human reading the terminal;
 *   off           byte offset of that same span, or AXI_NO_OFF when the
 *                 diagnostic is about an artifact (a .axb, a run) with no
 *                 source text to point at — honest absence, never a fake 0;
 *   fix           prose for the reviewer;
 *   ed_*          the machine's half: replace src[ed_off, ed_off+ed_len)
 *                 with ed_text. has_edit == 0 means no mechanical repair is
 *                 known and the agent has to think.
 *
 * A repair that does not fit in ed_text degrades to prose (has_edit = 0)
 * instead of shipping a truncated edit: a half-applied fix is worse than
 * none. Same refusal-to-truncate doctrine as the lexer (W03).
 */
/* ---- trivia (comments) --------------------------------------------------
 * W05 canonical form must re-print comments, so the lexer offers an
 * optional sink: set .triv/.triv_cap after init and comments are recorded
 * instead of vanishing. NULL sink = old behavior (parse/lex paths). */

typedef struct {
    uint32_t    line, col;   /* 1-based, at '#' */
    const char *start;       /* into source, at '#' */
    uint32_t    len;         /* to end of line (newline excluded) */
    int         own_line;    /* 1 = nothing but whitespace before it */
} axi_trivia;

/* ---- lexer -------------------------------------------------------------- */

typedef struct {
    const char *src;
    size_t      len;
    size_t      pos;
    uint32_t    line;  /* 1-based */
    uint32_t    col;   /* 1-based; col of src[pos] */
    axi_diags  *diags;
    axi_trivia *triv;          /* optional comment sink (W05); NULL = skip */
    int         triv_cap;
    int         triv_n;
    int         triv_dropped;  /* honesty counter, mirrors diags.dropped */
    uint32_t    last_tok_line; /* line of last real token (own_line calc) */
} axi_lexer;

void        axi_lex_init(axi_lexer *lx, const char *src, size_t len,
                         axi_diags *diags);
/* Text-string contract v1: \\n, \\t, \\0, \\\\ and \\". Lexemes include quotes.
 * Length/into functions allocate nothing, return 0 on success, and leave
 * outputs untouched on invalid input or insufficient capacity. The output
 * buffer must be disjoint from the lexeme; capacity includes a final NUL.
 * Decoded embedded NUL is data: consumers must use the returned length. */
int         axi_str_decoded_length(const char *lexeme, size_t len, uint32_t *outlen);
int         axi_str_decode_into(const char *lexeme, size_t len, char *dst,
                                 size_t capacity, uint32_t *outlen);
/* Allocating convenience wrapper; caller frees, NULL on invalid input/OOM. */
char       *axi_str_unescape(const char *lexeme, size_t len, uint32_t *outlen);
/* Always produces a token; T_EOF forever at end. Invalid bytes produce a
 * diagnostic and are skipped (lexer never wedges: bear INV-212/213 lesson —
 * every path must consume). */
void        axi_lex_next(axi_lexer *lx, axi_token *out);
const char *axi_tok_name(axi_tok_kind k);

/* axi_bc.c (W08) — AXB assembler/disassembler front doors */
int cmd_asm(const char *in, const char *out_path);
int cmd_dis(const char *in);
int cmd_bind(const char *mod_path, const char *src_path); /* W14: verify src_hash */
/* W21 — the seal. `seal` proves and emits (W12); these two answer a different
 * question: not "is it correct" but "whose is it". Separate verbs on purpose,
 * because a tool that signs as a side effect of building is a tool that signs
 * things nobody meant to sign. */
int cmd_sign(const char *mod_path, const char *key_path);

#endif /* AXI_H */
