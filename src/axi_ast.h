/* axial — AST + parser API (W04). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * LL(1) per SPEC-GRAMMAR §3 (G6: one-token lookahead, local repair).
 * Nodes are individually heap-allocated with a private parse-ownership link.
 * The returned unit owns its complete tree; lex/pos slices borrow the source
 * until axi_ast_free(unit) returns.
 */
#ifndef AXI_AST_H
#define AXI_AST_H

#include "axi.h"
#include "axi_compile_budget.h"

typedef enum {
    N_UNIT, N_CELL, N_POLICY, N_SIG, N_PARAM, N_TYPE, N_ERRT, N_OKT,
    N_FUEL, N_PURE, N_USES, N_CAP, N_EFF,
    N_BLOCK, N_LET, N_RET, N_IF, N_EXPRSTMT,
    N_INT, N_FLOAT, N_STR, N_TRUE, N_FALSE, N_OK, N_ID,
    N_BIN, N_UN, N_CALL, N_INDEX, N_FIELD, N_TRY, N_LIST
} axi_nkind;

typedef struct axi_node axi_node;
/* Private checker -> codegen return notes. Source admits one payload plus
 * optional ok. Frozen manifest tags sort every payload before OK (tag 9). */
enum {
    AXI_RET_UNCHECKED = 0, AXI_RET_PLAIN = 1,
    AXI_RET_SOME = 2, AXI_RET_NONE = 3
};
struct axi_node {
    axi_nkind    kind;
    uint32_t     line, col;      /* 1-based span start (G3) */
    const char  *pos;            /* W16: first byte in source; the byte
                                  * anchor (line,col) names. NULL only for
                                  * synthesized nodes. AXI-INV-027 holds
                                  * pos and (line,col) to the same byte. */
    axi_tok_kind op;             /* N_BIN / N_UN operator */
    uint64_t     ival;           /* N_INT; N_TYPE: 1 = cap-qualified */
    double       fval;           /* N_FLOAT */
    const char  *lex;            /* names/paths/strings: raw source slice */
    uint32_t     lexlen;
    axi_node    *a, *b, *c;      /* fixed children (grammar-position) */
    axi_node    *list;           /* first element of a child list */
    axi_node    *next;           /* sibling link inside a list */
    uint32_t     inferred_caps_mask; /* AXI-INV-078: unit call-graph fixpoint */
    uint8_t      tyann;          /* AXI-INV-101: typechecker -> codegen note.
                                  * N_UN minus: 1 = i64, 2 = f64, 0 = unset.
                                  * N_RET: AXI_RET_* representation note.
                                  * The codegen never re-infers a type. */
    uint8_t      contract_checked; /* AXI-INV-122: unit passed type/cap closure */
    /* Borrowed shape established by check_try; not an owned AST child. */
    const axi_node *result_type;
    axi_compile_budget *budget; /* Private owner; NULL is the legacy API. */
};

/* Parse a whole unit. Syntax errors return a partial tree and AXI-P0xx
 * diagnostics (G8: caged, keep going). Allocation failure reclaims every
 * partial node and returns NULL with AXI-D999; the process is not terminated. */
axi_node *axi_parse_unit(const char *src, size_t len, const char *path,
                         axi_diags *diags);
/* The caller keeps budget and source alive through axi_ast_free. The source
 * is borrowed; charge/copy it in the same budget when bounding an invocation. */
axi_node *axi_parse_unit_budget(const char *src, size_t len, const char *path,
                                axi_diags *diags, axi_compile_budget *budget);

/* Release a complete or partial tree. The source must remain alive until this
 * returns because node lexemes are borrowed slices. */
void axi_ast_free(axi_node *n);

/* Stable s-expression dump (golden-test format). */
void axi_ast_dump(const axi_node *n, int indent);

/* W05: the one true text. Returns a malloc'd canonical rendering of a
 * parse-green unit (caller frees). Comments are harvested from a trivia
 * re-lex of src and re-attached on their own lines. */
char *axi_canon_render(const char *src, size_t len, const axi_node *unit);

/* W15: canonical text of a single expression / type (caller frees).
 * The interface projection uses these so there is exactly one printer. */
char *axi_canon_expr_str(const axi_node *e);
/* Fallible form for library projections: allocation failure returns NULL. */
char *axi_canon_expr_str_fallible(const axi_node *e);
char *axi_canon_type_str(const axi_node *t);

/* G1 integer spelling (`_` every 3 digits iff >=5 digits), into a caller
 * buffer of >= 32 bytes. AXI-INV-025: every surface that prints an integer
 * an agent may paste back into source goes through this one door, or the
 * tool ships text its own canonical-form law would reject. */
void axi_canon_int_str(uint64_t v, char *out, size_t cap);

/* Same authority, JSON's grammar (plain digits, no `_`). For machine
 * projections only — never for text an agent pastes back into source. */
void axi_canon_int_json(uint64_t v, char *out, size_t cap);

/* W06: type checker. Walks a parse-green unit and appends AXI-T0xx diags.
 * Contract in SPEC-GRAMMAR §6: zero coercion; opt/result = rettype unions;
 * unions demand `?`; cap-rooted values are opaque until W07. */
void axi_type_check(const axi_node *unit, axi_diags *ds);

#endif /* AXI_AST_H */
