/* axi — CLI for axial. Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * v0 subcommands:
 *   axi version
 *   axi lex FILE [--json]     token stream (golden-test format) + diagnostics
 *   axi parse FILE [--json]   AST s-expression dump + diagnostics
 *
 * Diagnostics honor ADR-000 G6: with --json they are emitted as typed cells
 * on AXI_OUT; the human form goes to AXI_ERR otherwise. Exit 1 iff diags.
 */
#include "axi.h"
#include "axi_alloc.h"
#include "axi_ast.h"
#include "axi_numeric.h"
#include "axi_policy_lint.h"
#include "axi_hash.h"
#include "axi_iface.h"
#include "axi_effect.h"
#include "axi_codegen.h"
#include "axi_bc.h"
#include "axi_contract.h"
#include "axi_json.h"
#include "axi_replay.h"
#include "axi_aer1.h"
#include "axi_aer1_verify.h"
#include "axi_sign.h"
#include "axi_vm.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Bound host snapshots before allocating. Non-regular sources (notably
 * FIFOs) are refused without blocking. Parsing and hashing use these bytes. */
#define AXI_CLI_FILE_MAX (64u * 1024u * 1024u)

static char *read_file_budget(const char *path, size_t *out_len,
                              axi_compile_budget *budget)
{
    struct stat st;
    FILE *f;
    int fd, saved;
    size_t size;
    char *buf;
    if (out_len) *out_len = 0;
    if (!path || !*path || !out_len) { errno = EINVAL; return NULL; }
    fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return NULL;
    if (fstat(fd, &st) != 0) {
        saved = errno; close(fd); errno = saved; return NULL;
    }
    if (!S_ISREG(st.st_mode) || st.st_size < 0) {
        close(fd); errno = EINVAL; return NULL;
    }
    if ((uintmax_t)st.st_size > AXI_CLI_FILE_MAX) {
        close(fd); errno = EFBIG; return NULL;
    }
    size = (size_t)st.st_size;
    f = fdopen(fd, "rb");
    if (!f) { saved = errno; close(fd); errno = saved; return NULL; }
    buf = (char *)axi_compile_malloc(budget, size + 1);
    if (!buf) { saved = errno; fclose(f); errno = saved; return NULL; }
    if ((size && fread(buf, 1, size, f) != size)
            || fgetc(f) != EOF || ferror(f)) {
        fclose(f); (void)axi_compile_free(budget, buf); errno = EIO; return NULL;
    }
    if (fclose(f) != 0) { saved = errno; (void)axi_compile_free(budget, buf); errno = saved; return NULL; }
    buf[size] = '\0';
    *out_len = size;
    return buf;
}

static char *read_file(const char *path, size_t *out_len)
{
    return read_file_budget(path, out_len, NULL);
}

static int cmd_aer_verify(const char *path, const char *key_path)
{
    size_t len = 0;
    char *bytes = read_file(path, &len);
    uint8_t trusted_pk[32], root[32];
    axi_aer1 receipt;
    if (!bytes || axi_trusted_pk_load(key_path, trusted_pk) != 0
            || axi_aer1_verify_signed(&receipt, (const uint8_t *)bytes,
                                      len, trusted_pk) != 0) {
        free(bytes);
        fprintf(AXI_ERR, "AXI-AER001 receipt signature or framing is invalid\n");
        return 1;
    }
    axi_aer1_root(&receipt, root);
    fprintf(AXI_OUT, "AER1 VERIFIED decision=%u attempt=%u outcome=%u "
                     "coverage=%u profile=%u opacity=%u maturity=%u "
                     "evidence=%u root=",
            receipt.decision, receipt.attempt, receipt.outcome,
            receipt.coverage, receipt.profile, receipt.opacity,
            receipt.maturity,
            receipt.evidence);
    for (size_t i = 0; i < sizeof root; i++) fprintf(AXI_OUT, "%02x", root[i]);
    fputc('\n', AXI_OUT);
    free(bytes);
    return ferror(AXI_OUT) ? 1 : 0;
}

static int file_json_sink(void *ctx, const char *bytes, size_t len)
{
    return fwrite(bytes, 1, len, (FILE *)ctx) == len ? 0 : -1;
}

static void json_escape_n(const char *s, size_t n, FILE *out)
{
    (void)axi_json_escape(s, n, file_json_sink, out);
}

static void json_escape(const char *s, FILE *out)
{
    json_escape_n(s, strlen(s), out);
}

static void json_hex(const char *s, FILE *out)
{
    static const char HEX[] = "0123456789abcdef";
    size_t i, n = strlen(s);
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        fputc(HEX[c >> 4], out);
        fputc(HEX[c & 15], out);
    }
}

static void print_diags_human(const axi_diags *ds, const char *path)
{
    int i;
    for (i = 0; i < ds->n; i++) {
        const axi_diag *d = &ds->d[i];
        fprintf(AXI_ERR, "%s %s:%u:%u %s", d->code, path, d->line, d->col,
                d->msg);
        if (d->fix[0] != '\0') fprintf(AXI_ERR, " | fix: %s", d->fix);
        fputc('\n', AXI_ERR);
    }
    if (ds->dropped > 0)
        fprintf(AXI_ERR, "AXI-D999 %s: %d further diagnostics dropped\n",
                path, ds->dropped);
}

static void print_diags_json(const axi_diags *ds, const char *path)
{
    int i;
    printf("{\"schema\":\"%s\",\"file\":\"", AXI_DIAG_SCHEMA);
    json_escape(path, AXI_OUT);
    printf("\",\"file_bytes\":\"");
    json_hex(path, AXI_OUT);
    printf("\",\"diags\":[");
    for (i = 0; i < ds->n; i++) {
        const axi_diag *d = &ds->d[i];
        if (i > 0) printf(",");
        printf("{\"code\":\"%s\",\"line\":%u,\"col\":%u,\"len\":%u,"
               "\"msg\":\"", d->code, d->line, d->col, d->len);
        json_escape(d->msg, AXI_OUT);
        printf("\",\"fix\":\"");
        json_escape(d->fix, AXI_OUT);
        printf("\"");
        /* W16: `off` absent means the diagnostic has no source span at all
         * (it speaks about an artifact) — never a fake zero. `edit` absent
         * means no mechanical repair is known and the agent must think. */
        if (d->off != AXI_NO_OFF) printf(",\"off\":%u", d->off);
        if (d->has_edit) {
            printf(",\"edit\":{\"off\":%u,\"len\":%u,\"text\":\"",
                   d->ed_off, d->ed_len);
            json_escape_n(d->ed_text, d->ed_textlen, AXI_OUT);
            printf("\"}");
        }
        printf("}");
    }
    printf("],\"dropped\":%d}\n", ds->dropped);
}

static void print_read_error(const char *path, int json)
{
    int oversized = errno == EFBIG;
    const char *code = oversized ? "AXI-X003" : "AXI-X001";
    const char *message = oversized ? "input exceeds the 64 MiB CLI limit"
                                      : "cannot read file";
    if (json) {
        axi_diags ds;
        axi_diags_init(&ds);
        axi_diag_add(&ds, code, 0, 0, 0, message,
                     oversized ? "split the input into bounded files"
                               : "provide a readable regular file");
        print_diags_json(&ds, path);
    } else {
        fprintf(AXI_ERR, "%s %s: %s\n", code, message, path);
    }
}

static const char *compile_failure_message(const axi_compile_budget *budget)
{
    switch (budget ? budget->failure : AXI_COMPILE_HOST_OOM) {
    case AXI_COMPILE_QUOTA: return "compiler invocation memory quota exceeded";
    case AXI_COMPILE_HOST_OOM: return "host could not allocate compiler memory";
    case AXI_COMPILE_OVERFLOW: return "compiler allocation size overflow";
    case AXI_COMPILE_OWNERSHIP: return "compiler allocation ownership failure";
    case AXI_COMPILE_OK: return "compiler operation failed";
    }
    return "compiler operation failed";
}

static void print_compile_failure(const char *path, int json,
                                  const axi_compile_budget *budget)
{
    axi_diags ds;
    if (!budget || budget->failure == AXI_COMPILE_OK) return;
    axi_diags_init(&ds);
    axi_diag_add_at(&ds, axi_compile_failure_code(budget), 1, 1, 1, 0,
                   compile_failure_message(budget),
                   "adjust --compile-mem or reduce the input; the limit counts owned storage");
    if (json) print_diags_json(&ds, path);
    else print_diags_human(&ds, path);
}

static void print_compile_read_error(const char *path, int json,
                                     const axi_compile_budget *budget)
{
    if (budget && budget->failure != AXI_COMPILE_OK)
        print_compile_failure(path, json, budget);
    else print_read_error(path, json);
}

static int cmd_lex(const char *path, int json, axi_compile_budget *budget)
{
    size_t len = 0;
    char *src = read_file_budget(path, &len, budget);
    axi_diags ds;
    axi_lexer lx;
    axi_token t;

    if (!src) {
        print_compile_read_error(path, json, budget);
        return 2;
    }
    axi_diags_init(&ds);
    axi_lex_init(&lx, src, len, &ds);

    do {
        axi_lex_next(&lx, &t);
        if (!json) {
            printf("%u:%u %s", t.line, t.col, axi_tok_name(t.kind));
            if (t.kind == T_INT)        printf(" %llu", (unsigned long long)t.ival);
            else if (t.kind == T_FLOAT) printf(" %.17g", t.fval);
            else if (t.kind == T_ID || t.kind == T_STR)
                printf(" %.*s", (int)t.len, t.start);
            printf("\n");
        }
    } while (t.kind != T_EOF);

    if (json) print_diags_json(&ds, path);
    else      print_diags_human(&ds, path);

    (void)axi_compile_free(budget, src);
    return ds.n > 0 ? 1 : 0;
}

static int cmd_parse(const char *path, int json, axi_compile_budget *budget)
{
    size_t len = 0;
    char *src = read_file_budget(path, &len, budget);
    axi_diags ds;
    axi_node *unit;

    if (!src) {
        print_compile_read_error(path, json, budget);
        return 2;
    }
    axi_diags_init(&ds);
    unit = axi_parse_unit_budget(src, len, path, &ds, budget);
    if (!unit) {
        if (json) print_diags_json(&ds, path);
        else print_diags_human(&ds, path);
        (void)axi_compile_free(budget, src);
        return 2;
    }

    if (json) {
        print_diags_json(&ds, path);
    } else {
        axi_ast_dump(unit, 0);
        print_diags_human(&ds, path);
    }

    axi_ast_free(unit);
    (void)axi_compile_free(budget, src);
    return ds.n > 0 ? 1 : 0;
}

/* ---- canonical form (W05) ------------------------------------------------ */

static int cmd_canon(const char *path, axi_compile_budget *budget)
{
    size_t len = 0;
    char *src = read_file_budget(path, &len, budget);
    axi_diags ds;
    axi_node *unit;
    char *canon;

    if (!src) {
        fprintf(AXI_ERR, "AXI-X001 cannot read file: %s\n", path);
        return 2;
    }
    axi_diags_init(&ds);
    unit = axi_parse_unit_budget(src, len, path, &ds, budget);
    if (!unit) { print_diags_human(&ds, path); (void)axi_compile_free(budget, src); return 2; }
    if (ds.n > 0) { /* partial tree: refusing beats emitting a wrong canon */
        print_diags_human(&ds, path);
        axi_ast_free(unit);
        (void)axi_compile_free(budget, src);
        return 1;
    }
    canon = axi_canon_render(src, len, unit);
    if (!canon) { /* INV-323 / AXI-INV-105: trivia cap overflow is a refusal */
        if (budget && budget->failure != AXI_COMPILE_OK)
            print_compile_failure(path, 0, budget);
        else fprintf(AXI_ERR, "AXI-C006 %s: input exceeds the canonical trivia cap "
                "(%d comments) | fix: the canon never drops a comment; "
                "split the file\n", path, 512);
        axi_ast_free(unit);
        (void)axi_compile_free(budget, src);
        return 1;
    }
    fputs(canon, AXI_OUT);
    (void)axi_compile_free(budget, canon);
    axi_ast_free(unit);
    (void)axi_compile_free(budget, src);
    return 0;
}

/* split into lines (newline excluded); returns count */
static int split_lines(const char *s, size_t len,
                       const char **ls, uint32_t *ll, int max)
{
    int n = 0;
    size_t i = 0, start = 0;
    for (i = 0; i <= len; i++) {
        if (i == len || s[i] == '\n') {
            if (i == len && i == start) break; /* no trailing phantom line */
            if (n < max) { ls[n] = s + start; ll[n] = (uint32_t)(i - start); }
            n++;
            start = i + 1;
        }
    }
    return n;
}

#define CHECK_MAX_LINES 4096

/* W16 — the prose hint and the mechanical edit are the same knowledge said
 * twice: once for the human reading the terminal, once for `axi fix`.
 * `off`/`oldlen` is the byte range this line occupies in the source; when
 * `add_nl` the replacement carries the newline the canonical file wants. */
static void diag_line_fix(axi_diags *ds, const char *code,
                          uint32_t line, uint32_t col, const char *msg,
                          const char *fix, uint32_t fixlen,
                          uint32_t off, uint32_t oldlen, int add_nl)
{
    char fixbuf[AXI_DIAG_MSG], editbuf[AXI_DIAG_MSG];
    uint32_t elen = fixlen + (add_nl ? 1u : 0u);

    if (fixlen >= sizeof fixbuf) {
        axi_diag_add_at(ds, code, line, col, 1, off, msg,
                        "line exceeds the diag cell; run `axi canon` and take "
                        "the whole file");
        return;
    }
    memcpy(fixbuf, fix, fixlen);
    fixbuf[fixlen] = '\0';
    if (elen >= sizeof editbuf) {   /* no room for the repair; prose survives */
        axi_diag_add_at(ds, code, line, col, 1, off, msg, fixbuf);
        return;
    }
    memcpy(editbuf, fix, fixlen);
    if (add_nl) editbuf[fixlen] = '\n';
    axi_diag_add_fix(ds, code, line, col, 1, off, msg, fixbuf,
                     off, oldlen, editbuf, elen);
}

static void form_diags(const char *src, size_t len, const char *canon,
                       axi_diags *ds, axi_compile_budget *budget);

/* and_types: 0 = form only (`axi form`, the gate's fixpoint law),
 *            1 = the full ladder grammar → form → types (`axi check`).
 * The ladder speaks one layer at a time: types stay silent until the
 * form is silent — an agent fixes one kind of red per pass. */
static int cmd_check_snapshot(const char *path, int json, int and_types,
                               char **source_out, axi_node **unit_out,
                               axi_compile_budget *budget)
{
    size_t len = 0;
    char *src = read_file_budget(path, &len, budget);
    axi_diags ds;
    axi_node *unit;
    char *canon;
    int i;
    uint32_t last_cr = 0, last_tab = 0;
    size_t k;
    uint32_t line = 1;

    if (source_out) *source_out = NULL;
    if (unit_out) *unit_out = NULL;
    if (!src) {
        print_compile_read_error(path, json, budget);
        return 2;
    }
    axi_diags_init(&ds);

    /* alphabet-of-form pre-scan: CR and TAB make invisible diffs, so they
     * get loud, dedicated diags (one per line each). */
    for (k = 0; k < len; k++) {
        char c = src[k];
        if (c == '\r' && last_cr != line) {
            axi_diag_add_source(&ds, "AXI-C004", src, (uint32_t)k, 1,
                                "carriage return is not part of the canonical form",
                                "use LF-only line endings");
            last_cr = line;
        }
        if (c == '\t' && last_tab != line) {
            axi_diag_add_source(&ds, "AXI-C005", src, (uint32_t)k, 1,
                                "tab is not canonical whitespace",
                                "use spaces; indent is 2 per level");
            last_tab = line;
        }
        if (c == '\n') line++;
    }

    unit = axi_parse_unit_budget(src, len, path, &ds, budget);
    if (!unit) {
        if (json) print_diags_json(&ds, path);
        else print_diags_human(&ds, path);
        (void)axi_compile_free(budget, src);
        return 2;
    }
    if (ds.n > 0 && unit->list == NULL) {
        /* nothing parsed; canon compare would only shout noise */
        if (json) print_diags_json(&ds, path);
        else      print_diags_human(&ds, path);
        axi_ast_free(unit);
        (void)axi_compile_free(budget, src);
        return 1;
    }
    {
        int parse_diags = 0;
        for (i = 0; i < ds.n; i++)
            if (ds.d[i].code[4] == 'P' || ds.d[i].code[4] == 'L')
                parse_diags = 1;
        if (parse_diags) { /* fix the grammar first, then the form */
            if (json) print_diags_json(&ds, path);
            else      print_diags_human(&ds, path);
            axi_ast_free(unit);
            (void)axi_compile_free(budget, src);
            return 1;
        }
    }

    canon = axi_canon_render(src, len, unit);
    if (!canon) { /* INV-323 / AXI-INV-105: no canon, no verdict */
        if (budget && budget->failure != AXI_COMPILE_OK)
            axi_diag_add_source(&ds, axi_compile_failure_code(budget), src, 0, 1,
                compile_failure_message(budget), "increase --compile-mem or reduce the input");
        else axi_diag_add_source(&ds, "AXI-C006", src, 0, 1,
                            "input exceeds the canonical trivia cap (512 comments)",
                            "the canon never drops a comment; split the file");
        if (json) print_diags_json(&ds, path);
        else      print_diags_human(&ds, path);
        axi_ast_free(unit);
        (void)axi_compile_free(budget, src);
        return 1;
    }

    if (strlen(canon) == (size_t)len && memcmp(canon, src, len) == 0
        && ds.n == 0) {
        (void)axi_compile_free(budget, canon);
        if (and_types) { /* form green → the types layer speaks (W06) */
            axi_type_check(unit, &ds);
            if (ds.n > 0) {
                if (json) print_diags_json(&ds, path);
                else      print_diags_human(&ds, path);
                axi_ast_free(unit);
                (void)axi_compile_free(budget, src);
                return 1;
            }
        }
        if (source_out && unit_out) {
            *source_out = src;
            *unit_out = unit;
        } else {
            axi_ast_free(unit);
            (void)axi_compile_free(budget, src);
        }
        return 0; /* Retain the exact validated snapshot when requested. */
    }

    form_diags(src, len, canon, &ds, budget);

    if (json) print_diags_json(&ds, path);
    else      print_diags_human(&ds, path);
    (void)axi_compile_free(budget, canon);
    axi_ast_free(unit);
    (void)axi_compile_free(budget, src);
    return ds.n > 0 ? 1 : 0;
}

static int cmd_check_impl(const char *path, int json, int and_types,
                          axi_compile_budget *budget)
{
    return cmd_check_snapshot(path, json, and_types, NULL, NULL, budget);
}

/* W16 — the form layer's diagnostics, byte-anchored and repairable. Shared
 * by `axi check`, which prints them, and `axi fix`, which applies them: one
 * body of knowledge, so a repair can never disagree with its complaint.
 *
 * The edits are emitted in ascending byte order — the lines that differ,
 * then the tail, then the closing newline — because AXI-INV-025 requires a
 * diagnostic set to be applicable in a single pass. */
static void form_diags(const char *src, size_t len, const char *canon,
                       axi_diags *ds, axi_compile_budget *budget)
{
    struct line_workspace {
        const char *sl[CHECK_MAX_LINES], *cl[CHECK_MAX_LINES];
        uint32_t sll[CHECK_MAX_LINES], cll[CHECK_MAX_LINES];
    } *workspace = axi_compile_malloc(budget, sizeof *workspace);
    const char **sl, **cl;
    uint32_t *sll, *cll;
    int sn, cn, i, minn;

    if (!workspace) {
        axi_diag_add_source(ds, axi_compile_failure_code(budget), src, 0, 1,
                            "cannot reserve form comparison workspace",
                            "increase --compile-mem or reduce the input");
        return;
    }
    sl = workspace->sl; cl = workspace->cl;
    sll = workspace->sll; cll = workspace->cll;
    sn = split_lines(src, len, sl, sll, CHECK_MAX_LINES);
    cn = split_lines(canon, strlen(canon), cl, cll, CHECK_MAX_LINES);
    /* INV-323 / AXI-INV-105: past the line cap the arrays hold only a
     * prefix — comparing a prefix would call a divergent file canonical.
     * Refuse instead. */
    if (sn > CHECK_MAX_LINES || cn > CHECK_MAX_LINES) {
        axi_diag_add_source(ds, "AXI-C006", src, 0, 1,
                            "file exceeds the diagnostic line cap",
                            "split the file; the checker never compares a prefix");
        (void)axi_compile_free(budget, workspace);
        return;
    }
    minn = sn < cn ? sn : cn;
    if (minn > CHECK_MAX_LINES) minn = CHECK_MAX_LINES;

    for (i = 0; i < minn; i++) {
        if (sll[i] != cll[i] || memcmp(sl[i], cl[i], sll[i]) != 0) {
            uint32_t d = 0;
            while (d < sll[i] && d < cll[i] && sl[i][d] == cl[i][d]) d++;
            diag_line_fix(ds, "AXI-C001", (uint32_t)i + 1, d + 1,
                          "line is not canonical", cl[i], cll[i],
                          (uint32_t)(sl[i] - src), sll[i], 0);
        }
    }
    if (sn > cn) {
        /* Every extra line dies in one cut, from the start of the first
         * surplus line to the end of the file. */
        uint32_t off = (uint32_t)(sl[cn] - src);
        axi_diag_add_fix(ds, "AXI-C002", (uint32_t)cn + 1, 1, 1, off,
                         "extra line: the canonical file is shorter",
                         "delete this line",
                         off, (uint32_t)len - off, "", 0);
    } else {
        /* The closing newline is inserted first: a missing line appended to a
         * file that does not end in one would fuse with the last line. Both
         * edits sit at `len` and are zero-width, so they stay disjoint. */
        /* W16: the repair text here is a bare "\n" — invisible, so it cannot
         * double as the prose hint the way a rewritten line can. The two are
         * spelled out separately instead of letting the edit mute the prose. */
        if (len > 0 && src[len - 1] != '\n')
            axi_diag_add_fix(ds, "AXI-C003", (uint32_t)sn, 1, 1, (uint32_t)len,
                             "file must end in a single newline",
                             "add a final newline",
                             (uint32_t)len, 0, "\n", 1);
        for (i = sn; i < cn; i++)
            diag_line_fix(ds, "AXI-C002", (uint32_t)i + 1, 1,
                          "missing canonical line", cl[i], cll[i],
                          (uint32_t)len, 0, 1);
    }
    (void)axi_compile_free(budget, workspace);
}

/* types only: parse must be green, then the checker speaks (form ignored,
 * so red-form fixtures can still exercise pure type laws in the suite). */
static int cmd_types(const char *path, int json, axi_compile_budget *budget)
{
    size_t len = 0;
    char *src = read_file_budget(path, &len, budget);
    axi_diags ds;
    axi_node *unit;

    if (!src) {
        print_compile_read_error(path, json, budget);
        return 2;
    }
    axi_diags_init(&ds);
    unit = axi_parse_unit_budget(src, len, path, &ds, budget);
    if (!unit) {
        if (json) print_diags_json(&ds, path);
        else print_diags_human(&ds, path);
        (void)axi_compile_free(budget, src);
        return 2;
    }
    if (ds.n == 0) /* grammar first; a broken tree would only lie */
        axi_type_check(unit, &ds);
    if (ds.n > 0) {
        if (json) print_diags_json(&ds, path);
        else      print_diags_human(&ds, path);
        axi_ast_free(unit);
        (void)axi_compile_free(budget, src);
        return 1;
    }
    if (json) print_diags_json(&ds, path); /* empty cell list = green */
    axi_ast_free(unit);
    (void)axi_compile_free(budget, src);
    return 0;
}

/* ---- compile: axial source -> .axb (M3) ---------------------------------- */

static int cmd_compile(const char *in, const char *out_path,
                       const char *signing_key_path, axi_compile_budget *budget)
{
    size_t n = 0;
    char *src = read_file_budget(in, &n, budget);
    axi_diags ds;
    axi_node *unit;
    size_t alen;
    char *axs;
    int rc;

    if (!src) {
        fprintf(AXI_ERR, "AXI-X001 cannot read file: %s\n", in);
        return 2;
    }
    axi_diags_init(&ds);
    unit = axi_parse_unit_budget(src, n, in, &ds, budget);
    if (!unit) { print_diags_human(&ds, in); (void)axi_compile_free(budget, src); return 2; }
    if (ds.n == 0)
        axi_type_check(unit, &ds);
    if (ds.n > 0) {
        print_diags_human(&ds, in);
        axi_ast_free(unit);
        (void)axi_compile_free(budget, src);
        return 1;
    }

    axs = axi_codegen_contract_v1(unit, &alen);
    if (!axs) {
        fprintf(AXI_ERR, "AXI-X002 %s: codegen failed\n", in);
        axi_ast_free(unit);
        (void)axi_compile_free(budget, src);
        return 2;
    }

    {
        axi_mem_account account;
        axi_compile_account_init(&account, budget);
        rc = axb_contract_v1_write_signed_text_accounted(axs, alen, in, out_path,
                                            signing_key_path, &account);
    }
    (void)axi_compile_free(budget, axs);
    axi_ast_free(unit);
    (void)axi_compile_free(budget, src);
    return rc;
}

/* ---- interface projection (W15) ------------------------------------------ */

/* One door (AXI-INV-023). A contract is only projected out of a file that
 * ALREADY passed the full ladder — grammar, canonical form and types — and
 * the way we know it passed is that we run `axi check` itself, not a second
 * copy of its rules. A private, laxer validation here would be a second door:
 * `axi check` would refuse a file while `axi iface` hashed and published it,
 * and the published contract would describe a program that cannot exist.
 * A lying interface is worse than no interface at all. */
static axi_node *load_unit_or_null(const char *path, char **src_out, int json,
                                   axi_compile_budget *budget)
{
    axi_node *unit = NULL;
    if (cmd_check_snapshot(path, json, 1, src_out, &unit, budget) != 0)
        return NULL;
    return unit;
}

static int cmd_iface(const char *path, int json, axi_compile_budget *budget)
{
    char *src = NULL;
    axi_node *unit = load_unit_or_null(path, &src, json, budget);
    char *text;

    if (!unit) return 2;
    text = json ? axi_iface_json(unit) : axi_iface_render(unit);
    if (!text) {
        print_compile_failure(path, json, budget);
        axi_ast_free(unit);
        (void)axi_compile_free(budget, src);
        return 2;
    }
    fputs(text, AXI_OUT);
    (void)axi_compile_free(budget, text);
    axi_ast_free(unit);
    (void)axi_compile_free(budget, src);
    return 0;
}

/* W19 — the honest inventory. Everything this binary can do to the world, and
 * nothing it cannot: an operator deciding whether to hand over a --cap should
 * never have to read our source to find the list. /AXI-INV-036/ */
static int cmd_caps(int json)
{
    size_t n = axi_host_eff_count();
    if (json) {
        fputs("{\"caps\":[", AXI_OUT);
        for (size_t i = 0; i < n; i++)
            printf("%s\"%s\"", i ? "," : "", axi_host_eff_at(i)->name);
        printf("],\"count\":%zu}\n", n);
        return 0;
    }
    for (size_t i = 0; i < n; i++)
        printf("%s\n", axi_host_eff_at(i)->name);
    /* the empty build is a legitimate answer, and a loud one */
    if (n == 0) fputs("(none — this build cannot touch the world)\n", AXI_OUT);
    return 0;
}

static int cmd_iface_diff(const char *op, const char *np, int json,
                          axi_compile_budget *budget)
{
    char *osrc = NULL, *nsrc = NULL;
    axi_node *ou, *nu;
    int verdict;

    ou = load_unit_or_null(op, &osrc, json, budget);
    if (!ou) return 2;
    nu = load_unit_or_null(np, &nsrc, json, budget);
    if (!nu) {
        axi_ast_free(ou);
        (void)axi_compile_free(budget, osrc);
        return 2;
    }

    verdict = axi_iface_diff(ou, nu, AXI_OUT, json);
    axi_ast_free(ou);
    axi_ast_free(nu);
    (void)axi_compile_free(budget, osrc);
    (void)axi_compile_free(budget, nsrc);
    /* 0 = identical or compatible: the change is safe for existing callers.
     * 1 = breaking: red, on purpose — this is the check a release runs. */
    return verdict == 2 ? 1 : 0;
}

static int cmd_compat(const char *path, int json)
{
    unsigned char header[8];
    FILE *file = fopen(path, "rb");
    uint32_t version;
    axb_compat compatibility;
    const char *status, *action;
    if (!file) {
        print_read_error(path, json);
        return 2;
    }
    if (fread(header, 1, sizeof header, file) != sizeof header) {
        fclose(file);
        fprintf(AXI_ERR, "AXI-B012 %s: truncated AXB header\n", path);
        return 2;
    }
    fclose(file);
    if (memcmp(header, AXB_MAGIC, 4) != 0) {
        fprintf(AXI_ERR, "AXI-B010 %s: not an AXB module\n", path);
        return 2;
    }
    version = (uint32_t)header[4]
            | (uint32_t)header[5] << 8
            | (uint32_t)header[6] << 16
            | (uint32_t)header[7] << 24;
    compatibility = axb_version_compat(version);
    if (compatibility == AXB_COMPAT_CURRENT) {
        status = "CURRENT";
        action = "load";
    } else if (compatibility == AXB_COMPAT_REASSEMBLE) {
        status = "ARCHIVAL";
        action = "reassemble-from-source";
    } else {
        status = "UNSUPPORTED";
        action = "refuse";
    }
    if (json) {
        printf("{\"schema\":\"axi.compat.v1\",\"format\":\"AXB\","
               "\"version\":%u,\"status\":\"%s\",\"action\":\"%s\"}\n",
               version, status, action);
    } else {
        printf("AXB %u %s %s\n", version, status, action);
    }
    return compatibility == AXB_COMPAT_CURRENT ? 0 : 1;
}

/* Opt-in lint has an explicit status contract: 0=no matched pattern,
 * 1=advisory warnings, 2=invalid source/read failure. Never means authorized. */
static int cmd_lint_safe(const char *path, int json, axi_compile_budget *budget)
{
    size_t len=0;
    char *src=read_file_budget(path,&len,budget);
    axi_diags ds;
    axi_node *unit;
    int rc;
    if (!src) { print_compile_read_error(path,json,budget); return 2; }
    axi_diags_init(&ds);
    unit=axi_parse_unit_budget(src,len,path,&ds,budget);
    if (unit && !ds.n && !ds.dropped) axi_type_check(unit,&ds);
    if (!unit || ds.n || ds.dropped) rc=2;
    else { axi_policy_lint(unit,&ds); rc=(ds.n || ds.dropped) ? 1 : 0; }
    if (json) print_diags_json(&ds,path); else print_diags_human(&ds,path);
    axi_ast_free(unit); (void)axi_compile_free(budget, src);
    return rc;
}

static int cmd_asm_budget(const char *in, const char *out_path,
                           const char *signing_key_path,
                           axi_compile_budget *budget)
{
    size_t len = 0;
    char *src = read_file_budget(in, &len, budget);
    axi_mem_account account;
    int rc;
    if (!src) { print_compile_read_error(in, 0, budget); return 2; }
    axi_compile_account_init(&account, budget);
    rc = axb_contract_v1_write_signed_text_accounted(src, len, in, out_path,
                                                    signing_key_path, &account);
    (void)axi_compile_free(budget, src);
    return rc;
}

static int dispatch(int argc, char **argv, axi_compile_budget *budget)
{
    if ((argc == 3 || (argc == 4 && strcmp(argv[3], "--json") == 0))
            && strcmp(argv[1], "lint-safe") == 0)
        return cmd_lint_safe(argv[2], argc == 4, budget);
    if (argc == 2 && strcmp(argv[1], "version") == 0) {
        printf("axial %s (axi) — Bear Core\n", AXI_VERSION);
        return 0;
    }
    if ((argc == 2 || (argc == 3 && strcmp(argv[2], "--json") == 0))
            && strcmp(argv[1], "abi-id") == 0) {
        uint8_t id[32];
        char hex[65];
        axb_artifact_abi_id(id);
        axi_hash_hex(id, hex);
        if (argc == 3)
            printf("{\"schema\":\"axi.artifact-abi-id.v1\",\"id\":\"%s\"}\n",
                   hex);
        else
            printf("%s\n", hex);
        return 0;
    }
    if ((argc == 3 || (argc == 4 && strcmp(argv[3], "--json") == 0))
            && strcmp(argv[1], "lex") == 0) {
        int json = (argc >= 4 && strcmp(argv[3], "--json") == 0);
        return cmd_lex(argv[2], json, budget);
    }
    if ((argc == 3 || (argc == 4 && strcmp(argv[3], "--json") == 0))
            && strcmp(argv[1], "parse") == 0) {
        int json = (argc >= 4 && strcmp(argv[3], "--json") == 0);
        return cmd_parse(argv[2], json, budget);
    }
    if (argc == 3 && strcmp(argv[1], "canon") == 0) {
        return cmd_canon(argv[2], budget);
    }
    if ((argc == 3 || (argc == 4 && strcmp(argv[3], "--json") == 0))
            && strcmp(argv[1], "check") == 0) {
        int json = (argc >= 4 && strcmp(argv[3], "--json") == 0);
        return cmd_check_impl(argv[2], json, 1, budget);
    }
    if ((argc == 3 || (argc == 4 && strcmp(argv[3], "--json") == 0))
            && strcmp(argv[1], "form") == 0) {
        int json = (argc >= 4 && strcmp(argv[3], "--json") == 0);
        return cmd_check_impl(argv[2], json, 0, budget);
    }
    if ((argc == 3 || (argc == 4 && strcmp(argv[3], "--json") == 0))
            && strcmp(argv[1], "types") == 0) {
        int json = (argc >= 4 && strcmp(argv[3], "--json") == 0);
        return cmd_types(argv[2], json, budget);
    }
    if (argc == 7 && strcmp(argv[1], "compile") == 0
            && strcmp(argv[3], "-o") == 0
            && strcmp(argv[5], "--signing-key") == 0) {
        return cmd_compile(argv[2], argv[4], argv[6], budget);
    }
    if ((argc == 3 || (argc == 4 && strcmp(argv[3], "--json") == 0))
            && strcmp(argv[1], "iface") == 0) {
        int json = (argc >= 4 && strcmp(argv[3], "--json") == 0);
        return cmd_iface(argv[2], json, budget);
    }
    if ((argc == 4 || (argc == 5 && strcmp(argv[4], "--json") == 0))
            && strcmp(argv[1], "iface-diff") == 0) {
        int json = (argc >= 5 && strcmp(argv[4], "--json") == 0);
        return cmd_iface_diff(argv[2], argv[3], json, budget);
    }
    if ((argc == 3 || (argc == 4 && strcmp(argv[3], "--json") == 0))
            && strcmp(argv[1], "compat") == 0) {
        int json = argc == 4;
        return cmd_compat(argv[2], json);
    }
    if (argc == 7 && strcmp(argv[1], "asm") == 0
            && strcmp(argv[3], "-o") == 0
            && strcmp(argv[5], "--signing-key") == 0) {
        return cmd_asm_budget(argv[2], argv[4], argv[6], budget);
    }
    if (argc == 8 && strcmp(argv[1], "migrate") == 0
            && strcmp(argv[4], "-o") == 0
            && strcmp(argv[6], "--signing-key") == 0) {
        return cmd_migrate_contract_v5(argv[2], argv[3], argv[5], argv[7]);
    }
    if (argc == 7 && strcmp(argv[1], "seal") == 0
            && strcmp(argv[3], "-o") == 0
            && strcmp(argv[5], "--signing-key") == 0) {
        return cmd_seal_contract_signed(argv[2], argv[4], argv[6]);
    }
    if (argc >= 3 && strcmp(argv[1], "dis") == 0) {
        if (argc == 5 && strcmp(argv[3], "--trusted-key") == 0)
            return cmd_dis_contract_trusted(argv[2], argv[4]);
        fprintf(AXI_ERR, "AXI-B025 dis requires --trusted-key KEYFILE\n");
        return 2;
    }
    if (argc >= 3 && strcmp(argv[1], "inspect") == 0) {
        if (argc == 5 && strcmp(argv[3], "--trusted-key") == 0)
            return cmd_inspect_contract_trusted(argv[2], argv[4]);
        fprintf(AXI_ERR, "AXI-B025 inspect requires --trusted-key KEYFILE\n");
        return 2;
    }
    if (argc == 2 && strcmp(argv[1], "selftest") == 0) {
        return axi_hash_selftest();
    }
    if (argc >= 2 && strcmp(argv[1], "bind") == 0) {
        if (argc == 6 && strcmp(argv[4], "--trusted-key") == 0)
            return cmd_bind_contract_trusted(argv[2], argv[3], argv[5]);
        fprintf(AXI_ERR, "AXI-B025 bind requires --trusted-key KEYFILE\n");
        return 2;
    }
    if (argc >= 2 && strcmp(argv[1], "verify") == 0) {
        if (argc == 5 && strcmp(argv[3], "--trusted-key") == 0)
            return cmd_verify_contract_trusted(argv[2], argv[4]);
        fprintf(AXI_ERR, "AXI-N001 verify requires --trusted-key KEYFILE\n");
        return 2;
    }
    if (argc >= 2 && strcmp(argv[1], "aer-verify") == 0) {
        if (argc == 5 && strcmp(argv[3], "--trusted-key") == 0)
            return cmd_aer_verify(argv[2], argv[4]);
        fprintf(AXI_ERR, "AXI-AER001 aer-verify requires --trusted-key KEYFILE\n");
        return 2;
    }
    if (argc >= 2 && strcmp(argv[1], "check-seal") == 0) {
        if (argc == 5 && strcmp(argv[3], "--trusted-key") == 0)
            return cmd_check_seal_contract_trusted(argv[2], argv[4]);
        fprintf(AXI_ERR, "AXI-S005 check-seal requires --trusted-key KEYFILE\n");
        return 2;
    }
    if (argc >= 4 && strcmp(argv[1], "run") == 0) {
        const char *trusted_key = NULL;
        /* INV-284 / AXI-INV-079: option values are skipped as values; none can
         * be rediscovered as a trust option by the outer dispatcher. */
        for (int i = 4; i < argc; i++) {
            if (strcmp(argv[i], "--") == 0) break;
            if (strcmp(argv[i], "--trusted-key") == 0) {
                if (trusted_key || i + 1 >= argc) {
                    fprintf(AXI_ERR, "AXI-R025 run accepts one --trusted-key KEYFILE\n");
                    return 2;
                }
                trusted_key = argv[++i];
            } else if (strcmp(argv[i], "--fuel") == 0
                    || strcmp(argv[i], "--mem") == 0
                    || strcmp(argv[i], "--effect-calls") == 0
                    || strcmp(argv[i], "--input-bytes") == 0
                    || strcmp(argv[i], "--output-bytes") == 0
                    || strcmp(argv[i], "--handles") == 0
                    || strcmp(argv[i], "--children") == 0
                    || strcmp(argv[i], "--deadline-ms") == 0
                    || strcmp(argv[i], "--fs-root") == 0
                    || strcmp(argv[i], "--cap") == 0
                    || strcmp(argv[i], "--record") == 0
                    || strcmp(argv[i], "--aer") == 0
                    || strcmp(argv[i], "--aer-key") == 0
                    || strcmp(argv[i], "--recorder-key") == 0) {
                if (++i >= argc) return 2;
            }
        }
        if (!trusted_key) {
            fprintf(AXI_ERR, "AXI-R025 run requires --trusted-key KEYFILE\n");
            return 2;
        }
        return cmd_run_contract_trusted(argv[2], argv[3], trusted_key,
                                        argc - 4, argv + 4);
    }
    if (argc >= 5 && strcmp(argv[1], "replay") == 0) {
        const char *trusted_key = NULL, *recorder_key = NULL;
        /* INV-284 / AXI-INV-079 */
        for (int i = 5; i < argc; i++) {
            if (strcmp(argv[i], "--") == 0) break;
            if (strcmp(argv[i], "--trusted-key") == 0) {
                if (trusted_key || i + 1 >= argc) return 2;
                trusted_key = argv[++i];
            } else if (strcmp(argv[i], "--recorder-key") == 0) {
                if (recorder_key || i + 1 >= argc) return 2;
                recorder_key = argv[++i];
            } else if (strcmp(argv[i], "--fuel") == 0
                    || strcmp(argv[i], "--mem") == 0
                    || strcmp(argv[i], "--effect-calls") == 0
                    || strcmp(argv[i], "--input-bytes") == 0
                    || strcmp(argv[i], "--output-bytes") == 0
                    || strcmp(argv[i], "--handles") == 0
                    || strcmp(argv[i], "--children") == 0
                    || strcmp(argv[i], "--deadline-ms") == 0
                    || strcmp(argv[i], "--fs-root") == 0
                    || strcmp(argv[i], "--aer") == 0
                    || strcmp(argv[i], "--cap") == 0) {
                if (++i >= argc) return 2;
            }
        }
        if (!trusted_key || !recorder_key) {
            fprintf(AXI_ERR, "AXI-R025 replay requires both --trusted-key and --recorder-key\n");
            return 2;
        }
        return cmd_replay_contract_trusted(argv[2], argv[3], argv[4],
                                           trusted_key, recorder_key,
                                           argc - 5, argv + 5);
    }
    if ((argc == 2 || (argc == 3 && strcmp(argv[2], "--json") == 0))
            && strcmp(argv[1], "caps") == 0) {
        return cmd_caps(argc >= 3 && strcmp(argv[2], "--json") == 0);
    }
    fprintf(AXI_ERR,
        "axial %s — the agent-first attested language (Bear Core)\n"
        "usage: axi lint-safe FILE [--json] | axi version | axi abi-id [--json] | axi lex FILE [--json] | axi parse FILE "
        "[--json]\n"
        "       axi canon FILE          print the one true form\n"
        "       axi form  FILE [--json] refuse non-canonical form "
        "(AXI-C0xx)\n"
        "       axi types FILE [--json] type laws only (AXI-T0xx)\n"
        "       axi check FILE [--json] the door: grammar + form + types\n"
        "       axi compile FILE.axi -o FILE.axb --signing-key SEED\n"
        "                 --compile-mem BYTES --compile-mem-report\n"
        "                 shared by lex/parse/canon/form/types/check/iface/iface-diff/lint-safe/asm\n"
        "       axi iface FILE [--json]        the contract, derived + hashed\n"
        "       axi iface-diff OLD NEW [--json]  may NEW replace OLD? "
        "(1 = breaking)\n"
        "       axi compat FILE.axb [--json]  report load/migration policy\n"
        "       axi aer-verify FILE.aer --trusted-key PK\n"
        "       axi asm FILE.axs -o FILE.axb --signing-key SEED\n"
        "       axi migrate OLD.axb SOURCE.axs -o NEW.axb --signing-key SEED\n"
        "       axi seal FILE.axs -o FILE.axb --signing-key SEED  check law_* and emit AXPC "
        "(AXI-S0xx)\n"
        "       axi dis FILE.axb --trusted-key PK  signed v7 contract text\n"
        "       axi inspect FILE.axb --trusted-key PK  admitted v7 facts\n"
        "       axi bind FILE.axb FILE.axs --trusted-key PK  prove source "
        "claim (AXI-B016)\n"
        "       axi run FILE.axb CELL [ARGS..] --trusted-key PK\n"
        "                 --cap Name.Verb      authorise ONE effect (repeat)\n"
        "                 --json               read one str arg from stdin\n"
        "                 --fuel N --fuel-report --mem N --mem-report\n"
        "                 --effect-calls N --input-bytes N --output-bytes N\n"
        "                 --handles N --children N --deadline-ms N\n"
        "                 --trace              print deterministic witness\n"
        "                 --ledger[-json]      print the receipt + tip\n"
        "                 --record PATH.axr --recorder-key SEED\n"
        "                                      sign replay evidence (MOAT-4)\n"
        "                 --aer PATH.aer --aer-key SEED\n"
        "                                      publish signed canonical AER1\n"
        "       axi replay TRACE.axr FILE.axb CELL [--trace]\n"
        "                 --trusted-key PK --recorder-key PK  signed v7 replay\n"
        "                                    re-run using recorded I/O\n"
        "       axi verify FILE.axb --trusted-key PK  producer signature only\n"
        "       axi check-seal FILE.axb --trusted-key PK  re-execute AXPC laws\n"
        "       axi caps [--json]              what this build can do at all\n"
        "       axi selftest                   prove SHA-256 (FIPS 180-4)\n",
        AXI_VERSION);
    return 2;
}

/* A successful computation is not a published result until stdio flushes.
 * Preserve normal semantic exit codes; publication failure is a CLI error. */
static int is_compiler_command(const char *command)
{
    static const char *const commands[] = {
        "lex", "parse", "canon", "form", "types", "check", "compile",
        "iface", "iface-diff", "lint-safe", "asm"
    };
    for (size_t i = 0; i < sizeof commands / sizeof commands[0]; i++)
        if (!strcmp(command, commands[i])) return 1;
    return 0;
}

static int compile_options(int *argc, char **argv, int enabled,
                           size_t *limit, int *report, int *json)
{
    int set_limit = 0, output, first_option;
    *limit = AXI_COMPILE_DEFAULT_LIMIT;
    *report = 0;
    *json = 0;
    /* Runtime commands own their complete argv, including values and the
     * `--` positional boundary. Compiler options follow the required FILE
     * arguments; a file or an option value may itself have an option name. */
    if (!enabled) return 0;
    first_option = !strcmp(argv[1], "iface-diff") ? 4 : 3;
    output = *argc < first_option ? *argc : first_option;
    for (int i = output; i < *argc; i++) {
        if (!strcmp(argv[i], "-o") || !strcmp(argv[i], "--signing-key")) {
            argv[output++] = argv[i];
            if (i + 1 < *argc) argv[output++] = argv[++i];
        } else if (!strcmp(argv[i], "--compile-mem")) {
            const char *p;
            size_t value = 0;
            if (set_limit || ++i == *argc || !*argv[i]) return 1;
            p = argv[i];
            while (*p >= '0' && *p <= '9') {
                size_t digit = (size_t)(*p++ - '0');
                if (value > (SIZE_MAX - digit) / 10) return 1;
                value = value * 10 + digit;
            }
            if (*p) return 1;
            *limit = value;
            set_limit = 1;
        } else if (!strcmp(argv[i], "--compile-mem-report")) {
            if (*report) return 1;
            *report = 1;
        } else {
            if (!strcmp(argv[i], "--json")) *json = 1;
            argv[output++] = argv[i];
        }
    }
    *argc = output;
    argv[output] = NULL;
    return 0;
}

int main(int argc, char **argv)
{
    axi_compile_budget budget;
    int compile = argc > 1 && is_compiler_command(argv[1]);
    int report, json, rc;
    size_t limit;
    /* This is a reservation for the bounded CLI diagnostic and lexical
     * workspaces, not a promise to cap all C stack or process RSS. */
    const size_t workspace = sizeof budget + 2 * sizeof(axi_diags)
                            + sizeof(axi_lexer) + sizeof(axi_token)
                            + (compile && !strcmp(argv[1], "lex")
                               ? AXI_NUMERIC_SCRATCH_BYTES : 0);
    if (compile_options(&argc, argv, compile, &limit, &report, &json) != 0) {
        fprintf(AXI_ERR, "AXI-X005 invalid or repeated compiler memory option\n");
        return 2;
    }
    if (compile) {
        axi_compile_budget_init(&budget, limit);
        if (axi_compile_reserve(&budget, workspace)) {
            rc = dispatch(argc, argv, &budget);
            (void)axi_compile_release(&budget, workspace);
        } else {
            print_compile_failure(argc > 2 ? argv[2] : "<compiler>", json, &budget);
            rc = 2;
        }
        if (budget.live != 0)
            axi_compile_fail(&budget, AXI_COMPILE_OWNERSHIP, budget.live);
        if (budget.failure != AXI_COMPILE_OK) {
            fprintf(AXI_ERR, "%s %s (limit=%zu, peak=%zu, requested=%zu)\n",
                    axi_compile_failure_code(&budget), compile_failure_message(&budget),
                    budget.limit, budget.peak, budget.failed_request);
            rc = 2;
        }
        if (report)
            fprintf(AXI_ERR, "{\"schema\":\"axi.compiler-memory.v1\",\"limit\":%zu,"
                "\"peak\":%zu,\"live\":%zu,\"allocations\":%zu,\"fixed\":%zu,"
                "\"failure\":\"%s\"}\n", budget.limit, budget.peak, budget.live,
                budget.allocations, budget.fixed, axi_compile_failure_code(&budget));
        axi_compile_budget_destroy(&budget);
    } else rc = dispatch(argc, argv, NULL);
    if (fflush(AXI_OUT) != 0 || ferror(AXI_OUT)) {
        fprintf(AXI_ERR, "AXI-X004 cannot publish CLI output\n");
        return 2;
    }
    return rc;
}
