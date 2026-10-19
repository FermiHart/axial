/* axial - independent, non-executing AXB v7 observer.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * INV-424 / AXI-INV-134: a dossier rederives signed artifact facts through a
 * bounded parser of its own. It never enters the AXB loader, VM, runtime,
 * effect, replay, or platform doors, and never executes an instruction.
 */
#include "axi_dossier.h"
#include "axi_checker_identity.h"
#include "axi_hash.h"
#include "ed25519.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define D_BODY_MAX       (1024u * 1024u)
#define D_JSON_MAX       (64u * 1024u * 1024u)
#define D_TRAILER        104u
#define D_MANIFEST_MAX   (16u * 1024u)
#define D_NAME_MAX       63u
#define D_LAW_MAX        4096u
#define D_CELLS_MAX      256u
#define D_TABLE_MAX      64u
#define D_PARAMS_MAX     16u
#define D_RETURNS_MAX    16u
#define D_ERRORS_MAX     16u
#define D_LAWS_MAX       64u
#define D_REGS_MAX       256u
#define D_CONSTS_MAX     65536u
#define D_CERT_MAX       (16u * 1024u)
#define D_CERT_FUEL_MAX  1000000ull

#define D_OP_CALL        14u
#define D_OP_EFF         20u
#define D_OP_BUILTIN     21u
#define D_OP_COUNT       23u

typedef struct {
    const uint8_t *p;
    uint32_t n;
} d_slice;

typedef struct {
    uint8_t tag;
    d_slice name;
} d_type;

typedef struct {
    d_slice name;
    d_type type;
} d_param;

typedef struct {
    uint32_t version;
    uint32_t flags;
    uint64_t fuel;
    uint32_t nparams;
    d_param params[D_PARAMS_MAX];
    uint32_t nreturns;
    d_type returns[D_RETURNS_MAX];
    uint32_t nerrors;
    d_slice errors[D_ERRORS_MAX];
    uint32_t ncaps;
    d_slice caps[D_TABLE_MAX];
    uint32_t nlaws;
    d_slice laws[D_LAWS_MAX];
    uint8_t iface_hash[32];
    uint8_t body_hash[32];
    size_t iface_off;
    size_t body_off;
} d_manifest;

typedef struct {
    d_slice name;
    d_manifest manifest;
    uint32_t nregs;
    uint32_t nk;
    uint32_t ncode;
    size_t name_wire_off;
    size_t tail_off;
    size_t end_off;
    size_t code_off;
    d_slice closure[D_TABLE_MAX];
    uint32_t nclosure;
} d_cell;

typedef struct {
    uint32_t cell_index;
    d_slice name;
    uint8_t iface_hash[32];
    uint8_t body_hash[32];
    uint64_t budget;
    uint64_t fuel_used;
    uint32_t result_kind;
    uint32_t verdict;
} d_cert_law;

typedef struct {
    int present;
    uint32_t version;
    uint32_t maturity;
    uint8_t subject_root[32];
    uint8_t protocol_id[32];
    uint8_t semantics_root[32];
    uint64_t aggregate_budget;
    uint64_t aggregate_fuel;
    uint32_t law_count;
    d_cert_law laws[D_LAWS_MAX];
} d_certificate;

typedef struct {
    const uint8_t *body;
    size_t body_len;
    uint8_t source_hash[32];
    uint8_t ir_hash[32];
    uint8_t compiler_hash[32];
    uint8_t body_hash[32];
    uint32_t neffects;
    d_slice effects[D_TABLE_MAX];
    uint32_t nbuiltins;
    d_slice builtins[D_TABLE_MAX];
    uint32_t ncells;
    d_cell *cells;
    size_t certificate_offset;
    d_certificate certificate;
    uint64_t reaches[D_CELLS_MAX][D_CELLS_MAX / 64];
} d_module;

typedef struct {
    const char *code;
    const char *reason;
    size_t offset;
} d_failure;

typedef struct {
    const uint8_t *p;
    size_t end;
    size_t off;
    d_failure *failure;
} d_reader;

typedef struct {
    char *p;
    size_t n;
    size_t cap;
    size_t max;
    int failed; /* 1 allocation, 2 bound */
} d_buf;

typedef struct {
    const char *name;
    uint8_t arity;
    const char *cap;
} d_builtin;

static const d_builtin D_BUILTINS[] = {
    {"fs.path_under", 2, "fs.Read"},
    {"json.get", 2, NULL},
    {NULL, 0, NULL}
};

static void d_set_failure(d_failure *f, const char *code, size_t offset,
                          const char *reason)
{
    if (!f->code) {
        f->code = code;
        f->offset = offset;
        f->reason = reason;
    }
}

static int d_need(d_reader *r, size_t n, const char *reason)
{
    if (r->off > r->end || n > r->end - r->off) {
        d_set_failure(r->failure, "DOS-004", r->off, reason);
        return 0;
    }
    return 1;
}

static uint8_t d_u8(d_reader *r)
{
    if (!d_need(r, 1, "truncated byte field")) return 0;
    return r->p[r->off++];
}

static uint32_t d_u32(d_reader *r)
{
    const uint8_t *p;
    if (!d_need(r, 4, "truncated u32 field")) return 0;
    p = r->p + r->off;
    r->off += 4;
    return (uint32_t)p[0] | (uint32_t)p[1] << 8
         | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t d_u64(d_reader *r)
{
    uint64_t lo = d_u32(r);
    uint64_t hi = d_u32(r);
    return lo | hi << 32;
}

static uint32_t d_load_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8
         | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t d_load_u64(const uint8_t *p)
{
    return (uint64_t)d_load_u32(p) | (uint64_t)d_load_u32(p + 4) << 32;
}

static int d_read_slice(d_reader *r, uint32_t max, d_slice *out,
                        const char *reason)
{
    uint32_t n = d_u32(r);
    if (r->failure->code) return 0;
    if (n == 0 || n > max || !d_need(r, n, reason)) {
        if (!r->failure->code)
            d_set_failure(r->failure, "DOS-009", r->off - 4, reason);
        return 0;
    }
    out->p = r->p + r->off;
    out->n = n;
    r->off += n;
    return 1;
}

static int d_slice_cmp(d_slice a, d_slice b)
{
    uint32_t n = a.n < b.n ? a.n : b.n;
    int c = memcmp(a.p, b.p, n);
    if (c) return c;
    return a.n < b.n ? -1 : a.n > b.n;
}

static int d_slice_eq(d_slice a, d_slice b)
{
    return a.n == b.n && memcmp(a.p, b.p, a.n) == 0;
}

static int d_name_ok(d_slice s, int dotted, int one_dot)
{
    uint32_t i, dots = 0;
    int first = 1;
    if (!s.p || s.n == 0 || s.n > D_NAME_MAX) return 0;
    for (i = 0; i < s.n; i++) {
        unsigned char c = s.p[i];
        if (dotted && c == '.') {
            if (first || i + 1 == s.n || (one_dot && ++dots > 1)) return 0;
            if (!one_dot) dots++;
            first = 1;
        } else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                   || c == '_' || (!first && c >= '0' && c <= '9')) {
            first = 0;
        } else {
            return 0;
        }
    }
    return !first;
}

static int d_law_ok(d_slice s)
{
    uint32_t i;
    if (!s.p || s.n == 0 || s.n > D_LAW_MAX) return 0;
    for (i = 0; i < s.n; i++)
        if (s.p[i] == 0 || s.p[i] == 0x7f || s.p[i] == '\n'
                || s.p[i] == '\r' || s.p[i] < 0x20) return 0;
    return 1;
}

static int d_type_ok(const d_type *t, int parameter)
{
    if (t->tag >= 1 && t->tag <= 8) return t->name.n == 0;
    if (!parameter && t->tag == 9) return t->name.n == 0;
    if (parameter && t->tag == 10) return d_name_ok(t->name, 1, 1);
    return 0;
}

static int d_parse_type(d_reader *r, d_type *type, int parameter)
{
    memset(type, 0, sizeof *type);
    type->tag = d_u8(r);
    if (r->failure->code) return 0;
    if (type->tag == 10
            && !d_read_slice(r, D_NAME_MAX, &type->name,
                             "invalid capability type name")) return 0;
    if (!d_type_ok(type, parameter)) {
        d_set_failure(r->failure, "DOS-011", r->off ? r->off - 1 : 0,
                      "invalid manifest type atom");
        return 0;
    }
    return 1;
}

static int d_parse_manifest(d_reader *r, size_t end, d_manifest *m)
{
    uint32_t i, j;
    size_t start = r->off;
    if (end < start || end - start == 0 || end - start > D_MANIFEST_MAX) {
        d_set_failure(r->failure, "DOS-010", start,
                      "manifest length is outside the v1 bound");
        return 0;
    }
    r->end = end;
    memset(m, 0, sizeof *m);
    m->version = d_u32(r);
    m->flags = d_u32(r);
    m->fuel = d_u64(r);
    m->nparams = d_u32(r);
    if (r->failure->code) return 0;
    if (m->version != 1 || m->flags > 3 || m->flags == 3 || m->fuel == 0
            || m->nparams > D_PARAMS_MAX) {
        d_set_failure(r->failure, "DOS-011", start,
                      "invalid manifest version, flags, fuel, or parameter count");
        return 0;
    }
    for (i = 0; i < m->nparams; i++) {
        if (!d_read_slice(r, D_NAME_MAX, &m->params[i].name,
                          "invalid parameter name")
                || !d_name_ok(m->params[i].name, 0, 0)
                || !d_parse_type(r, &m->params[i].type, 1)) {
            if (!r->failure->code)
                d_set_failure(r->failure, "DOS-011", r->off,
                              "invalid manifest parameter");
            return 0;
        }
        for (j = 0; j < i; j++)
            if (d_slice_eq(m->params[j].name, m->params[i].name)) {
                d_set_failure(r->failure, "DOS-011", r->off,
                              "duplicate manifest parameter name");
                return 0;
            }
    }
    m->nreturns = d_u32(r);
    if (r->failure->code || m->nreturns > D_RETURNS_MAX) goto invalid;
    for (i = 0; i < m->nreturns; i++) {
        if (!d_parse_type(r, &m->returns[i], 0)) return 0;
        if (i && m->returns[i - 1].tag >= m->returns[i].tag) goto invalid;
    }
    m->nerrors = d_u32(r);
    if (r->failure->code || m->nerrors > D_ERRORS_MAX) goto invalid;
    for (i = 0; i < m->nerrors; i++) {
        if (!d_read_slice(r, D_NAME_MAX, &m->errors[i], "invalid error atom")
                || !d_name_ok(m->errors[i], 1, 1)
                || (i && d_slice_cmp(m->errors[i - 1], m->errors[i]) >= 0))
            goto invalid;
    }
    m->ncaps = d_u32(r);
    if (r->failure->code || m->ncaps > D_TABLE_MAX) goto invalid;
    for (i = 0; i < m->ncaps; i++) {
        if (!d_read_slice(r, D_NAME_MAX, &m->caps[i], "invalid capability atom")
                || !d_name_ok(m->caps[i], 1, 1)
                || (i && d_slice_cmp(m->caps[i - 1], m->caps[i]) >= 0))
            goto invalid;
    }
    m->nlaws = d_u32(r);
    if (r->failure->code || m->nlaws > D_LAWS_MAX) goto invalid;
    for (i = 0; i < m->nlaws; i++) {
        if (!d_read_slice(r, D_LAW_MAX, &m->laws[i], "invalid canonical law")
                || !d_law_ok(m->laws[i])
                || (i && d_slice_cmp(m->laws[i - 1], m->laws[i]) >= 0))
            goto invalid;
    }
    if (m->nreturns + m->nerrors == 0) goto invalid;
    if (!d_need(r, 64, "truncated manifest hashes")) return 0;
    m->iface_off = r->off;
    memcpy(m->iface_hash, r->p + r->off, 32);
    r->off += 32;
    m->body_off = r->off;
    memcpy(m->body_hash, r->p + r->off, 32);
    r->off += 32;
    if (r->off != end) {
        d_set_failure(r->failure, "DOS-012", r->off,
                      "manifest has trailing or unconsumed bytes");
        return 0;
    }
    return 1;
invalid:
    if (!r->failure->code)
        d_set_failure(r->failure, "DOS-011", r->off,
                      "manifest violates v1 canonical bounds or ordering");
    return 0;
}

static int d_parse_name_table(d_reader *r, d_slice *table, uint32_t *count,
                              const char *kind)
{
    uint32_t i, j;
    *count = d_u32(r);
    if (r->failure->code) return 0;
    if (*count > D_TABLE_MAX) {
        d_set_failure(r->failure, "DOS-008", r->off - 4, kind);
        return 0;
    }
    for (i = 0; i < *count; i++) {
        if (!d_read_slice(r, D_NAME_MAX, &table[i], kind)
                || !d_name_ok(table[i], 1, 0)) {
            if (!r->failure->code)
                d_set_failure(r->failure, "DOS-009", r->off, kind);
            return 0;
        }
        for (j = 0; j < i; j++)
            if (d_slice_eq(table[j], table[i])) {
                d_set_failure(r->failure, "DOS-009", r->off,
                              "duplicate module declaration");
                return 0;
            }
    }
    return 1;
}

static int d_string_constant_ok(const uint8_t *p, uint32_t n)
{
    uint32_t i;
    for (i = 0; i < n; i++)
        if (p[i] < 0x20 || p[i] == 0x7f) return 0;
    return 1;
}

static int d_parse_certificate(d_reader *r, size_t end,
                               d_certificate *cert)
{
    uint32_t i;
    if (!d_need(r, 4, "truncated AXPC magic")
            || memcmp(r->p + r->off, "AXPC", 4) != 0) {
        d_set_failure(r->failure, "DOS-028", r->off, "bad AXPC magic");
        return 0;
    }
    r->off += 4;
    cert->present = 1;
    cert->version = d_u32(r);
    cert->maturity = d_u32(r);
    if (!d_need(r, 96, "truncated AXPC identities")) return 0;
    memcpy(cert->subject_root, r->p + r->off, 32); r->off += 32;
    memcpy(cert->protocol_id, r->p + r->off, 32); r->off += 32;
    memcpy(cert->semantics_root, r->p + r->off, 32); r->off += 32;
    cert->aggregate_budget = d_u64(r);
    cert->aggregate_fuel = d_u64(r);
    cert->law_count = d_u32(r);
    if (r->failure->code || cert->version != 1 || cert->maturity != 1
            || cert->law_count == 0 || cert->law_count > D_LAWS_MAX) {
        d_set_failure(r->failure, "DOS-028", r->off,
                      "AXPC version, maturity or law count is not canonical");
        return 0;
    }
    for (i = 0; i < cert->law_count; i++) {
        d_cert_law *law = &cert->laws[i];
        law->cell_index = d_u32(r);
        if (!d_read_slice(r, D_NAME_MAX, &law->name,
                          "invalid AXPC law name")
                || !d_name_ok(law->name, 0, 0)
                || !d_need(r, 64, "truncated AXPC law hashes"))
            return 0;
        memcpy(law->iface_hash, r->p + r->off, 32); r->off += 32;
        memcpy(law->body_hash, r->p + r->off, 32); r->off += 32;
        law->budget = d_u64(r);
        law->fuel_used = d_u64(r);
        law->result_kind = d_u32(r);
        law->verdict = d_u32(r);
        if (r->failure->code) return 0;
    }
    if (r->off != end) {
        d_set_failure(r->failure, "DOS-028", r->off,
                      "AXPC does not end at its declared boundary");
        return 0;
    }
    return 1;
}

static int d_parse_module(d_module *m, d_failure *failure)
{
    d_reader r;
    uint32_t i, j;
    r.p = m->body;
    r.end = m->body_len;
    r.off = 0;
    r.failure = failure;
    if (!d_need(&r, 8, "truncated AXB header")
            || memcmp(m->body, "AXB0", 4) != 0) {
        d_set_failure(failure, "DOS-002", 0, "bad AXB magic");
        return 0;
    }
    r.off = 4;
    if (d_u32(&r) != 7) {
        d_set_failure(failure, "DOS-003", 4, "observer accepts exact AXB version 7 only");
        return 0;
    }
    if (!d_need(&r, 32 + 96, "truncated source provenance hash")) return 0;
    memcpy(m->source_hash, r.p + r.off, 32);
    r.off += 32;
    memcpy(m->ir_hash, r.p + r.off, 32);
    r.off += 32;
    memcpy(m->compiler_hash, r.p + r.off, 32);
    r.off += 32;
    memcpy(m->body_hash, r.p + r.off, 32);
    r.off += 32;
    if (!d_parse_name_table(&r, m->effects, &m->neffects,
                            "invalid effect table")
            || !d_parse_name_table(&r, m->builtins, &m->nbuiltins,
                                   "invalid builtin table")) return 0;
    m->ncells = d_u32(&r);
    if (failure->code) return 0;
    if (m->ncells == 0 || m->ncells > D_CELLS_MAX
            || m->ncells > m->body_len / 8) {
        d_set_failure(failure, "DOS-013", r.off - 4,
                      "cell count is outside the v7 bound");
        return 0;
    }
    m->cells = (d_cell *)calloc(m->ncells, sizeof *m->cells);
    if (!m->cells) return -1;
    for (i = 0; i < m->ncells; i++) {
        d_cell *c = &m->cells[i];
        uint32_t manifest_len;
        size_t manifest_end;
        c->name_wire_off = r.off;
        if (!d_read_slice(&r, D_NAME_MAX, &c->name, "invalid cell name")
                || !d_name_ok(c->name, 0, 0)) {
            if (!failure->code)
                d_set_failure(failure, "DOS-014", r.off, "invalid cell name");
            return 0;
        }
        for (j = 0; j < i; j++)
            if (d_slice_eq(m->cells[j].name, c->name)) {
                d_set_failure(failure, "DOS-014", c->name_wire_off,
                              "duplicate cell name");
                return 0;
            }
        manifest_len = d_u32(&r);
        if (failure->code) return 0;
        if (manifest_len == 0 || manifest_len > D_MANIFEST_MAX
                || manifest_len > r.end - r.off) {
            d_set_failure(failure, "DOS-010", r.off - 4,
                          "manifest length is outside the v1 bound");
            return 0;
        }
        manifest_end = r.off + manifest_len;
        if (!d_parse_manifest(&r, manifest_end, &c->manifest)) return 0;
        r.end = m->body_len;
        c->tail_off = r.off;
        c->nregs = d_u32(&r);
        c->nk = d_u32(&r);
        if (failure->code) return 0;
        if (c->nregs > D_REGS_MAX || c->nk > D_CONSTS_MAX
                || c->nk > m->body_len / 5) {
            d_set_failure(failure, "DOS-015", c->tail_off,
                          "register or constant count exceeds its bound");
            return 0;
        }
        for (j = 0; j < c->nk; j++) {
            uint8_t tag = d_u8(&r);
            if (failure->code) return 0;
            if (tag < 1 || tag > 5) {
                d_set_failure(failure, "DOS-016", r.off - 1,
                              "unknown constant tag");
                return 0;
            }
            if (tag == 4 || tag == 5) {
                uint32_t n = d_u32(&r);
                size_t at = r.off;
                if (failure->code || !d_need(&r, n, "truncated string constant")) return 0;
                if (!d_string_constant_ok(r.p + r.off, n)) {
                    d_set_failure(failure, "DOS-016", at,
                                  "string constant cannot be rendered canonically");
                    return 0;
                }
                r.off += n;
            } else if (!d_need(&r, 8, "truncated scalar constant")) {
                return 0;
            } else {
                r.off += 8;
            }
        }
        c->ncode = d_u32(&r);
        if (failure->code || c->ncode > m->body_len / 4) {
            if (!failure->code)
                d_set_failure(failure, "DOS-017", r.off - 4,
                              "code count exceeds the module bound");
            return 0;
        }
        c->code_off = r.off;
        if (!d_need(&r, (size_t)c->ncode * 4, "truncated instruction words")) return 0;
        r.off += (size_t)c->ncode * 4;
        c->end_off = r.off;
        if ((c->nregs ? c->nregs : 1) < c->manifest.nparams) {
            d_set_failure(failure, "DOS-018", c->tail_off,
                          "cell register file is smaller than its parameter list");
            return 0;
        }
    }
    m->certificate_offset = r.off;
    {
        uint32_t certificate_len = d_u32(&r);
        size_t certificate_end;
        if (failure->code || certificate_len > D_CERT_MAX
                || certificate_len > r.end - r.off) {
            d_set_failure(failure, "DOS-028", m->certificate_offset,
                          "AXPC length exceeds its exact bound");
            return 0;
        }
        certificate_end = r.off + certificate_len;
        if (certificate_len
                && !d_parse_certificate(&r, certificate_end, &m->certificate))
            return 0;
    }
    if (r.off != m->body_len) {
        d_set_failure(failure, "DOS-005", r.off,
                      "body does not end exactly at the AXBS trailer");
        return 0;
    }
    return 1;
}

static const d_builtin *d_builtin_find(d_slice name)
{
    size_t i;
    for (i = 0; D_BUILTINS[i].name; i++) {
        size_t n = strlen(D_BUILTINS[i].name);
        if (n == name.n && memcmp(name.p, D_BUILTINS[i].name, n) == 0)
            return &D_BUILTINS[i];
    }
    return NULL;
}

static int d_closure_add(d_cell *c, d_slice cap)
{
    uint32_t i;
    for (i = 0; i < c->nclosure; i++)
        if (d_slice_eq(c->closure[i], cap)) return 1;
    if (c->nclosure == D_TABLE_MAX) return 0;
    c->closure[c->nclosure++] = cap;
    return 1;
}

static int d_manifest_cap_index(const d_manifest *manifest, d_slice cap)
{
    uint32_t lo = 0, hi = manifest->ncaps;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        int cmp = d_slice_cmp(manifest->caps[mid], cap);
        if (cmp < 0) lo = mid + 1;
        else if (cmp > 0) hi = mid;
        else return (int)mid;
    }
    return -1;
}

static int d_verify_opcodes(d_module *m, d_failure *failure)
{
    uint32_t i, pc, pass;
    for (i = 0; i < m->ncells; i++) {
        d_cell *c = &m->cells[i];
        uint32_t nr = c->nregs ? c->nregs : 1;
        uint32_t p;
        for (p = 0; p < c->manifest.nparams; p++)
            if (c->manifest.params[p].type.tag == 10
                    && !d_closure_add(c, c->manifest.params[p].type.name)) {
                d_set_failure(failure, "DOS-024", c->tail_off,
                              "capability closure exceeds 64 atoms");
                return 0;
            }
        for (pc = 0; pc < c->ncode; pc++) {
            size_t off = c->code_off + (size_t)pc * 4;
            uint32_t w = d_load_u32(m->body + off);
            uint8_t op = (uint8_t)w;
            uint8_t a = (uint8_t)(w >> 8);
            uint8_t b = (uint8_t)(w >> 16);
            uint8_t cc = (uint8_t)(w >> 24);
            uint16_t bc = (uint16_t)((uint16_t)b << 8 | cc);
            int64_t target;
            int ok = 1;
            if (op >= D_OP_COUNT) ok = 0;
            else if (op == 0 || op == 22) ok = a == 0 && b == 0 && cc == 0;
            else if (op == 15) ok = a < nr && b == 0 && cc == 0;
            else if (op == 2 || op == 8 || (op >= 17 && op <= 19))
                ok = a < nr && b < nr && cc == 0;
            else if ((op >= 3 && op <= 7) || (op >= 9 && op <= 11) || op == 16)
                ok = a < nr && b < nr && cc < nr;
            else if (op == 1) ok = a < nr && bc < c->nk;
            else if (op == 12) {
                target = (int64_t)pc + (int16_t)bc;
                ok = a == 0 && target >= 0 && target < c->ncode;
            } else if (op == 13) {
                target = (int64_t)pc + (int16_t)bc;
                ok = a < nr && target >= 0 && target < c->ncode;
            } else if (op == D_OP_CALL) {
                ok = a < nr && b < m->ncells && cc <= D_PARAMS_MAX
                    && a + (uint32_t)cc <= nr;
                if (ok && cc != m->cells[b].manifest.nparams) {
                    d_set_failure(failure, "DOS-020", off,
                                  "CALL argc differs from callee manifest arity");
                    return 0;
                }
                if (ok) m->reaches[i][b / 64] |= UINT64_C(1) << (b % 64);
            } else if (op == D_OP_EFF) {
                ok = a < nr && b < m->neffects && cc < nr;
                if (ok && !d_closure_add(c, m->effects[b])) {
                    d_set_failure(failure, "DOS-024", off,
                                  "capability closure exceeds 64 atoms");
                    return 0;
                }
            } else if (op == D_OP_BUILTIN) {
                const d_builtin *bi = b < m->nbuiltins
                    ? d_builtin_find(m->builtins[b]) : NULL;
                ok = a < nr && b < m->nbuiltins && cc < nr && bi
                    && cc + (uint32_t)bi->arity <= nr;
                if (ok && bi->cap) {
                    d_slice cap;
                    cap.p = (const uint8_t *)bi->cap;
                    cap.n = (uint32_t)strlen(bi->cap);
                    if (!d_closure_add(c, cap)) {
                        d_set_failure(failure, "DOS-024", off,
                                      "capability closure exceeds 64 atoms");
                        return 0;
                    }
                }
            }
            if (!ok) {
                d_set_failure(failure, "DOS-019", off,
                              "invalid opcode, operand shape, index, or register window");
                return 0;
            }
        }
    }
    for (pass = 0; pass < m->ncells; pass++) {
        uint32_t from;
        for (from = 0; from < m->ncells; from++)
            if (m->reaches[from][pass / 64]
                    & (UINT64_C(1) << (pass % 64))) {
                uint32_t word;
                for (word = 0; word < D_CELLS_MAX / 64; word++)
                    m->reaches[from][word] |= m->reaches[pass][word];
            }
    }
    for (i = 0; i < m->ncells; i++) {
        d_cell *c = &m->cells[i];
        uint32_t callee, k;
        uint64_t seen = 0;
        for (k = 0; k < c->nclosure; k++) {
            int at = d_manifest_cap_index(&c->manifest, c->closure[k]);
            if (at < 0) goto caps_bad;
            seen |= UINT64_C(1) << (uint32_t)at;
        }
        /* Reachability was already closed as a 256x256 bit matrix. Merge each
         * callee's local authority once instead of rescanning all code 256 times. */
        for (callee = 0; callee < m->ncells; callee++)
            if (m->reaches[i][callee / 64]
                    & (UINT64_C(1) << (callee % 64)))
                for (k = 0; k < m->cells[callee].nclosure; k++) {
                    int at = d_manifest_cap_index(&c->manifest,
                                                  m->cells[callee].closure[k]);
                    if (at < 0) goto caps_bad;
                    seen |= UINT64_C(1) << (uint32_t)at;
                }
        if (seen != (c->manifest.ncaps == 64 ? UINT64_MAX
                                             : (UINT64_C(1) << c->manifest.ncaps) - 1))
            goto caps_bad;
        if ((c->manifest.flags & 1u) && seen != 0) {
            d_set_failure(failure, "DOS-025", c->tail_off,
                          "PURE cell has a non-empty transitive authority closure");
            return 0;
        }
        continue;
caps_bad:
        d_set_failure(failure, "DOS-024", c->tail_off,
                      "manifest caps differ from rederived transitive authority");
        return 0;
    }
    return 1;
}

static size_t d_digits(uint64_t v)
{
    char text[32];
    int n = snprintf(text, sizeof text, "%llu", (unsigned long long)v);
    return n > 0 ? (size_t)n : 0;
}

static size_t d_hex_digits(uint64_t v)
{
    size_t n = 1;
    while (v >= 16) { v >>= 4; n++; }
    return n;
}

static const char *d_type_name(uint8_t tag);

static int d_text_add(size_t *n, size_t add)
{
    if (*n > D_BODY_MAX || add > D_BODY_MAX - *n) return 0;
    *n += add;
    return 1;
}

static size_t d_type_text_len(const d_type *type)
{
    const char *name = d_type_name(type->tag);
    return name ? strlen(name) : 4u + type->name.n;
}

static int d_verify_text_bound(const d_module *m, d_failure *failure)
{
    static const char *const opnames[D_OP_COUNT] = {
        "nop", "ldk", "mov", "add", "sub", "mul", "div", "mod",
        "not", "eq", "lt", "le", "jmp", "jf", "call", "ret",
        "umake", "utag", "upay", "uchk", "eff", "builtin", "halt"
    };
    size_t text = 0;
    uint32_t i, j;
    for (i = 0; i < m->neffects; i++)
        if (!d_text_add(&text, 6u + m->effects[i].n)) goto too_large;
    for (i = 0; i < m->nbuiltins; i++)
        if (!d_text_add(&text, 10u + m->builtins[i].n)) goto too_large;
    if ((m->neffects || m->nbuiltins) && !d_text_add(&text, 1)) goto too_large;
    for (i = 0; i < m->ncells; i++) {
        const d_cell *c = &m->cells[i];
        const uint8_t *p = m->body + c->tail_off + 8;
        if (i && !d_text_add(&text, 1)) goto too_large;
        if (!d_text_add(&text, 13u + c->name.n + d_digits(c->nregs))) goto too_large;
        for (j = 0; j < c->nk; j++) {
            uint8_t tag = *p++;
            size_t line = 3u + d_digits(j) + 5u + 1u;
            if (tag == 4 || tag == 5) {
                uint32_t n = d_load_u32(p);
                uint32_t k;
                p += 4;
                line += 2u + n;
                for (k = 0; k < n; k++)
                    if (p[k] == '"' || p[k] == '\\') line++;
                p += n;
            } else {
                uint64_t v = d_load_u64(p);
                p += 8;
                if (tag == 1) line += d_digits(v);
                else if (tag == 2)
                    line += (v >> 63 ? 1u + d_digits((uint64_t)0 - v) : d_digits(v));
                else line += d_hex_digits(v);
            }
            if (!d_text_add(&text, line)) goto too_large;
        }
        p += 4; /* ncode */
        for (j = 0; j < c->ncode; j++, p += 4) {
            uint32_t w = d_load_u32(p);
            uint8_t op = (uint8_t)w;
            uint8_t a = (uint8_t)(w >> 8);
            uint8_t b = (uint8_t)(w >> 16);
            uint8_t cc = (uint8_t)(w >> 24);
            uint16_t bc = (uint16_t)((uint16_t)b << 8 | cc);
            size_t line = 2u + strlen(opnames[op]) + 1u;
            if (op == 1)
                line += 4u + d_digits(a) + d_digits(bc);
            else if (op == 2 || op == 8 || (op >= 17 && op <= 19))
                line += 4u + d_digits(a) + d_digits(b);
            else if ((op >= 3 && op <= 7) || (op >= 9 && op <= 11) || op == 16)
                line += 6u + d_digits(a) + d_digits(b) + d_digits(cc);
            else if (op == 12 || op == 13) {
                int32_t rel = (int16_t)bc;
                uint64_t mag = rel < 0 ? (uint64_t)(-rel) : (uint64_t)rel;
                line += 2u + d_digits(mag); /* space, explicit sign, digits */
                if (op == 13) line += 2u + d_digits(a);
            } else if (op == D_OP_CALL)
                line += 5u + d_digits(a) + m->cells[b].name.n + d_digits(cc);
            else if (op == 15)
                line += 2u + d_digits(a);
            else if (op == D_OP_EFF)
                line += 6u + d_digits(a) + m->effects[b].n + d_digits(cc);
            else if (op == D_OP_BUILTIN)
                line += 6u + d_digits(a) + m->builtins[b].n + d_digits(cc);
            if (!d_text_add(&text, line)) goto too_large;
        }
        if (!d_text_add(&text, 4)) goto too_large; /* end\n */
    }
    for (i = 0; i < m->ncells; i++) {
        const d_manifest *manifest = &m->cells[i].manifest;
        if (!d_text_add(&text, 27)) goto too_large;
        for (j = 0; j < manifest->nparams; j++)
            if (!d_text_add(&text, 12u + manifest->params[j].name.n
                                  + d_type_text_len(&manifest->params[j].type)))
                goto too_large;
        for (j = 0; j < manifest->nreturns; j++)
            if (!d_text_add(&text, 9u + d_type_text_len(&manifest->returns[j])))
                goto too_large;
        for (j = 0; j < manifest->nerrors; j++)
            if (!d_text_add(&text, 9u + manifest->errors[j].n)) goto too_large;
        for (j = 0; j < manifest->ncaps; j++)
            if (!d_text_add(&text, 9u + manifest->caps[j].n)) goto too_large;
        if (!d_text_add(&text, 10u + d_digits(manifest->fuel))) goto too_large;
        if ((manifest->flags & 1u) && !d_text_add(&text, 9)) goto too_large;
        if ((manifest->flags & 2u) && !d_text_add(&text, 11)) goto too_large;
        for (j = 0; j < manifest->nlaws; j++)
            if (!d_text_add(&text, 9u + manifest->laws[j].n)) goto too_large;
    }
    return 1;
too_large:
    d_set_failure(failure, "DOS-026", m->body_len,
                  "canonical contract text exceeds the 1 MiB bound");
    return 0;
}

static void d_buf_need(d_buf *b, size_t add)
{
    size_t need, cap;
    char *p;
    if (b->failed) return;
    if (add > b->max - b->n) { b->failed = 2; return; }
    need = b->n + add + 1;
    if (need <= b->cap) return;
    cap = b->cap ? b->cap : 256;
    while (cap < need) {
        if (cap > (b->max + 1) / 2) { cap = b->max + 1; break; }
        cap *= 2;
    }
    p = (char *)realloc(b->p, cap);
    if (!p) { b->failed = 1; return; }
    b->p = p;
    b->cap = cap;
}

static void d_buf_raw(d_buf *b, const void *p, size_t n)
{
    d_buf_need(b, n);
    if (b->failed) return;
    memcpy(b->p + b->n, p, n);
    b->n += n;
    b->p[b->n] = 0;
}

static void d_buf_str(d_buf *b, const char *s)
{
    d_buf_raw(b, s, strlen(s));
}

static void d_buf_ch(d_buf *b, char c)
{
    d_buf_raw(b, &c, 1);
}

static void d_buf_u64(d_buf *b, uint64_t v)
{
    char text[32];
    int n = snprintf(text, sizeof text, "%llu", (unsigned long long)v);
    if (n < 0 || (size_t)n >= sizeof text) { b->failed = 1; return; }
    d_buf_raw(b, text, (size_t)n);
}

static void d_buf_canon_u64(d_buf *b, uint64_t v)
{
    char text[32];
    int printed = snprintf(text, sizeof text, "%llu", (unsigned long long)v);
    size_t n, i;
    if (printed < 0 || (size_t)printed >= sizeof text) { b->failed = 1; return; }
    n = (size_t)printed;
    for (i = 0; i < n; i++) {
        size_t remaining = n - i - 1;
        d_buf_ch(b, text[i]);
        if (n >= 5 && remaining && remaining % 3 == 0) d_buf_ch(b, '_');
    }
}

static void d_buf_json_string(d_buf *b, const uint8_t *p, size_t n)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;
    d_buf_ch(b, '"');
    for (i = 0; i < n; i++) {
        unsigned char c = p[i];
        if (c == '"') d_buf_str(b, "\\\"");
        else if (c == '\\') d_buf_str(b, "\\\\");
        else if (c >= 0x20 && c <= 0x7e) d_buf_ch(b, (char)c);
        else {
            char esc[6] = {'\\', 'u', '0', '0', hex[c >> 4], hex[c & 15]};
            d_buf_raw(b, esc, sizeof esc);
        }
    }
    d_buf_ch(b, '"');
}

static void d_buf_json_cstr(d_buf *b, const char *s)
{
    d_buf_json_string(b, (const uint8_t *)s, strlen(s));
}

static const char *d_type_name(uint8_t tag)
{
    static const char *const names[] = {
        NULL, "u64", "i64", "f64", "bool", "str", "bytes", "json",
        "decision", "ok"
    };
    return tag < sizeof names / sizeof names[0] ? names[tag] : NULL;
}

static void d_buf_iface_type(d_buf *b, const d_type *type)
{
    const char *name = d_type_name(type->tag);
    if (name) d_buf_str(b, name);
    else {
        d_buf_str(b, "cap ");
        d_buf_raw(b, type->name.p, type->name.n);
    }
}

static int d_iface_hash(const d_cell *c, uint8_t hash[32])
{
    static const uint8_t return_lex_order[] = {4, 6, 8, 3, 2, 7, 9, 5, 1};
    d_buf b;
    uint32_t i, j;
    memset(&b, 0, sizeof b);
    b.max = D_BODY_MAX;
    d_buf_str(&b, "cell "); d_buf_raw(&b, c->name.p, c->name.n); d_buf_ch(&b, '\n');
    for (i = 0; i < c->manifest.nparams; i++) {
        d_buf_str(&b, "param ");
        d_buf_raw(&b, c->manifest.params[i].name.p, c->manifest.params[i].name.n);
        d_buf_ch(&b, ' '); d_buf_iface_type(&b, &c->manifest.params[i].type);
        d_buf_ch(&b, '\n');
    }
    /* Interface identity predates manifest wire tags: its return set is sorted
     * by rendered spelling, while manifest v1 is sorted by numeric tag. */
    for (i = 0; i < sizeof return_lex_order; i++)
        for (j = 0; j < c->manifest.nreturns; j++)
            if (c->manifest.returns[j].tag == return_lex_order[i]) {
                d_buf_str(&b, "ret ");
                d_buf_iface_type(&b, &c->manifest.returns[j]);
                d_buf_ch(&b, '\n');
            }
    for (i = 0; i < c->manifest.nerrors; i++) {
        d_buf_str(&b, "err ");
        d_buf_raw(&b, c->manifest.errors[i].p, c->manifest.errors[i].n);
        d_buf_ch(&b, '\n');
    }
    for (i = 0; i < c->manifest.ncaps; i++) {
        d_buf_str(&b, "cap "); d_buf_raw(&b, c->manifest.caps[i].p, c->manifest.caps[i].n);
        d_buf_ch(&b, '\n');
    }
    d_buf_str(&b, "fuel "); d_buf_canon_u64(&b, c->manifest.fuel); d_buf_ch(&b, '\n');
    if (c->manifest.flags & 1u) d_buf_str(&b, "pure\n");
    for (i = 0; i < c->manifest.nlaws; i++) {
        d_buf_str(&b, "law "); d_buf_raw(&b, c->manifest.laws[i].p, c->manifest.laws[i].n);
        d_buf_ch(&b, '\n');
    }
    d_buf_str(&b, "end\n");
    if (b.failed) { free(b.p); return b.failed == 1 ? -1 : 0; }
    axi_sha256(b.p, b.n, hash);
    free(b.p);
    return 1;
}

static void d_compiler_hash(uint8_t out[32])
{
    static const char id[] = "AXI-CA17-COMPILER-v1 c99";
    axi_sha256(id, sizeof id - 1, out);
}

static int d_all_zero(const uint8_t h[32])
{
    int i;
    for (i = 0; i < 32; i++) if (h[i] != 0) return 0;
    return 1;
}

static void d_checker_protocol_id(uint8_t out[32])
{
    static const char protocol[] = "AXI-CHECKED-SEAL-v1";
    axi_sha256(protocol, sizeof protocol, out);
}

static void d_checker_semantics_root(uint8_t out[32])
{
    static const char semantics[] =
        "AXI-CHECKER-SEMANTICS-v1\0"
        AXI_CHECKER_SOURCE_ROOT_HEX "\0"
        "NOP\0nop\0AXB_OPS_NONE\0" "1\0no operation\0"
        "LDK\0ldk\0AXB_OPS_RA_KBC\0" "1\0ra = consts[bc]\0"
        "MOV\0mov\0AXB_OPS_RA_RB\0" "1\0ra = rb\0"
        "ADD\0add\0AXB_OPS_RA_RB_RC\0" "1\0ra = rb + rc\0"
        "SUB\0sub\0AXB_OPS_RA_RB_RC\0" "1\0ra = rb - rc\0"
        "MUL\0mul\0AXB_OPS_RA_RB_RC\0" "2\0ra = rb * rc\0"
        "DIV\0div\0AXB_OPS_RA_RB_RC\0" "4\0ra = rb / rc (checked)\0"
        "MOD\0mod\0AXB_OPS_RA_RB_RC\0" "4\0ra = rb % rc (int only)\0"
        "NOT\0not\0AXB_OPS_RA_RB\0" "1\0ra = !rb (bool only)\0"
        "EQ\0eq\0AXB_OPS_RA_RB_RC\0" "1\0ra = rb == rc\0"
        "LT\0lt\0AXB_OPS_RA_RB_RC\0" "1\0ra = rb < rc  /INV-002/\0"
        "LE\0le\0AXB_OPS_RA_RB_RC\0" "1\0ra = rb <= rc /INV-002/\0"
        "JMP\0jmp\0AXB_OPS_SBC\0" "1\0pc += sbc\0"
        "JF\0jf\0AXB_OPS_RA_SBC\0" "1\0if !ra: pc += sbc\0"
        "CALL\0call\0AXB_OPS_RA_CB_IC\0" "4\0rA=base @cellB argcC; args rA.., result rA\0"
        "RET\0ret\0AXB_OPS_RA\0" "1\0return ra\0"
        "UMAKE\0umake\0AXB_OPS_RA_RB_RC\0" "1\0ra = union tag rb pay rc\0"
        "UTAG\0utag\0AXB_OPS_RA_RB\0" "1\0ra = tag(rb)\0"
        "UPAY\0upay\0AXB_OPS_RA_RB\0" "1\0ra = payload(rb)\0"
        "UCHK\0uchk\0AXB_OPS_RA_RB\0" "2\0the `?`: tag 0 unwraps to ra, else return rb\0"
        "EFF\0eff\0AXB_OPS_RA_EB_RC\0" "100\0rA = eff @effB, payload rC\0"
        "BUILTIN\0builtin\0AXB_OPS_RA_BB_RC\0" "8\0rA = builtin @builtinB, args rC..\0"
        "HALT\0halt\0AXB_OPS_NONE\0" "1\0trap: fell off the cell\0";
    axi_sha256(semantics, sizeof semantics, out);
}

static int d_verify_certificate(const d_module *m, d_failure *failure)
{
    static const char domain[] = "AXI-SEAL-SUBJECT-v1";
    const d_certificate *cert = &m->certificate;
    uint8_t want[32], *preimage;
    uint64_t budget_sum = 0, fuel_sum = 0;
    size_t preimage_len;
    uint32_t i, law_index = 0;
    if (!cert->present) return 1;
    d_checker_protocol_id(want);
    if (memcmp(want, cert->protocol_id, 32) != 0) goto bad;
    d_checker_semantics_root(want);
    if (memcmp(want, cert->semantics_root, 32) != 0) goto bad;
    if (m->certificate_offset > (size_t)-1 - (sizeof domain - 1) - 4)
        return -1;
    preimage_len = sizeof domain - 1 + m->certificate_offset + 4;
    preimage = (uint8_t *)malloc(preimage_len);
    if (!preimage) return -1;
    memcpy(preimage, domain, sizeof domain - 1);
    memcpy(preimage + sizeof domain - 1, m->body, m->certificate_offset);
    preimage[sizeof domain - 1 + m->certificate_offset + 0] = 0;
    preimage[sizeof domain - 1 + m->certificate_offset + 1] = 0;
    preimage[sizeof domain - 1 + m->certificate_offset + 2] = 0;
    preimage[sizeof domain - 1 + m->certificate_offset + 3] = 0;
    axi_sha256(preimage, preimage_len, want);
    free(preimage);
    if (memcmp(want, cert->subject_root, 32) != 0) goto bad;
    for (i = 0; i < m->ncells; i++) {
        const d_cell *cell = &m->cells[i];
        const d_cert_law *law;
        uint64_t budget;
        if (cell->name.n < 4 || memcmp(cell->name.p, "law_", 4) != 0) continue;
        if (law_index >= cert->law_count) goto bad;
        law = &cert->laws[law_index++];
        budget = cell->manifest.fuel > D_CERT_FUEL_MAX
            ? D_CERT_FUEL_MAX : cell->manifest.fuel;
        if (cell->manifest.nparams != 0 || cell->manifest.nreturns != 1
                || cell->manifest.returns[0].tag != 4
                || cell->manifest.ncaps != 0 || cell->manifest.flags != 1
                || law->cell_index != i || !d_slice_eq(law->name, cell->name)
                || memcmp(law->iface_hash, cell->manifest.iface_hash, 32) != 0
                || memcmp(law->body_hash, cell->manifest.body_hash, 32) != 0
                || law->budget != budget || law->fuel_used > budget
                || law->result_kind != 4 || law->verdict != 1
                || budget_sum > D_CERT_FUEL_MAX - budget
                || fuel_sum > D_CERT_FUEL_MAX - law->fuel_used)
            goto bad;
        budget_sum += budget;
        fuel_sum += law->fuel_used;
    }
    if (law_index != cert->law_count
            || budget_sum != cert->aggregate_budget
            || fuel_sum != cert->aggregate_fuel) goto bad;
    return 1;
bad:
    d_set_failure(failure, "DOS-029", m->certificate_offset,
                  "AXPC does not bind exactly to the observed v7 subject");
    return 0;
}

static void d_buf_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static int d_body_hash(const d_module *m, uint8_t out[32])
{
    /* AXI-CA17 / AXI-INV-139: the dossier independently rederives the v5
     * executable body root from the parsed v7 container.  The v7 cell layout
     * after the manifest is byte-identical to a v5 cell, so we copy each
     * cell from the observed body and prepend a v5 module header. */
    uint8_t *w = NULL;
    size_t cap = 256, len = 0;
    uint32_t i;
    if (!out) return 1;
    memset(out, 0, 32);
    if (!m->body || m->ncells == 0 || m->ncells > D_CELLS_MAX) return 1;
    for (i = 0; i < m->ncells; i++) {
        size_t cell_bytes = m->cells[i].end_off - m->cells[i].name_wire_off;
        if (cell_bytes > D_BODY_MAX) return 1;
    }
    w = (uint8_t *)malloc(cap);
    if (!w) return -1;
#define GROW(need) do { \
        size_t req = len + (need); \
        if (req > cap) { \
            size_t nc = cap; \
            while (nc < req) { \
                if (nc > D_BODY_MAX / 2) { free(w); return 1; } \
                nc *= 2; \
            } \
            uint8_t *nw = (uint8_t *)realloc(w, nc); \
            if (!nw) { free(w); return -1; } \
            w = nw; cap = nc; \
        } \
    } while (0)
    GROW(4); memcpy(w + len, "AXB0", 4); len += 4;
    GROW(4); d_buf_u32le(w + len, 5); len += 4;
    GROW(32); memcpy(w + len, m->source_hash, 32); len += 32;
    GROW(4); d_buf_u32le(w + len, m->neffects); len += 4;
    for (i = 0; i < m->neffects; i++) {
        GROW(4 + m->effects[i].n);
        d_buf_u32le(w + len, m->effects[i].n);
        memcpy(w + len + 4, m->effects[i].p, m->effects[i].n);
        len += 4 + m->effects[i].n;
    }
    GROW(4); d_buf_u32le(w + len, m->nbuiltins); len += 4;
    for (i = 0; i < m->nbuiltins; i++) {
        GROW(4 + m->builtins[i].n);
        d_buf_u32le(w + len, m->builtins[i].n);
        memcpy(w + len + 4, m->builtins[i].p, m->builtins[i].n);
        len += 4 + m->builtins[i].n;
    }
    GROW(4); d_buf_u32le(w + len, m->ncells); len += 4;
    for (i = 0; i < m->ncells; i++) {
        const d_cell *c = &m->cells[i];
        size_t name_bytes = 4 + c->name.n;
        size_t tail_bytes = c->end_off - c->tail_off;
        GROW(name_bytes + tail_bytes);
        d_buf_u32le(w + len, c->name.n);
        memcpy(w + len + 4, c->name.p, c->name.n);
        memcpy(w + len + name_bytes, m->body + c->tail_off, tail_bytes);
        len += name_bytes + tail_bytes;
    }
    axi_sha256(w, len, out);
    free(w);
    return 0;
#undef GROW
}

static int d_verify_hashes(d_module *m, d_failure *failure)
{
    static const uint8_t domain[] = "AXI-CELL-BODY-v1";
    uint32_t i;
    uint8_t want_body[32];
    uint8_t want_compiler[32];
    int rc;
    /* AXI-CA17 / AXI-INV-139: the dossier independently rederives the
     * executable body root and the canonical compiler identity.  It does not
     * have access to the original .axi source or the canonical IR text, so
     * those two hashes are reported as claims, not rederived facts. */
    rc = d_body_hash(m, want_body);
    if (rc < 0) return -1;
    if (rc != 0 || memcmp(want_body, m->body_hash, 32) != 0) {
        d_set_failure(failure, "DOS-022", 0,
                      "body_hash does not rederive from the v7 body contents");
        return 0;
    }
    if (!d_all_zero(m->compiler_hash)) {
        d_compiler_hash(want_compiler);
        if (memcmp(want_compiler, m->compiler_hash, 32) != 0) {
            d_set_failure(failure, "DOS-006", 64,
                          "compiler_hash is not the canonical identity");
            return 0;
        }
    }
    for (i = 0; i < m->ncells; i++) {
        d_cell *c = &m->cells[i];
        size_t head = 4 + c->name.n;
        size_t tail = c->end_off - c->tail_off;
        size_t total = sizeof domain + head + tail;
        uint8_t *wire = (uint8_t *)malloc(total);
        uint8_t body_hash[32], iface_hash[32];
        int rc;
        if (!wire) return -1;
        memcpy(wire, domain, sizeof domain);
        memcpy(wire + sizeof domain, m->body + c->name_wire_off, head);
        memcpy(wire + sizeof domain + head, m->body + c->tail_off, tail);
        axi_sha256(wire, total, body_hash);
        free(wire);
        if (memcmp(body_hash, c->manifest.body_hash, 32) != 0) {
            d_set_failure(failure, "DOS-022", c->manifest.body_off,
                          "manifest body_hash differs from rederived cell body");
            return 0;
        }
        rc = d_iface_hash(c, iface_hash);
        if (rc < 0) return -1;
        if (rc == 0) {
            d_set_failure(failure, "DOS-026", c->manifest.iface_off,
                          "canonical interface rendering exceeds its bound");
            return 0;
        }
        if (memcmp(iface_hash, c->manifest.iface_hash, 32) != 0) {
            d_set_failure(failure, "DOS-021", c->manifest.iface_off,
                          "manifest iface_hash differs from rederived contract");
            return 0;
        }
    }
    return 1;
}

static void d_buf_hex(d_buf *b, const uint8_t *p, size_t n)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;
    d_buf_ch(b, '"');
    for (i = 0; i < n; i++) {
        d_buf_ch(b, hex[p[i] >> 4]);
        d_buf_ch(b, hex[p[i] & 15]);
    }
    d_buf_ch(b, '"');
}

static void d_json_slice_array(d_buf *b, const d_slice *v, uint32_t n)
{
    uint32_t i;
    d_buf_ch(b, '[');
    for (i = 0; i < n; i++) {
        if (i) d_buf_ch(b, ',');
        d_buf_json_string(b, v[i].p, v[i].n);
    }
    d_buf_ch(b, ']');
}

static void d_json_byte_array(d_buf *b, const d_slice *v, uint32_t n)
{
    uint32_t i;
    d_buf_ch(b, '[');
    for (i = 0; i < n; i++) {
        if (i) d_buf_ch(b, ',');
        d_buf_str(b, "{\"encoding\":\"hex\",\"bytes\":");
        d_buf_hex(b, v[i].p, v[i].n);
        d_buf_ch(b, '}');
    }
    d_buf_ch(b, ']');
}

static void d_json_type(d_buf *b, const d_type *type)
{
    const char *name = d_type_name(type->tag);
    d_buf_ch(b, '"');
    if (name) d_buf_str(b, name);
    else {
        d_buf_str(b, "cap ");
        d_buf_raw(b, type->name.p, type->name.n);
    }
    d_buf_ch(b, '"');
}

static int d_render_accepted(const d_module *m, const char *sig_status,
                             const uint8_t producer[32], char **out,
                             size_t *out_len)
{
    d_buf b;
    uint8_t module_root[32];
    uint32_t i, j;
    int provenance_complete;
    const char *missing[4];
    size_t missing_n = 0;
    memset(&b, 0, sizeof b);
    b.max = D_JSON_MAX;
    if (d_all_zero(m->source_hash)) missing[missing_n++] = "src_hash";
    if (d_all_zero(m->ir_hash)) missing[missing_n++] = "ir_hash";
    if (d_all_zero(m->compiler_hash)) missing[missing_n++] = "compiler_hash";
    if (d_all_zero(m->body_hash)) missing[missing_n++] = "body_hash";
    provenance_complete = missing_n == 0;
    axi_sha256(m->body, m->body_len, module_root);
    d_buf_str(&b, "{\"schema\":\"axi.dossier.v1\",\"accepted\":true,"
                  "\"format_version\":7,\"contract_version\":1,\"module_root\":");
    d_buf_hex(&b, module_root, 32);
    d_buf_str(&b, ",\"signature\":{\"status\":");
    d_buf_json_cstr(&b, sig_status);
    d_buf_str(&b, ",\"producer\":"); d_buf_hex(&b, producer, 32);
    d_buf_str(&b, "},\"derivation\":{\"src_hash\":");
    d_buf_hex(&b, m->source_hash, 32);
    d_buf_str(&b, ",\"ir_hash\":"); d_buf_hex(&b, m->ir_hash, 32);
    d_buf_str(&b, ",\"compiler_hash\":"); d_buf_hex(&b, m->compiler_hash, 32);
    d_buf_str(&b, ",\"body_hash\":"); d_buf_hex(&b, m->body_hash, 32);
    d_buf_str(&b, "},\"seal\":{\"maturity\":");
    d_buf_json_cstr(&b, m->certificate.present ? "CHECKED" : "UNCHECKED");
    d_buf_str(&b, ",\"execution\":");
    d_buf_json_cstr(&b, "UNOBSERVED");
    if (m->certificate.present) {
        d_buf_str(&b, ",\"subject_root\":");
        d_buf_hex(&b, m->certificate.subject_root, 32);
        d_buf_str(&b, ",\"checker_protocol\":");
        d_buf_hex(&b, m->certificate.protocol_id, 32);
        d_buf_str(&b, ",\"checker_semantics\":");
        d_buf_hex(&b, m->certificate.semantics_root, 32);
        d_buf_str(&b, ",\"law_count\":");
        d_buf_u64(&b, m->certificate.law_count);
        d_buf_str(&b, ",\"aggregate_budget\":");
        d_buf_u64(&b, m->certificate.aggregate_budget);
        d_buf_str(&b, ",\"aggregate_fuel_used\":");
        d_buf_u64(&b, m->certificate.aggregate_fuel);
        d_buf_str(&b, ",\"laws\":[");
        for (i = 0; i < m->certificate.law_count; i++) {
            const d_cert_law *law = &m->certificate.laws[i];
            if (i) d_buf_ch(&b, ',');
            d_buf_str(&b, "{\"cell_index\":");
            d_buf_u64(&b, law->cell_index);
            d_buf_str(&b, ",\"name\":");
            d_buf_json_string(&b, law->name.p, law->name.n);
            d_buf_str(&b, ",\"iface_hash\":");
            d_buf_hex(&b, law->iface_hash, 32);
            d_buf_str(&b, ",\"body_hash\":");
            d_buf_hex(&b, law->body_hash, 32);
            d_buf_str(&b, ",\"budget\":"); d_buf_u64(&b, law->budget);
            d_buf_str(&b, ",\"fuel_used\":"); d_buf_u64(&b, law->fuel_used);
            d_buf_str(&b, ",\"result_kind\":\"BOOL\",\"verdict\":\"TRUE\"}");
        }
        d_buf_ch(&b, ']');
    }
    d_buf_str(&b, "},\"provenance\":{\"status\":");
    if (provenance_complete) {
        d_buf_json_cstr(&b, "complete");
    } else {
        size_t k;
        d_buf_json_cstr(&b, "incomplete");
        d_buf_str(&b, ",\"missing\":[");
        for (k = 0; k < missing_n; k++) {
            if (k) d_buf_ch(&b, ',');
            d_buf_json_cstr(&b, missing[k]);
        }
        d_buf_ch(&b, ']');
    }
    d_buf_str(&b, "},\"effects\":");
    d_json_slice_array(&b, m->effects, m->neffects);
    d_buf_str(&b, ",\"builtins\":");
    d_json_slice_array(&b, m->builtins, m->nbuiltins);
    d_buf_str(&b, ",\"cells\":[");
    for (i = 0; i < m->ncells; i++) {
        const d_cell *c = &m->cells[i];
        if (i) d_buf_ch(&b, ',');
        d_buf_str(&b, "{\"name\":"); d_buf_json_string(&b, c->name.p, c->name.n);
        d_buf_str(&b, ",\"fuel\":"); d_buf_u64(&b, c->manifest.fuel);
        d_buf_str(&b, ",\"ancestral_fuel\":[");
        {
            uint32_t ancestor, seen = 0;
            for (ancestor = 0; ancestor < m->ncells; ancestor++)
                if (m->reaches[ancestor][i / 64]
                        & (UINT64_C(1) << (i % 64))) {
                    if (seen++) d_buf_ch(&b, ',');
                    d_buf_str(&b, "{\"cell\":");
                    d_buf_json_string(&b, m->cells[ancestor].name.p,
                                      m->cells[ancestor].name.n);
                    d_buf_str(&b, ",\"fuel\":");
                    d_buf_u64(&b, m->cells[ancestor].manifest.fuel);
                    d_buf_ch(&b, '}');
                }
        }
        d_buf_ch(&b, ']');
        d_buf_str(&b, ",\"flags\":"); d_buf_u64(&b, c->manifest.flags);
        d_buf_str(&b, ",\"params\":[");
        for (j = 0; j < c->manifest.nparams; j++) {
            if (j) d_buf_ch(&b, ',');
            d_buf_str(&b, "{\"name\":");
            d_buf_json_string(&b, c->manifest.params[j].name.p,
                              c->manifest.params[j].name.n);
            d_buf_str(&b, ",\"type\":"); d_json_type(&b, &c->manifest.params[j].type);
            d_buf_ch(&b, '}');
        }
        d_buf_str(&b, "],\"returns\":[");
        for (j = 0; j < c->manifest.nreturns; j++) {
            if (j) d_buf_ch(&b, ',');
            d_json_type(&b, &c->manifest.returns[j]);
        }
        d_buf_str(&b, "],\"errors\":");
        d_json_slice_array(&b, c->manifest.errors, c->manifest.nerrors);
        d_buf_str(&b, ",\"caps\":");
        d_json_slice_array(&b, c->manifest.caps, c->manifest.ncaps);
        d_buf_str(&b, ",\"laws\":");
        d_json_byte_array(&b, c->manifest.laws, c->manifest.nlaws);
        d_buf_str(&b, ",\"iface_hash\":"); d_buf_hex(&b, c->manifest.iface_hash, 32);
        d_buf_str(&b, ",\"body_hash\":"); d_buf_hex(&b, c->manifest.body_hash, 32);
        d_buf_str(&b, ",\"calls\":[");
        {
            uint32_t pc, seen = 0;
            for (pc = 0; pc < c->ncode; pc++) {
                uint32_t w = d_load_u32(m->body + c->code_off + (size_t)pc * 4);
                if ((uint8_t)w == D_OP_CALL) {
                    uint8_t target = (uint8_t)(w >> 16);
                    if (seen++) d_buf_ch(&b, ',');
                    d_buf_str(&b, "{\"target\":");
                    d_buf_json_string(&b, m->cells[target].name.p, m->cells[target].name.n);
                    d_buf_str(&b, ",\"base\":"); d_buf_u64(&b, (uint8_t)(w >> 8));
                    d_buf_str(&b, ",\"argc\":"); d_buf_u64(&b, (uint8_t)(w >> 24));
                    d_buf_ch(&b, '}');
                }
            }
        }
        d_buf_str(&b, "]}");
    }
    d_buf_str(&b, "]}\n");
    if (b.failed) {
        int failed = b.failed;
        free(b.p);
        return failed == 1 ? -1 : 0;
    }
    *out = b.p;
    *out_len = b.n;
    return 1;
}

static int d_emit_refusal(const d_failure *f, const uint8_t *producer,
                          const char *status, char **out, size_t *out_len)
{
    d_buf b;
    memset(&b, 0, sizeof b);
    b.max = D_JSON_MAX;
    d_buf_str(&b, "{\"schema\":\"axi.dossier.v1\",\"accepted\":false,\"code\":");
    d_buf_json_cstr(&b, f->code ? f->code : "DOS-999");
    d_buf_str(&b, ",\"offset\":"); d_buf_u64(&b, (uint64_t)f->offset);
    d_buf_str(&b, ",\"reason\":");
    d_buf_json_cstr(&b, f->reason ? f->reason : "artifact refused");
    if (producer && status) {
        d_buf_str(&b, ",\"signature\":{\"status\":"); d_buf_json_cstr(&b, status);
        d_buf_str(&b, ",\"producer\":"); d_buf_hex(&b, producer, 32); d_buf_ch(&b, '}');
    }
    d_buf_str(&b, "}\n");
    if (b.failed) { free(b.p); return 2; }
    *out = b.p;
    *out_len = b.n;
    return 1;
}

int axi_dossier_bytes(const uint8_t *artifact, size_t len,
                      const uint8_t trusted_pk[32],
                      char **json_out, size_t *json_len)
{
    d_module module;
    d_failure failure;
    const uint8_t *trailer, *producer, *sig;
    const char *sig_status;
    uint8_t msg[44];
    size_t body_len;
    char *published = NULL;
    size_t published_len = 0;
    int rc;
    if (!artifact || !json_out || !json_len) return 2;
    memset(&module, 0, sizeof module);
    memset(&failure, 0, sizeof failure);
    if (len < D_TRAILER + 8) {
        d_set_failure(&failure, "DOS-001", len,
                      "artifact is too short for signed AXB v7 framing");
        return d_emit_refusal(&failure, NULL, NULL, json_out, json_len);
    }
    if (len > D_BODY_MAX + D_TRAILER) {
        d_set_failure(&failure, "DOS-001", D_BODY_MAX,
                      "signed artifact exceeds the 1 MiB body bound");
        return d_emit_refusal(&failure, NULL, NULL, json_out, json_len);
    }
    body_len = len - D_TRAILER;
    trailer = artifact + body_len;
    if (memcmp(trailer, "AXBS", 4) != 0) {
        d_set_failure(&failure, "DOS-005", body_len, "missing exact AXBS trailer");
        return d_emit_refusal(&failure, NULL, NULL, json_out, json_len);
    }
    if (d_load_u32(trailer + 4) != 1) {
        d_set_failure(&failure, "DOS-005", body_len + 4,
                      "observer accepts exact AXBS version 1 only");
        return d_emit_refusal(&failure, NULL, NULL, json_out, json_len);
    }
    producer = trailer + 8;
    sig = trailer + 40;
    memcpy(msg, "AXI-SIGN-v1", 11);
    msg[11] = 0;
    axi_sha256(artifact, body_len, msg + 12);
    if (ed25519_verify(sig, msg, (uint32_t)sizeof msg, producer) != 0) {
        d_set_failure(&failure, "DOS-006", body_len + 40,
                      "Ed25519 signature does not verify over the exact body");
        return d_emit_refusal(&failure, NULL, NULL, json_out, json_len);
    }
    if (trusted_pk && memcmp(producer, trusted_pk, 32) != 0) {
        d_set_failure(&failure, "DOS-007", body_len + 8,
                      "producer key does not match the supplied trust anchor");
        return d_emit_refusal(&failure, producer, "mismatch", json_out, json_len);
    }
    sig_status = trusted_pk ? "trusted" : "valid-unanchored";
    module.body = artifact;
    module.body_len = body_len;
    rc = d_parse_module(&module, &failure);
    if (rc < 0) goto oom;
    if (rc == 0) goto refused;
    if (!d_verify_opcodes(&module, &failure)) goto refused;
    if (!d_verify_text_bound(&module, &failure)) goto refused;
    rc = d_verify_hashes(&module, &failure);
    if (rc < 0) goto oom;
    if (rc == 0) goto refused;
    rc = d_verify_certificate(&module, &failure);
    if (rc < 0) goto oom;
    if (rc == 0) goto refused;
    rc = d_render_accepted(&module, sig_status, producer, &published, &published_len);
    if (rc < 0) goto oom;
    if (rc == 0) {
        d_set_failure(&failure, "DOS-027", body_len,
                       "canonical dossier exceeds the 64 MiB output bound");
        goto refused;
    }
    free(module.cells);
    *json_out = published;
    *json_len = published_len;
    return 0;
refused:
    free(module.cells);
    return d_emit_refusal(&failure, producer, sig_status, json_out, json_len);
oom:
    free(module.cells);
    free(published);
    return 2;
}

void axi_dossier_free(char *json)
{
    free(json);
}
