/* axial — embed API implementation (M4). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 */
#include "axi_embed.h"
#include "axi_alloc.h"
#include "axi_vm.h"
#include "axi_json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VM_FUEL_DEFAULT 1000000u

struct axi_vm_ctx {
    axb_contract_mod model;
    axi_grants grants;
    void *sink;
    uint64_t fuel_budget;
};

struct axi_vm_v7_invocation {
    const axi_vm_v7_ctx *ctx;
    axi_vm_contract_invocation *runtime;
};

static void embed_diag(axi_diags *diags, const char *code,
                       const char *msg, const char *fix)
{
    axi_diag_add(diags, code, 0, 0, 0, msg, fix);
}

axi_vm_ctx *axi_vm_create(const uint8_t *module_bytes, size_t len,
                          const uint8_t trusted_pk[32],
                          const axi_grants *grants, void *sink,
                          axi_diags *diags)
{
    axi_vm_ctx *ctx = NULL;
    if (axi_vm_v7_create_trusted(module_bytes, len, trusted_pk, grants, sink,
                                 &ctx, diags) != 0)
        return NULL;
    ctx->fuel_budget = VM_FUEL_DEFAULT;
    return ctx;
}

void axi_vm_destroy(axi_vm_ctx *ctx)
{
    axi_vm_v7_destroy(ctx);
}

static int cell_index(const axb_contract_mod *m, const char *name)
{
    uint32_t i;
    for (i = 0; i < m->body.n; i++)
        if (strcmp(m->body.cells[i].name, name) == 0) return (int)i;
    return -1;
}

typedef struct {
    char   **buf;
    size_t  *n;
    size_t  *cap;
} embed_json_sink;

static int sb_json_bytes(void *raw, const char *bytes, size_t len)
{
    embed_json_sink *s = (embed_json_sink *)raw;
    if (*s->n + len + 1 > *s->cap) {
        size_t ncap = *s->cap ? *s->cap * 2 : 256;
        char *next;
        while (*s->n + len + 1 > ncap) ncap *= 2;
        next = axi_realloc(*s->buf, ncap);
        if (!next) return -1;
        *s->buf = next;
        *s->cap = ncap;
    }
    memcpy(*s->buf + *s->n, bytes, len);
    *s->n += len;
    return 0;
}

/* Serialize a VM value into a freshly malloc'd JSON string. */
static char *vval_to_json(const axi_vval *v, size_t *out_len)
{
    char *buf;
    size_t n;

    switch (v->kind) {
    case VB_UNIT:
        n = 4; buf = axi_malloc(n + 1);
        if (!buf) return NULL;
        memcpy(buf, "null", n + 1);
        break;
    case VB_BOOL:
        if (v->bits) {
            n = 4; buf = axi_malloc(n + 1);
            if (!buf) return NULL;
            memcpy(buf, "true", n + 1);
        } else {
            n = 5; buf = axi_malloc(n + 1);
            if (!buf) return NULL;
            memcpy(buf, "false", n + 1);
        }
        break;
    case VB_U64: {
        char tmp[32];
        n = (size_t)snprintf(tmp, sizeof tmp, "%llu",
                             (unsigned long long)v->bits);
        buf = axi_malloc(n + 1);
        if (!buf) return NULL;
        memcpy(buf, tmp, n + 1);
        break;
    }
    case VB_I64: {
        char tmp[32];
        n = (size_t)snprintf(tmp, sizeof tmp, "%lld",
                             (long long)(int64_t)v->bits);
        buf = axi_malloc(n + 1);
        if (!buf) return NULL;
        memcpy(buf, tmp, n + 1);
        break;
    }
    case VB_F64: {
        char tmp[32];
        double d; memcpy(&d, &v->bits, 8);
        n = (size_t)snprintf(tmp, sizeof tmp, "%.17g", d);
        buf = axi_malloc(n + 1);
        if (!buf) return NULL;
        memcpy(buf, tmp, n + 1);
        break;
    }
    case VB_STR: {
        size_t cap = 0;
        embed_json_sink sink = { &buf, &n, &cap };
        buf = NULL; n = 0;
        if (sb_json_bytes(&sink, "\"", 1) != 0
                || axi_json_escape(v->s, v->slen, sb_json_bytes, &sink) != 0
                || sb_json_bytes(&sink, "\"", 1) != 0) {
            free(buf); return NULL;
        }
        buf[n] = '\0';
        break;
    }
    case VB_ERR: {
        size_t cap = 0;
        embed_json_sink sink = { &buf, &n, &cap };
        buf = NULL; n = 0;
        if (sb_json_bytes(&sink, "{\"error\":\"", 10) != 0
                || axi_json_escape(v->s, v->slen, sb_json_bytes, &sink) != 0
                || sb_json_bytes(&sink, "\"}", 2) != 0) {
            free(buf); return NULL;
        }
        buf[n] = '\0';
        break;
    }
    default:
        buf = axi_malloc(5);
        if (!buf) return NULL;
        memcpy(buf, "null", 5);
        n = 4;
        break;
    }
    if (out_len) *out_len = n;
    return buf;
}

int axi_vm_eval(axi_vm_ctx *ctx, const char *cell_name,
                const char *input_json, size_t input_len,
                char **output_json, size_t *output_len,
                uint64_t *fuel_used, axi_diags *diags)
{
    int ci;
    axi_vval result, arg;
    axi_vm_contract_invocation *inv = NULL;
    char *json;
    size_t json_len = 0;
    uint64_t used = 0;
    int ok;

    if (!ctx || !cell_name || !output_json || !fuel_used
            || input_len > UINT32_MAX || (input_len > 0 && !input_json)) {
        embed_diag(diags, "AXI-E001", "invalid eval arguments",
                   "provide context, cell, input, output and fuel pointers");
        return -1;
    }

    ci = cell_index(&ctx->model, cell_name);
    if (ci < 0) {
        embed_diag(diags, "AXI-E002", "policy cell does not exist",
                   "inspect the module and request one of its declared cells");
        return -1;
    }

    arg.kind = VB_STR;
    arg.bits = 0;
    arg.s    = input_json;
    arg.slen = (uint32_t)input_len;

    if (axi_vm_contract_invocation_create(&ctx->model, &ctx->grants,
                                           &inv) != 0) {
        embed_diag(diags, "AXI-E005", "policy invocation creation failed",
                   "retry with enough host memory and runtime entropy");
        return -1;
    }
    memset(&result, 0, sizeof result);
    ok = axi_vm_contract_invocation_run_diag(inv, (uint32_t)ci, &arg, 1,
                                              &result, ctx->fuel_budget,
                                              &used, ctx->sink, diags);
    axi_vm_contract_invocation_destroy(inv);
    if (!ok) return -1;
    if (result.kind != VB_BOOL) { /* INV-276; AXI-INV-074 */
        embed_diag(diags, "AXI-E004", "policy returned a non-bool verdict",
                   "a host policy cell must return decision/bool");
        return -1;
    }

    json = vval_to_json(&result, &json_len);
    if (!json) {
        embed_diag(diags, "AXI-E005", "verdict serialization failed",
                   "retry with enough host memory to preserve the verdict");
        return -1;
    }
    *output_json = json;
    if (output_len) *output_len = json_len;
    *fuel_used = used;
    return result.bits ? 0 : 1;
}

/* Append a JSON-escaped string to a growable buffer. */
static int sb_json_escape(char **buf, size_t *n, size_t *cap, const char *s)
{
    embed_json_sink sink = { buf, n, cap };
    return axi_json_escape(s, strlen(s), sb_json_bytes, &sink);
}

static int sb_put(char **buf, size_t *n, size_t *cap, const char *s)
{
    size_t len = strlen(s);
    if (*n + len + 1 > *cap) {
        size_t ncap = *cap ? *cap * 2 : 256;
        char *next;
        while (*n + len + 1 > ncap) ncap *= 2;
        next = axi_realloc(*buf, ncap);
        if (!next) return -1;
        *buf = next;
        *cap = ncap;
    }
    memcpy(*buf + *n, s, len);
    *n += len;
    return 0;
}

static void hex32(char out[65], const uint8_t h[32])
{
    static const char HEX[] = "0123456789abcdef";
    int i;
    for (i = 0; i < 32; i++) {
        out[i * 2]     = HEX[h[i] >> 4];
        out[i * 2 + 1] = HEX[h[i] & 0xf];
    }
    out[64] = '\0';
}

int axi_vm_inspect(const uint8_t *module_bytes, size_t len,
                   const uint8_t trusted_pk[32],
                   char **meta_json, size_t *meta_len, axi_diags *diags)
{
    axb_contract_mod model;
    char *buf = NULL;
    size_t n = 0, cap = 0;
    char hex[65], number[32];
    uint32_t i;

    if (!module_bytes || !trusted_pk || !meta_json) {
        embed_diag(diags, "AXI-E001", "invalid inspect arguments",
                   "provide signed v7 bytes, an external trust anchor and output");
        return -1;
    }
    memset(&model, 0, sizeof model);
    if (axb_contract_v7_decode_trusted(&model, module_bytes, len,
                                       trusted_pk) != 0) {
        embed_diag(diags, "AXI-E003", "signed v7 inspection admission failed",
                   "inspect an intact v7 artifact signed by the configured producer");
        return -1;
    }

#define PUT(text) do { if (sb_put(&buf, &n, &cap, (text)) != 0) goto oom; } while (0)
#define ESC(text) do { if (sb_json_escape(&buf, &n, &cap, (text)) != 0) goto oom; } while (0)

    PUT("{\"format\":7,");
    hex32(hex, model.body.root);
    PUT("\"root\":\""); PUT(hex); PUT("\",");
    hex32(hex, model.body.sig_pk);
    PUT("\"signer\":\""); PUT(hex); PUT("\",");
    PUT("\"seal\":{\"maturity\":\"");
    PUT(model.seal.present ? "CHECKED" : "UNCHECKED"); PUT("\"");
    if (model.seal.present) {
        hex32(hex, model.seal.subject_root);
        PUT(",\"subject_root\":\""); PUT(hex); PUT("\"");
        hex32(hex, model.seal.checker_protocol_id);
        PUT(",\"checker_protocol\":\""); PUT(hex); PUT("\"");
        hex32(hex, model.seal.checker_semantics_root);
        PUT(",\"checker_semantics\":\""); PUT(hex); PUT("\"");
        (void)snprintf(number, sizeof number, "%u", model.seal.law_count);
        PUT(",\"law_count\":"); PUT(number);
    }
    PUT("},");
    PUT("\"cells\":[");
    for (i = 0; i < model.body.n; i++) {
        if (i) PUT(",");
        PUT("{\"name\":\""); ESC(model.body.cells[i].name); PUT("\",");
        hex32(hex, model.manifest[i].iface_hash);
        PUT("\"iface_hash\":\""); PUT(hex); PUT("\",");
        hex32(hex, model.manifest[i].body_hash);
        PUT("\"body_hash\":\""); PUT(hex); PUT("\",");
        (void)snprintf(number, sizeof number, "%llu",
                       (unsigned long long)model.manifest[i].fuel_max);
        PUT("\"fuel\":"); PUT(number); PUT("}");
    }
    PUT("],\"signed\":true}\n");
    buf[n] = '\0';
    axb_contract_mod_free(&model);
    *meta_json = buf;
    if (meta_len) *meta_len = n;
#undef ESC
#undef PUT
    return 0;

oom:
    free(buf);
    axb_contract_mod_free(&model);
    embed_diag(diags, "AXI-E005", "inspection serialization failed",
               "retry with enough host memory to preserve the metadata");
#undef ESC
#undef PUT
    return -1;
}

/* AXI-INV-128: admit one trusted decoded model and use the common contract
 * runtime door for every invocation. */
int axi_vm_v7_create_trusted(const uint8_t *module_bytes, size_t len,
                             const uint8_t trusted_pk[32],
                             const axi_grants *grants, void *sink,
                             axi_vm_v7_ctx **out, axi_diags *diags)
{
    axi_vm_v7_ctx *ctx;
    if (!out || !trusted_pk || (len > 0 && !module_bytes)
            || (grants && axi_grants_verify(grants) != 0)) {
        embed_diag(diags, "AXI-E001", "invalid v7 create arguments",
                   "provide signed bytes, an external trust anchor and valid grants");
        return -1;
    }
    ctx = axi_calloc(1, sizeof *ctx);
    if (!ctx) {
        embed_diag(diags, "AXI-E005", "v7 VM context allocation failed",
                   "retry with enough host memory to preserve caller state");
        return -1;
    }
    if (axb_contract_v7_decode_trusted(&ctx->model, module_bytes, len,
                                       trusted_pk) != 0) {
        free(ctx);
        embed_diag(diags, "AXI-E003", "signed v7 admission failed",
                   "use an intact v7 artifact signed by the configured producer");
        return -1;
    }
    if (grants) ctx->grants = *grants;
    else axi_grants_init(&ctx->grants);
    ctx->sink = sink;
    *out = ctx;
    return 0;
}

void axi_vm_v7_destroy(axi_vm_v7_ctx *ctx)
{
    if (!ctx) return;
    axb_contract_mod_free(&ctx->model);
    free(ctx);
}

static int v7_cell_index(const axb_contract_mod *m, const char *name)
{
    uint32_t i;
    for (i = 0; i < m->body.n; i++)
        if (strcmp(m->body.cells[i].name, name) == 0) return (int)i;
    return -1;
}

int axi_vm_v7_invocation_create(const axi_vm_v7_ctx *ctx,
                                axi_vm_v7_invocation **out,
                                axi_diags *diags)
{
    axi_vm_v7_invocation *inv;
    if (!ctx || !out) {
        embed_diag(diags, "AXI-E001", "invalid v7 invocation arguments",
                   "provide one admitted context and an output pointer");
        return -1;
    }
    inv = axi_calloc(1, sizeof *inv);
    if (!inv) {
        embed_diag(diags, "AXI-E005", "v7 invocation allocation failed",
                   "retry with enough host memory to preserve caller state");
        return -1;
    }
    if (axi_vm_contract_invocation_create(&ctx->model, &ctx->grants,
                                           &inv->runtime) != 0) {
        free(inv);
        embed_diag(diags, "AXI-E005", "v7 invocation creation failed",
                   "retry with enough host memory and runtime entropy");
        return -1;
    }
    inv->ctx = ctx;
    *out = inv;
    return 0;
}

int axi_vm_v7_invocation_cap(const axi_vm_v7_invocation *inv,
                             const char *atom, axi_vval *out,
                             axi_diags *diags)
{
    axi_vval cap;
    if (!inv || !atom || !out) {
        embed_diag(diags, "AXI-E001", "invalid v7 CAP mint arguments",
                   "provide a live invocation, granted atom and output");
        return -1;
    }
    memset(&cap, 0, sizeof cap);
    if (axi_vm_contract_invocation_cap(inv->runtime, atom, &cap) != 0) {
        embed_diag(diags, "AXI-R025", "v7 CAP mint was refused",
                   "mint a granted CAP before consuming its invocation");
        return -1;
    }
    *out = cap;
    return 0;
}

int axi_vm_v7_invocation_eval(axi_vm_v7_invocation *inv,
                              const char *cell_name,
                              const uint8_t expected_iface_hash[32],
                              const axi_vval *args, uint8_t argc,
                              axi_vval *out, uint64_t fuel_budget,
                              uint64_t *fuel_used, axi_diags *diags)
{
    axi_vval result;
    uint64_t used = 0;
    unsigned diff = 0;
    const axi_vm_v7_ctx *ctx;
    int ci;
    size_t i;
    if (!inv || !cell_name || !expected_iface_hash || !out || !fuel_used
            || (argc > 0 && !args)) {
        embed_diag(diags, "AXI-E001", "invalid v7 eval arguments",
                   "provide invocation, cell, contract pin, values, output and fuel");
        return -1;
    }
    ctx = inv->ctx;
    ci = v7_cell_index(&ctx->model, cell_name);
    if (ci < 0) {
        embed_diag(diags, "AXI-E002", "contract cell does not exist",
                   "inspect the trusted module and request a declared cell");
        return -1;
    }
    for (i = 0; i < 32; i++)
        diff |= expected_iface_hash[i] ^ ctx->model.manifest[ci].iface_hash[i];
    if (diff != 0) {
        embed_diag(diags, "AXI-R025", "embed contract pin does not match",
                   "use the reviewed interface hash for this exact cell");
        return -1;
    }
    memset(&result, 0, sizeof result);
    if (!axi_vm_contract_invocation_run_diag(inv->runtime, (uint32_t)ci,
                                              args, argc, &result,
                                              fuel_budget, &used, ctx->sink,
                                              diags))
        return -1;
    *out = result;
    *fuel_used = used;
    return 0;
}

void axi_vm_v7_invocation_destroy(axi_vm_v7_invocation *inv)
{
    if (!inv) return;
    axi_vm_contract_invocation_destroy(inv->runtime);
    free(inv);
}

static int v7_value_borrows_invocation(const axi_vval *v)
{
    axi_vkind kind = v->kind == VB_UNION ? v->payload_kind : v->kind;
    return kind == VB_STR || kind == VB_BYTES || kind == VB_ERR;
}

int axi_vm_v7_eval(axi_vm_v7_ctx *ctx, const char *cell_name,
                   const uint8_t expected_iface_hash[32],
                   const axi_vval *args, uint8_t argc,
                   axi_vval *out, uint64_t fuel_budget,
                   uint64_t *fuel_used, axi_diags *diags)
{
    axi_vm_v7_invocation *inv = NULL;
    axi_vval result;
    uint64_t used = 0;
    int rc;
    if (!out || !fuel_used) {
        embed_diag(diags, "AXI-E001", "invalid v7 eval outputs",
                   "provide caller-owned value and fuel outputs");
        return -1;
    }
    if (axi_vm_v7_invocation_create(ctx, &inv, diags) != 0) return -1;
    rc = axi_vm_v7_invocation_eval(inv, cell_name, expected_iface_hash,
                                   args, argc, &result, fuel_budget, &used,
                                   diags);
    if (rc == 0 && v7_value_borrows_invocation(&result)) {
        embed_diag(diags, "AXI-R025",
                   "convenience eval result borrows invocation storage",
                   "use the explicit v7 invocation lifecycle for this result kind");
        rc = -1;
    }
    if (rc == 0) {
        *out = result;
        *fuel_used = used;
    }
    axi_vm_v7_invocation_destroy(inv);
    return rc;
}

int axi_vm_v7_inspect_trusted(const uint8_t *module_bytes, size_t len,
                              const uint8_t trusted_pk[32],
                              char **contract_text, size_t *contract_len,
                              axi_diags *diags)
{
    axb_contract_mod model;
    char *text;
    size_t text_len;
    if (!contract_text || !contract_len || !trusted_pk
            || (len > 0 && !module_bytes)) {
        embed_diag(diags, "AXI-E001", "invalid v7 inspect arguments",
                   "provide signed bytes, an external trust anchor and outputs");
        return -1;
    }
    memset(&model, 0, sizeof model);
    if (axb_contract_v7_decode_trusted(&model, module_bytes, len,
                                       trusted_pk) != 0) {
        embed_diag(diags, "AXI-E003", "signed v7 inspection admission failed",
                   "inspect an intact v7 artifact signed by the configured producer");
        return -1;
    }
    text = axb_contract_v1_render(&model, &text_len);
    axb_contract_mod_free(&model);
    if (!text) {
        embed_diag(diags, "AXI-E005", "v7 inspection serialization failed",
                   "retry with enough host memory to preserve caller state");
        return -1;
    }
    *contract_text = text;
    *contract_len = text_len;
    return 0;
}
