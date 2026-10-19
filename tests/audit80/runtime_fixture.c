/* Explicit workload families, generated as canonical AXS contract-v1 text.
 * They exercise runtime paths, not a claim of production representativeness. */
#include "runtime_fixture.h"
#include "axi_sign.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const uint8_t seed[32] = {80, 69, 1}; /* Public test identity. */
const char *const runtime80_case_names[RUNTIME80_CASES] = {
    "policy_allow", "policy_deny", "bool_false", "json_plain", "json_escaped",
    "call_depth_8", "compute_128", "division_trap", "fuel_trap",
    "interface_refusal", "workspace_refusal", "json_trap"
};

static int append(char *text, size_t cap, size_t *len, const char *fmt, ...)
{
    va_list args;
    int n;
    va_start(args, fmt);
    n = vsnprintf(text + *len, cap - *len, fmt, args);
    va_end(args);
    if (n < 0 || (size_t)n >= cap - *len) return -1;
    *len += (size_t)n;
    return 0;
}

int runtime80_fixture_resign(runtime80_fixture *f)
{
    uint8_t *bytes = NULL;
    size_t len = 0;
    if (axb_contract_v7_encode_signed(&f->model, seed, &bytes, &len) != 0) return -1;
    free(f->bytes); f->bytes = bytes; f->len = len;
    return 0;
}

int runtime80_fixture_init(runtime80_fixture *f, unsigned cells, unsigned laws)
{
    char *text;
    size_t len = 0, cap = 131072;
    unsigned i;
    axi_sig identity;
    if (!f || cells < 13 || cells > 256 || laws > 64 || laws > cells - 13) return -1;
    memset(f, 0, sizeof *f);
    text = malloc(cap);
    if (!text) return -1;
#define ADD(...) do { if (append(text, cap, &len, __VA_ARGS__) != 0) goto fail; } while (0)
    ADD(".builtin json.get\n");
    ADD("cell policy nregs=3\n  contract 1\n    param amount u64\n"
        "    ret decision\n    fuel 100\n    policy\n  endcontract\n"
        "  k0 u64 64\n  ldk r1 k0\n  lt r2 r0 r1\n  ret r2\nend\n");
    ADD("cell boolean nregs=2\n  contract 1\n    ret bool\n    fuel 10\n"
        "    pure\n  endcontract\n  k0 u64 1\n  k1 u64 2\n"
        "  ldk r0 k0\n  ldk r1 k1\n  eq r0 r0 r1\n  ret r0\nend\n");
    ADD("cell json nregs=3\n  contract 1\n    param input json\n"
        "    ret str\n    fuel 100\n    pure\n  endcontract\n"
        "  k0 str \"$.role\"\n  ldk r1 k0\n  builtin r2 @json.get r0\n  ret r2\nend\n");
    ADD("cell compute nregs=4\n  contract 1\n    param start u64\n"
        "    param step u64\n    param stop u64\n    ret u64\n"
        "    fuel 65536\n    pure\n  endcontract\n"
        "  add r0 r0 r1\n  lt r3 r0 r2\n  jf r3 +2\n  jmp -3\n  ret r0\nend\n");
    ADD("cell divide nregs=2\n  contract 1\n    param numerator u64\n"
        "    param denominator u64\n    ret u64\n    fuel 100\n"
        "    pure\n  endcontract\n  div r0 r0 r1\n  ret r0\nend\n");
    for (i = 0; i < 8; i++) {
        ADD("cell call_%02u nregs=2\n  contract 1\n    param value u64\n"
            "    ret u64\n    fuel 100\n    pure\n  endcontract\n", i);
        if (i < 7) ADD("  call r0 @call_%02u 1\n  ret r0\nend\n", i + 1);
        else ADD("  k0 u64 1\n  ldk r1 k0\n  add r0 r0 r1\n  ret r0\nend\n");
    }
    for (i = 13; i < cells; i++) {
        int law = i - 13 < laws;
        ADD("cell %s_%03u nregs=1\n  contract 1\n    ret %s\n"
            "    fuel 1000\n    pure\n  endcontract\n  k0 u64 %u\n  ldk r0 k0\n",
            law ? "law" : "padding", cells - 1 - i, law ? "bool" : "u64", i);
        if (law) ADD("  eq r0 r0 r0\n");
        ADD("  ret r0\nend\n");
    }
    if (axb_contract_v1_parse(text, len, &f->model) != 0) goto fail;
    if (laws) {
        axb_seal_certificate *cert = &f->model.seal;
        cert->present = 1; cert->version = AXPC_VERSION; cert->maturity = AXPC_MATURITY_CHECKED;
        cert->law_count = laws; cert->aggregate_budget = (uint64_t)laws * 1000;
        cert->aggregate_fuel_used = (uint64_t)laws * 3;
        axb_checker_protocol_id(cert->checker_protocol_id);
        axb_checker_semantics_root(cert->checker_semantics_root);
        for (i = 0; i < laws; i++) {
            axb_seal_law *law = &cert->laws[i];
            unsigned cell = 13 + i;
            law->cell_index = cell; law->name.p = f->model.body.cells[cell].name;
            law->name.len = (uint32_t)strlen(law->name.p);
            memcpy(law->iface_hash, f->model.manifest[cell].iface_hash, 32);
            memcpy(law->body_hash, f->model.manifest[cell].body_hash, 32);
            law->budget = 1000; law->fuel_used = 3;
            law->result_kind = AXPC_RESULT_BOOL; law->verdict = AXPC_VERDICT_TRUE;
        }
        if (axb_contract_seal_subject_root(&f->model, cert->subject_root) != 0) goto fail;
    }
    if (runtime80_fixture_resign(f) != 0 || axi_sig_make(seed, 0, seed, &identity) != 0) goto fail;
    memcpy(f->pk, identity.pk, 32);
    free(text);
    return 0;
fail:
    free(text); runtime80_fixture_free(f); return -1;
#undef ADD
}

void runtime80_fixture_free(runtime80_fixture *f)
{
    if (!f) return;
    axb_contract_mod_free(&f->model); free(f->bytes); memset(f, 0, sizeof *f);
}

int runtime80_context(const runtime80_fixture *f, unsigned profile, axi_embed_v1_context **out)
{
    axi_embed_v1_context_options options = {0};
    options.abi_version = AXI_EMBED_V1_ABI_VERSION; options.struct_size = sizeof options;
    options.admission_profile = profile; options.module.data = f->bytes; options.module.len = f->len;
    memcpy(options.trusted_producer_pk, f->pk, 32);
    return (int)axi_embed_v1_context_create(&options, out, NULL);
}

int runtime80_prepare(const runtime80_fixture *f, unsigned which, unsigned input, runtime80_case *t)
{
    const char *name = "policy";
    unsigned i;
    if (which >= RUNTIME80_CASES) return -1;
    memset(t, 0, sizeof *t);
    t->request.abi_version = t->outcome.abi_version = AXI_EMBED_V1_ABI_VERSION;
    t->request.struct_size = sizeof t->request; t->outcome.struct_size = sizeof t->outcome;
    t->request.args = t->args; t->request.fuel_limit = 65536;
    t->request.workspace.data = t->workspace; t->request.workspace.capacity = sizeof t->workspace;
    for (i = 0; i < 3; i++) t->args[i].kind = AXI_EMBED_V1_VALUE_U64;
    t->kind = AXI_EMBED_V1_OUTCOME_VALUE; t->value_kind = AXI_EMBED_V1_VALUE_U64;
    switch (which) {
    case 0: case 1:
        t->request.argc = 1; t->args[0].bits = input % 64 + (which ? 64 : 0);
        t->kind = which ? AXI_EMBED_V1_OUTCOME_DENY : AXI_EMBED_V1_OUTCOME_ALLOW;
        t->value_kind = AXI_EMBED_V1_VALUE_BOOL; t->bits = which ? 0 : 1; t->fuel = 3; break;
    case 2:
        name = "boolean"; t->value_kind = AXI_EMBED_V1_VALUE_BOOL; t->fuel = 4; break;
    case 3: case 4: case 10: case 11:
        name = "json"; t->request.argc = 1; t->args[0].kind = AXI_EMBED_V1_VALUE_STR;
        t->args[0].payload.data = (const uint8_t *)(which == 3 ? "{\"role\":\"viewer\"}"
                                    : which == 11 ? "{" : "{\"role\":\"view\\ner\"}");
        t->args[0].payload.len = strlen((const char *)t->args[0].payload.data);
        t->value_kind = AXI_EMBED_V1_VALUE_STR; t->fuel = 10;
        t->payload = which == 3 ? "viewer" : "view\ner"; t->payload_len = strlen(t->payload);
        if (which == 10) { t->request.workspace.capacity = 1; t->kind = AXI_EMBED_V1_OUTCOME_BUFFER_TOO_SMALL; }
        /* JSON parameters are validated before the first opcode. */
        if (which == 11) { t->kind = AXI_EMBED_V1_OUTCOME_TRAP; t->fuel = 0; }
        break;
    case 5:
        name = "call_00"; t->request.argc = 1; t->args[0].bits = input;
        t->bits = (uint64_t)input + 1; t->fuel = 38; break;
    case 6:
        name = "compute"; t->request.argc = 3; t->args[1].bits = 1; t->args[2].bits = 128;
        t->bits = 128; t->fuel = 512; break;
    case 7: case 8:
        name = "divide"; t->request.argc = 2; t->args[0].bits = input;
        t->kind = AXI_EMBED_V1_OUTCOME_TRAP; t->fuel = which == 7 ? 4 : 0;
        if (which == 8) { t->request.fuel_limit = 3; t->flags = AXI_EMBED_V1_OUTCOME_F_FUEL_EXHAUSTED; }
        break;
    case 9:
        t->kind = AXI_EMBED_V1_OUTCOME_REFUSED; break;
    }
    t->request.cell.data = (const uint8_t *)name; t->request.cell.len = strlen(name);
    for (i = 0; i < f->model.body.n; i++) if (!strcmp(name, f->model.body.cells[i].name)) break;
    if (i == f->model.body.n) return -1;
    memcpy(t->request.expected_iface_hash, f->model.manifest[i].iface_hash, 32);
    if (which == 9) t->request.expected_iface_hash[0] ^= 1;
    memset(t->workspace, 0xa5, sizeof t->workspace);
    return 0;
}

int runtime80_result(const runtime80_case *t)
{
    const axi_embed_v1_outcome *o = &t->outcome;
    if (o->kind != t->kind || o->fuel_used != t->fuel || o->flags != t->flags) return -1;
    if (t->kind == AXI_EMBED_V1_OUTCOME_BUFFER_TOO_SMALL)
        return o->workspace_required == t->payload_len && t->workspace[0] == 0xa5 ? 0 : -1;
    if (t->kind == AXI_EMBED_V1_OUTCOME_TRAP || t->kind == AXI_EMBED_V1_OUTCOME_REFUSED)
        return t->workspace[0] == 0xa5 ? 0 : -1;
    if (o->value.kind != t->value_kind || o->value.bits != t->bits) return -1;
    if (t->payload_len && (o->value.payload.len != t->payload_len
                || memcmp(o->value.payload.data, t->payload, t->payload_len))) return -1;
    return 0;
}

uint64_t runtime80_now_ns(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) abort();
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
