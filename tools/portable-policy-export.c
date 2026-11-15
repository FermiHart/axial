/* Axial portable pure profile v1: export actual compiler words, not JS rules.
 * Build-time tool and native differential oracle only. It does not grant
 * authority, accept signed artifacts, or modify the frozen embed-v1 ABI.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0 */
#include "axi_ast.h"
#include "axi_codegen.h"
#include "axi_contract.h"
#include "axi_hash.h"
#include "axi_vm.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PROFILE "axial.portable-pure.v1"
#define CORE_REVISION "6623a69ef5f9729563f54ffb1ebf3e7034e4fcda"
#ifndef AXIAL_PORTABLE_CORE_DIGEST
#error "Build with tools/portable-policy-build.cjs to record exact compiler sources"
#endif
#define MAX_SOURCE 65536u
#define MAX_CODE 128u
#define MAX_REGS 32u
#define MAX_CONSTANTS 32u
#define MAX_FUEL 4096u

/* An upstream opcode change must refuse compilation, never silently drift. */
typedef char opcode_ids_must_match[
    OP_NOP == 0 && OP_LDK == 1 && OP_MOV == 2 && OP_NOT == 8 && OP_EQ == 9
    && OP_JMP == 12 && OP_JF == 13 && OP_RET == 15 && OP_HALT == 22 ? 1 : -1];

static int ident(const char *s, size_t n)
{
    if (!s || !n || n > 63) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || c == '_' || (i && c >= '0' && c <= '9'))) return 0;
    }
    return 1;
}

static int profile_ok(const axb_contract_mod *m)
{
    const axb_cell *c;
    const axb_manifest *f;
    if (!m || m->body.n != 1 || m->nmanifest != 1 || m->body.neff
            || m->body.nbuiltin) return 0;
    c = &m->body.cells[0]; f = &m->manifest[0];
    if (!ident(c->name, strlen(c->name)) || f->flags != AXB_MANIFEST_FLAG_PURE
            || f->ncaps || f->nerrors || f->nlaws || f->nreturns != 1
            || f->returns[0].tag != AXB_MT_BOOL || f->nparams > 16
            || !f->fuel_max || f->fuel_max > MAX_FUEL
            || !c->nregs || c->nregs > MAX_REGS || f->nparams > c->nregs
            || c->nk > MAX_CONSTANTS || !c->nc || c->nc > MAX_CODE) return 0;
    for (uint32_t i = 0; i < f->nparams; i++) {
        if (f->params[i].type.tag != AXB_MT_BOOL
                || !ident(f->params[i].name.p, f->params[i].name.len)) return 0;
        for (uint32_t j = 0; j < i; j++)
            if (f->params[i].name.len == f->params[j].name.len
                && !memcmp(f->params[i].name.p, f->params[j].name.p,
                           f->params[i].name.len)) return 0;
    }
    for (uint32_t i = 0; i < c->nk; i++)
        if (c->k[i].tag != AXB_KU64 || c->k[i].u > 1) return 0;
    for (uint32_t pc = 0; pc < c->nc; pc++) {
        uint32_t w = c->code[pc];
        uint8_t op = (uint8_t)w, a = (uint8_t)(w >> 8);
        uint8_t b = (uint8_t)(w >> 16), d = (uint8_t)(w >> 24);
        uint16_t bc = (uint16_t)((b << 8) | d);
        int jump = (int16_t)bc;
        const axb_opinfo *info = axb_op_info(op);
        if (!info || info->fuel != 1) return 0;
        switch (op) {
        case OP_NOP: case OP_HALT: if (a || b || d) return 0; break;
        case OP_LDK: if (a >= c->nregs || bc >= c->nk) return 0; break;
        case OP_MOV: case OP_NOT:
            if (a >= c->nregs || b >= c->nregs || d) return 0;
            break;
        case OP_EQ:
            if (a >= c->nregs || b >= c->nregs || d >= c->nregs) return 0;
            break;
        case OP_JMP: case OP_JF:
            if ((op == OP_JMP ? a != 0 : a >= c->nregs)
                || jump <= 0 || (uint32_t)jump >= c->nc - pc) return 0;
            break;
        case OP_RET: if (a >= c->nregs || b || d) return 0; break;
        default: return 0;
        }
    }
    return 1;
}

static int compile_source(const char *path, axb_contract_mod *out,
                           uint8_t source_hash[32])
{
    char *source = NULL, *assembly = NULL, *canonical = NULL;
    axi_node *unit = NULL;
    axi_diags diagnostics;
    size_t length, assembly_length = 0;
    FILE *input = fopen(path, "rb");
    int ok = 0;
    memset(out, 0, sizeof *out);
    if (!input) { perror(path); return 0; }
    source = malloc(MAX_SOURCE + 1u);
    if (!source) { fclose(input); return 0; }
    length = fread(source, 1, MAX_SOURCE + 1u, input);
    if (ferror(input) || length == 0 || length > MAX_SOURCE
            || memchr(source, 0, length) || memchr(source, '\r', length)
            || memchr(source, '\t', length)) {
        fclose(input); free(source); return 0;
    }
    fclose(input);
    source[length] = 0;
    axi_sha256(source, length, source_hash);
    axi_diags_init(&diagnostics);
    unit = axi_parse_unit(source, length, path, &diagnostics);
    if (!unit || diagnostics.n || diagnostics.dropped) goto done;
    canonical = axi_canon_render(source, length, unit);
    if (!canonical || strlen(canonical) != length || memcmp(canonical, source, length)) {
        fprintf(stderr, "AXP-C001 source is not canonical; use axi canon and review\n");
        goto done;
    }
    axi_type_check(unit, &diagnostics);
    if (diagnostics.n || diagnostics.dropped) goto done;
    assembly = axi_codegen_contract_v1(unit, &assembly_length);
    if (!assembly || axb_contract_v1_parse(assembly, assembly_length, out) != 0
            || axb_contract_v1_verify(out) != 0 || !profile_ok(out)) goto done;
    ok = 1;
done:
    for (int i = 0; i < diagnostics.n; i++)
        fprintf(stderr, "%s %s\n", diagnostics.d[i].code, diagnostics.d[i].msg);
    free(assembly);
    free(canonical);
    axi_ast_free(unit);
    free(source);
    if (!ok) axb_contract_mod_free(out);
    return ok;
}

static void emit_program(const axb_contract_mod *m, const uint8_t hash[32])
{
    const axb_cell *c = &m->body.cells[0];
    const axb_manifest *f = &m->manifest[0];
    char source[65], iface[65], body[65];
    axi_hash_hex(hash, source);
    axi_hash_hex(f->iface_hash, iface);
    axi_hash_hex(f->body_hash, body);
    printf("{\n  \"format\":\"%s\",\n", PROFILE);
    printf("  \"compilerSourceRevision\":\"%s\",\n", CORE_REVISION);
    printf("  \"compilerSourceDigest\":\"%s\",\n", AXIAL_PORTABLE_CORE_DIGEST);
    printf("  \"sourceSha256\":\"%s\",\n", source);
    printf("  \"ifaceHash\":\"%s\",\n  \"bodyHash\":\"%s\",\n", iface, body);
    printf("  \"entry\":\"%s\",\n  \"fuelMax\":%llu,\n", c->name,
           (unsigned long long)f->fuel_max);
    printf("  \"params\":[");
    for (uint32_t i = 0; i < f->nparams; i++)
        printf("%s\"%.*s\"", i ? "," : "", (int)f->params[i].name.len,
               f->params[i].name.p);
    printf("],\n  \"registers\":%u,\n  \"constants\":[", c->nregs);
    for (uint32_t i = 0; i < c->nk; i++)
        printf("%s%llu", i ? "," : "", (unsigned long long)c->k[i].u);
    printf("],\n  \"code\":[");
    for (uint32_t i = 0; i < c->nc; i++)
        printf("%s%u", i ? "," : "", c->code[i]);
    printf("]\n}\n");
}

static int emit_oracle(const axb_contract_mod *m)
{
    const axb_manifest *f = &m->manifest[0];
    uint64_t last = f->fuel_max < 256 ? f->fuel_max : 256;
    if (f->nparams > 8) return 0; /* exhaustive fixture table stays bounded */
    for (uint32_t mask = 0; mask < (1u << f->nparams); mask++) {
        for (uint64_t step = 0; step <= last + 1; step++) {
            axi_vval args[16], value;
            axi_diags diagnostics;
            axi_vm_output_storage storage = {0};
            uint64_t requested = step == last + 1 ? MAX_FUEL : step, used = 0;
            uint64_t fuel = requested < f->fuel_max ? requested : f->fuel_max;
            int exhausted = 0, ok;
            memset(args, 0, sizeof args); memset(&value, 0, sizeof value);
            for (uint32_t i = 0; i < f->nparams; i++) {
                args[i].kind = VB_BOOL; args[i].bits = (mask >> i) & 1;
            }
            axi_diags_init(&diagnostics);
            /* Source was parsed, type checked, compiled and contract verified
             * above. This is an oracle for that model, never an admission API. */
            ok = axi_vm_run_contract_cell_preverified_pure_scoped_diag(
                m, 0, args, (uint8_t)f->nparams, &value, fuel, &used,
                &exhausted, &diagnostics, &storage);
            if (ok && (value.kind != VB_BOOL || value.bits > 1)) {
                axi_vm_output_storage_release(&storage); return 0;
            }
            printf("{\"mask\":%u,\"fuel\":%llu,\"ok\":%s,\"allowed\":%s,"
                   "\"fuelUsed\":%llu,\"fuelLimit\":%llu,\"fuelExhausted\":%s}\n",
                   mask, (unsigned long long)requested, ok ? "true" : "false",
                   ok && value.bits ? "true" : "false", (unsigned long long)used,
                   (unsigned long long)fuel, exhausted ? "true" : "false");
            axi_vm_output_storage_release(&storage);
        }
    }
    return !ferror(stdout);
}

int main(int argc, char **argv)
{
    axb_contract_mod model;
    uint8_t source_hash[32];
    int ok;
    if (argc != 3 || (strcmp(argv[1], "export") && strcmp(argv[1], "oracle"))) {
        fprintf(stderr, "usage: portable-policy-export export|oracle source.axi\n");
        return 2;
    }
    if (!compile_source(argv[2], &model, source_hash)) {
        fprintf(stderr, "AXP-P001 source refused by compiler or portable pure v1\n");
        return 1;
    }
    if (!strcmp(argv[1], "export")) { emit_program(&model, source_hash); ok = !ferror(stdout); }
    else ok = emit_oracle(&model);
    axb_contract_mod_free(&model);
    return ok ? 0 : 1;
}
