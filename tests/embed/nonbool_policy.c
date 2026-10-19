/* AXI-INV-074: the host policy door accepts boolean verdicts only. */
#include "axi_embed.h"
#include "axi_contract.h"
#include "axi_sign.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int signed_v7_fixture(uint8_t **out, size_t *out_len, uint8_t pk[32])
{
    static const char model[] =
        "cell decide nregs=2\n"
        "  contract 1\n"
        "    param input json\n"
        "    ret u64\n"
        "    fuel 10\n"
        "  endcontract\n"
        "  k0 u64 7\n"
        "  ldk r1 k0\n"
        "  ret r1\n"
        "end\n";
    axb_contract_mod parsed;
    axi_sig identity;
    uint8_t seed[32];
    size_t i;
    int rc;
    memset(&parsed, 0, sizeof parsed);
    for (i = 0; i < 32; i++) seed[i] = (uint8_t)i;
    if (axb_contract_v1_parse(model, sizeof model - 1, &parsed) != 0)
        return -1;
    rc = axb_contract_v7_encode_signed(&parsed, seed, out, out_len);
    axb_contract_mod_free(&parsed);
    if (rc != 0 || axi_sig_make(seed, 0, seed, &identity) != 0) return -1;
    memcpy(pk, identity.pk, 32);
    return 0;
}

static uint8_t *read_file(const char *path, size_t *out_len)
{
    FILE *file = fopen(path, "rb");
    uint8_t *bytes;
    long length;
    if (!file) return NULL;
    if (fseek(file, 0, SEEK_END) != 0) { fclose(file); return NULL; }
    length = ftell(file);
    if (length <= 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }
    bytes = malloc((size_t)length);
    if (!bytes) { fclose(file); return NULL; }
    if (fread(bytes, 1, (size_t)length, file) != (size_t)length) {
        free(bytes);
        fclose(file);
        return NULL;
    }
    fclose(file);
    *out_len = (size_t)length;
    return bytes;
}

static int unhex_pk(const char *hex, uint8_t out[32])
{
    size_t i, j;
    if (strlen(hex) != 64) return -1;
    for (i = 0; i < 32; i++) {
        unsigned value = 0;
        for (j = 0; j < 2; j++) {
            unsigned char c = (unsigned char)hex[i * 2 + j];
            unsigned nibble;
            if (c >= '0' && c <= '9') nibble = c - '0';
            else if (c >= 'a' && c <= 'f') nibble = c - 'a' + 10;
            else return -1;
            value = value * 16 + nibble;
        }
        out[i] = (uint8_t)value;
    }
    return 0;
}

int main(int argc, char **argv)
{
    axi_grants grants;
    axi_vm_ctx *ctx;
    uint8_t *bytes;
    size_t bytes_len;
    char *output = NULL;
    size_t output_len = 0;
    uint64_t fuel_used = 0;
    int rc;
    uint8_t trusted_pk[32];
    int effect_mode;
    FILE *sink = NULL;
    axi_diags diags;

    if (argc != 1 && argc != 3 && argc != 4) return 2;
    effect_mode = argc == 4 && strcmp(argv[3], "effect-refused") == 0;
    if (argc == 4 && !effect_mode) return 2;
    if (argc >= 3) {
        if (unhex_pk(argv[2], trusted_pk) != 0) return 2;
        bytes = read_file(argv[1], &bytes_len);
        if (!bytes) return 2;
    } else {
        bytes = NULL;
        if (signed_v7_fixture(&bytes, &bytes_len, trusted_pk) != 0) return 2;
    }
    axi_grants_init(&grants);
    if (effect_mode && axi_grants_add(&grants, "io.Write") != 0) {
        free(bytes);
        return 2;
    }
    if (effect_mode && !(sink = tmpfile())) {
        free(bytes);
        return 2;
    }
    {
        static const uint8_t bad_module[] = {0};
        char *meta = (char *)(uintptr_t)1;
        size_t meta_len = 99;
        axi_diags_init(&diags);
        rc = axi_vm_inspect(bad_module, sizeof bad_module, trusted_pk,
                            &meta, &meta_len, &diags);
        if (rc != -1 || meta != (char *)(uintptr_t)1 || meta_len != 99
                || diags.n != 1 || strcmp(diags.d[0].code, "AXI-E003") != 0) {
            free(bytes);
            if (sink) fclose(sink);
            return 1;
        }
    }
    axi_diags_init(&diags);
    ctx = axi_vm_create(bytes, bytes_len, trusted_pk, &grants, sink, &diags);
    if (!ctx || diags.n != 0) {
        free(bytes);
        if (sink) fclose(sink);
        return 2;
    }
    {
        axi_vm_ctx *untrusted;
        bytes[bytes_len - 1] ^= 1;
        axi_diags_init(&diags);
        untrusted = axi_vm_create(bytes, bytes_len, trusted_pk, &grants, sink,
                                  &diags);
        bytes[bytes_len - 1] ^= 1;
        if (untrusted != NULL || diags.n != 1
                || strcmp(diags.d[0].code, "AXI-E003") != 0) {
            axi_vm_destroy(untrusted);
            axi_vm_destroy(ctx);
            free(bytes);
            if (sink) fclose(sink);
            return 1;
        }
    }
    free(bytes);

    {
        char *missing_output = (char *)(uintptr_t)1;
        size_t missing_len = 99;
        uint64_t missing_fuel = 99;
        axi_diags_init(&diags);
        rc = axi_vm_eval(ctx, "missing", "{}", 2, &missing_output,
                         &missing_len, &missing_fuel, &diags);
        if (rc != -1 || missing_output != (char *)(uintptr_t)1
                || missing_len != 99 || missing_fuel != 99 || diags.n != 1
                || strcmp(diags.d[0].code, "AXI-E002") != 0
                || diags.d[0].off != AXI_NO_OFF
                || diags.d[0].msg[0] == '\0' || diags.d[0].fix[0] == '\0') {
            axi_vm_destroy(ctx);
            if (sink) fclose(sink);
            return 1;
        }
    }

    axi_diags_init(&diags);
    rc = axi_vm_eval(ctx, "decide", "{}", 2, &output, &output_len,
                     &fuel_used, &diags);
    axi_vm_destroy(ctx);
    if (sink) {
        if (fflush(sink) != 0 || fseek(sink, 0, SEEK_END) != 0 || ftell(sink) != 0) {
            fclose(sink);
            free(output);
            return 1;
        }
        fclose(sink);
    }
    /* INV-482 / AXI-INV-149: effect mode must reach the missing-ledger door,
     * not pass accidentally through an earlier fuel refusal. */
    if (rc != -1 || output != NULL || output_len != 0 || diags.n != 1
            || strcmp(diags.d[0].code,
                       effect_mode ? "AXI-R017" : "AXI-E004") != 0
            || diags.d[0].msg[0] == '\0' || diags.d[0].fix[0] == '\0') {
        fprintf(stderr, "embed guard escaped: rc=%d output_len=%zu diag=%s\n",
                rc, output_len, diags.n ? diags.d[0].code : "<none>");
        free(output);
        return 1;
    }
    return 0;
}
