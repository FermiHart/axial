/* axial — embed API demo for examples/policy.axi.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * Build:
 *   make demo
 *
 * Run:
 *   ./scripts/jash_policy_demo.sh
 * Run:
 *   ./jash_policy_demo MODULE.axb TRUSTED_PK_HEX
 *
 * The demo loads the signed-v7 policy once and evaluates decide() repeatedly,
 * using the explicit producer trust anchor and showing
 * the allow/deny verdict and the fuel spent.
 */
#include "axi_embed.h"
#include "axi_effect.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static int eval_one(axi_vm_ctx *ctx, const char *json, const char *label)
{
    char *out = NULL;
    size_t out_len = 0;
    uint64_t fuel = 0;
    int r = axi_vm_eval(ctx, "decide", json, strlen(json), &out, &out_len, &fuel, NULL);
    printf("%-24s -> ", label);
    if (r == 0)       printf("ALLOW (output=%.*s, fuel=%llu)\n",
                              (int)out_len, out ? out : "",
                              (unsigned long long)fuel);
    else if (r == 1)  printf("DENY (output=%.*s, fuel=%llu)\n",
                              (int)out_len, out ? out : "",
                              (unsigned long long)fuel);
    else              printf("TRAP (fuel=%llu)\n", (unsigned long long)fuel);
    free(out);
    return r;
}

int main(int argc, char **argv)
{
    const char *module;
    uint8_t trusted_pk[32];
    size_t len;
    uint8_t *bytes;
    if (argc != 3 || unhex_pk(argv[2], trusted_pk) != 0) {
        fprintf(stderr, "usage: %s MODULE.axb TRUSTED_PK_HEX\n", argv[0]);
        return 2;
    }
    module = argv[1];
    bytes = read_file(module, &len);
    if (!bytes) {
        fprintf(stderr, "cannot read %s\n", module);
        return 1;
    }

    axi_grants grants;
    axi_grants_init(&grants);
    if (axi_grants_add(&grants, "fs.Read") != 0) {
        free(bytes);
        return 1;
    }

    {
        char *meta = NULL;
        size_t meta_len = 0;
        if (axi_vm_inspect(bytes, len, trusted_pk,
                           &meta, &meta_len, NULL) == 0) {
            printf("meta %.*s\n", (int)meta_len, meta ? meta : "");
            free(meta);
        }
    }

    axi_vm_ctx *ctx = axi_vm_create(bytes, len, trusted_pk, &grants, NULL, NULL);
    free(bytes);
    if (!ctx) {
        fprintf(stderr, "axi_vm_create failed\n");
        return 1;
    }

    printf("loaded %s\n\n", module);
    eval_one(ctx, "{\"builtin\":\"rm\",\"args\":[\"/home/agent/workspace/foo\"]}",
             "rm inside workspace");
    eval_one(ctx, "{\"builtin\":\"rm\",\"args\":[\"/etc/passwd\"]}",
             "rm outside workspace");
    eval_one(ctx, "{\"builtin\":\"export\",\"args\":[\"SECRET\"]}",
             "export secret name");
    eval_one(ctx, "{\"builtin\":\"export\",\"args\":[\"PATH\"]}",
             "export safe name");
    eval_one(ctx, "{\"builtin\":\"ls\",\"args\":[]}",
             "unknown builtin");

    axi_vm_destroy(ctx);
    return 0;
}
