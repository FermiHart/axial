/* axial - bounded command-line wrapper for the offline dossier.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 */
#include "axi_dossier.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DOSSIER_FILE_MAX ((1024u * 1024u) + 104u)

static int hex_value(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_key(const char *text, uint8_t key[32])
{
    size_t i;
    if (!text || strlen(text) != 64) return 0;
    for (i = 0; i < 32; i++) {
        int hi = hex_value((unsigned char)text[i * 2]);
        int lo = hex_value((unsigned char)text[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        key[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

int main(int argc, char **argv)
{
    uint8_t *bytes, key[32];
    const uint8_t *trusted = NULL;
    char *json = NULL;
    size_t n = 0, json_len = 0;
    FILE *f;
    int c, read_failed, rc;
    if (argc != 2 && argc != 4) {
        fprintf(stderr, "usage: axi-dossier ARTIFACT [--trust-pk HEX]\n");
        return 2;
    }
    if (argc == 4) {
        if (strcmp(argv[2], "--trust-pk") != 0 || !parse_key(argv[3], key)) {
            fprintf(stderr, "axi-dossier: --trust-pk requires exactly 64 hex digits\n");
            return 2;
        }
        trusted = key;
    }
    f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "axi-dossier: cannot open %s\n", argv[1]);
        return 2;
    }
    bytes = (uint8_t *)malloc(DOSSIER_FILE_MAX + 1u);
    if (!bytes) { (void)fclose(f); return 2; }
    n = fread(bytes, 1, DOSSIER_FILE_MAX + 1u, f);
    read_failed = ferror(f);
    c = read_failed ? EOF : fgetc(f);
    if (fclose(f) != 0 || read_failed || c != EOF || n > DOSSIER_FILE_MAX) {
        free(bytes);
        fprintf(stderr, "axi-dossier: artifact exceeds bound or could not be read exactly\n");
        return 2;
    }
    rc = axi_dossier_bytes(bytes, n, trusted, &json, &json_len);
    free(bytes);
    if (rc == 2 || !json) return 2;
    if (fwrite(json, 1, json_len, stdout) != json_len) rc = 2;
    axi_dossier_free(json);
    return rc;
}
