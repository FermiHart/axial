/* axial — content addressing (W14). Bear Core. SPDX-License-Identifier: LicenseRef-SPL-1.0
 * The implementation is BearBasm's sha256_ni.h — the single source that
 * basm, bear-ld and bearverify already share. axial adds no fourth copy
 * of the algorithm, only a fourth consumer of the one source.
 */
#include "axi_hash.h"
#include "axi_alloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SHA256NI_CTX_TYPE axh_sha
#define SHA256NI_PREFIX   axh_
#include "sha256_ni.h"
#include "axi_osif.h"   /* AXI-INV-064: one door for the streams */

void axi_sha256(const void *data, size_t len, uint8_t out[32])
{
    axh_sha c;
    axh_init(&c);
    axh_update(&c, data, len);
    axh_final(&c, out);
}

void axi_hash_hex(const uint8_t h[32], char out[65])
{
    static const char H[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i * 2]     = H[h[i] >> 4];
        out[i * 2 + 1] = H[h[i] & 15];
    }
    out[64] = 0;
}

/* AXI-INV-019: the hash doctrine is only worth its ink if the primitive is
 * PROVEN, not assumed. FIPS 180-4 vectors, checked by the gate on every run.
 * An imported primitive that was never verified in-tree is a rumour. */
int axi_hash_selftest(void) {
    struct { const char *msg; unsigned long rep; const char *want; } v[] = {
        { "", 1,
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        { "abc", 1,
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1,
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
        { "a", 1000000,
          "cd c7 6e 5c 99 14 fb 92 81 a1 c7 e2 84 d7 3e 67"
          "f1 80 9a 48 a4 97 20 0e 04 6d 39 cc c7 11 2c d0" },
    };
    int bad = 0;
    for (unsigned i = 0; i < sizeof v / sizeof v[0]; i++) {
        size_t mlen = strlen(v[i].msg), n = mlen * v[i].rep;
        char *buf = (char *)axi_malloc(n ? n : 1);
        if (!buf) return 1;
        for (unsigned long r = 0; r < v[i].rep; r++) memcpy(buf + r * mlen, v[i].msg, mlen);
        uint8_t h[32]; char hex[65], want[65]; int w = 0;
        axi_sha256(buf, n, h);
        axi_hash_hex(h, hex);
        for (const char *p = v[i].want; *p && w < 64; p++)
            if (*p != ' ') want[w++] = *p;
        want[w] = 0;
        free(buf);
        if (strcmp(hex, want) != 0) {
            fprintf(AXI_ERR, "AXI-H001 sha256 vector %u FAILED\n  want %s\n  got  %s\n",
                    i, want, hex);
            bad = 1;
        }
    }
    if (!bad) printf("SHA256-VECTORS OK (FIPS 180-4, %zu)\n", sizeof v / sizeof v[0]);
    return bad;
}
