/* SPDX-License-Identifier: LicenseRef-SPL-1.0
 * Positive public standards fixtures only; never use these seeds in production.
 * RFC 8032 sec. 7.1 tests 1-3; SHA examples: FIPS 180-4 / NIST.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "ed25519.h"
#include "sha256_ni.h"

static int unhex(const char *s, uint8_t *out, size_t n) {
    if (strlen(s) != n * 2) return 1;
    for (size_t i = 0; i < n; ++i) {
        unsigned x;
        if (sscanf(s + 2*i, "%2x", &x) != 1) return 1;
        out[i] = (uint8_t)x;
    }
    return 0;
}

static int signature_vectors(void) {
    static const struct {
        const char *seed, *pk, *msg, *sig;
    } vectors[] = {
        {"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
         "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
        {"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
         "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
        {"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
         "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
         "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"}
    };
    for (size_t i = 0; i < sizeof vectors / sizeof vectors[0]; ++i) {
        uint8_t seed[32], pk[32], sk[64], expected_pk[32], msg[2] = {0}, sig[64], expected[64];
        uint32_t n = (uint32_t)(strlen(vectors[i].msg) / 2);
        if (unhex(vectors[i].seed, seed, sizeof seed) ||
            unhex(vectors[i].pk, expected_pk, sizeof expected_pk) ||
            unhex(vectors[i].msg, msg, n) ||
            unhex(vectors[i].sig, expected, sizeof expected)) return 1;
        ed25519_keypair_from_seed(seed, pk, sk);
        if (memcmp(pk, expected_pk, sizeof pk) ||
            ed25519_sign(sig, msg, n, sk) ||
            memcmp(sig, expected, sizeof sig) ||
            ed25519_verify(expected, msg, n, expected_pk)) {
            fprintf(stderr, "FAIL: RFC 8032 vector %zu\n", i + 1);
            return 1;
        }
    }
    puts("PASS: RFC 8032 Ed25519 tests 1-3 (derive, sign, verify)");
    return 0;
}

static int hash_vectors(void) {
    static const struct { const char *msg, *sha256, *sha512; } vectors[] = {
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
         "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
         "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
         "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
         "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
        {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
         "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
         "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
         "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"}
    };
    for (size_t i = 0; i < sizeof vectors / sizeof vectors[0]; ++i) {
        uint8_t got256[32], got512[64], expected256[32], expected512[64];
        size_t n = strlen(vectors[i].msg);
        sha256ni_ctx c;
        if (unhex(vectors[i].sha256, expected256, 32) ||
            unhex(vectors[i].sha512, expected512, 64)) return 1;
        sha256ni_init(&c);
#ifdef SHA256NI_X86
        printf("SHA-256 vector %zu dispatch accelerated=%d\n", i + 1, c.accelerated);
#else
        printf("SHA-256 vector %zu software-only\n", i + 1);
#endif
        sha256ni_update(&c, vectors[i].msg, n);
        sha256ni_final(&c, got256);
        sha512(vectors[i].msg, (uint32_t)n, got512);
        if (memcmp(got256, expected256, 32) || memcmp(got512, expected512, 64)) {
            fprintf(stderr, "FAIL: hash vector %zu\n", i + 1);
            return 1;
        }
    }
    puts("PASS: three SHA-256 and three SHA-512 known-answer vectors");
    return 0;
}

int main(void) {
    if (signature_vectors() || hash_vectors()) return 1;
    return 0;
}
