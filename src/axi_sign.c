/* axial — the seal (W21). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * The whole file is 4 operations: build the message, sign it, verify it,
 * move it in and out of 104 bytes. Everything interesting is in the header.
 */
#include "axi_sign.h"
#include "axi_hash.h"
#include "axi_wipe.h"
#include "ed25519.h"   /* INV-275: canonical sovereign tree */

#include <stdio.h>
#include <string.h>

void axi_sig_msg(const uint8_t *body, size_t body_len, uint8_t out[AXI_SIG_MSG]) {
    /* 12 bytes of domain (NUL included, so "AXI-SIGN-v1x" can never collide
     * with a longer future domain that starts with the same 11 chars). */
    memset(out, 0, AXI_SIG_MSG);
    memcpy(out, AXI_SIG_DOMAIN, sizeof(AXI_SIG_DOMAIN));   /* 11 + NUL */
    axi_sha256(body, body_len, out + 12);
}

int axi_sig_make(const uint8_t *body, size_t body_len,
                  const uint8_t seed[32], axi_sig *out) {
    uint8_t sk[ED25519_SECKEY];
    uint8_t msg[AXI_SIG_MSG];
    int rc;

    axi_sig_msg(body, body_len, msg);
    ed25519_keypair_from_seed(seed, out->pk, sk);
    rc = ed25519_sign(out->sig, msg, AXI_SIG_MSG, sk);

    /* Best-effort explicit wipe of this expanded stack secret. The caller
     * owns its seed; this is not a forensic claim about registers or copies. */
    axi_private_wipe(sk, sizeof sk);
    return rc;
}

int axi_sig_verify(const uint8_t *body, size_t body_len, const axi_sig *s) {
    uint8_t msg[AXI_SIG_MSG];
    axi_sig_msg(body, body_len, msg);
    return ed25519_verify(s->sig, msg, AXI_SIG_MSG, s->pk);
}

void axi_sig_write(const axi_sig *s, uint8_t buf[AXBS_TRAILER]) {
    memcpy(buf, AXBS_MAGIC, 4);
    buf[4] = (uint8_t)(AXBS_VERSION      & 0xff);
    buf[5] = (uint8_t)(AXBS_VERSION >> 8 & 0xff);
    buf[6] = (uint8_t)(AXBS_VERSION >> 16& 0xff);
    buf[7] = (uint8_t)(AXBS_VERSION >> 24& 0xff);
    memcpy(buf + 8,  s->pk,  32);
    memcpy(buf + 40, s->sig, 64);
}

int axi_sig_read(const uint8_t buf[AXBS_TRAILER], axi_sig *out) {
    uint32_t ver;
    if (memcmp(buf, AXBS_MAGIC, 4) != 0) return -1;
    ver = (uint32_t)buf[4] | (uint32_t)buf[5] << 8
        | (uint32_t)buf[6] << 16 | (uint32_t)buf[7] << 24;
    if (ver != AXBS_VERSION) return -1;
    memcpy(out->pk,  buf + 8,  32);
    memcpy(out->sig, buf + 40, 64);
    return 0;
}

int axi_trusted_pk_load(const char *path, uint8_t out[32])
{
    FILE *f;
    uint8_t key[32];
    int extra, close_rc, rc = 1;
    if (!path || !*path || !out) return 1;
    f = fopen(path, "rb");
    if (!f) return 1;
    if (fread(key, 1, sizeof key, f) == sizeof key) {
        extra = fgetc(f);
        if (extra == EOF && !ferror(f)) {
            close_rc = fclose(f);
            f = NULL;
            if (close_rc == 0) {
                memcpy(out, key, sizeof key);
                rc = 0;
            }
        }
    }
    if (f) (void)fclose(f);
    memset(key, 0, sizeof key);
    return rc;
}

int axi_signing_seed_load(const char *path, uint8_t out[32])
{
    return axi_trusted_pk_load(path, out);
}
