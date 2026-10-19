/* axial — the seal (W21). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * W14 bound bytecode to the source text it came from. W19 made the module
 * declare its own authority. Both are claims the module makes about itself.
 * A claim a stranger cannot check is a rumour.
 *
 * The seal is the answer to one question: WHO produced this artifact, and
 * has anyone touched it since? It is a detached Ed25519 signature appended
 * to the module, and it is the only thing in the container the module does
 * not get to say about itself.
 *
 * Container, exactly:
 *   [ AXB0 body ................................ body_len bytes ]
 *   [ AXBS trailer ............................. 104 bytes, 0 or 1 of them ]
 * Trailer:
 *   magic  "AXBS"   4
 *   u32    version  AXBS_VERSION
 *   u8     pk[32]   the public key that signed
 *   u8     sig[64]  detached signature
 *
 * WHAT IS SIGNED (and why it is not the body itself):
 *   msg = "AXI-SIGN-v1\0" || sha256(body)          -> 44 bytes
 *   Two reasons, both load-bearing:
 *   1. The canonical Ed25519 implementation has a fixed ED25519_MAX_MSG
 *      scratch ceiling. Signing the body directly would silently work for
 *      small modules and fail when a real one crossed that ceiling. A digest
 *      is O(1).
 *   2. Domain separation. A bare signature over 32 raw bytes is replayable
 *      anywhere those same 32 bytes appear — an axi_trace tip, a ledger row,
 *      an src_hash. The domain string means a seal signature is valid for a
 *      module and for nothing else in this system, ever.
 *
 * WHAT THE SEAL DOES NOT DO: it does not say the code is good, and it does
 * not grant authority. Effects still need --cap (W19), fuel still binds
 * (W10), the VM still refuses undeclared effects. A signed module that asks
 * for authority it was not granted is refused exactly as loudly as an
 * unsigned one. The seal answers "from whom", never "may it".
 */
#ifndef AXI_SIGN_H
#define AXI_SIGN_H

#include <stdint.h>
#include <stddef.h>
#include "ed25519.h"

#define AXBS_MAGIC     "AXBS"
#define AXBS_VERSION   1u
#define AXBS_TRAILER   104u                /* 4 + 4 + 32 + 64 */
#define AXI_SIG_DOMAIN "AXI-SIGN-v1"      /* 11 chars; the NUL is signed too */
#define AXI_SIG_MSG   44u                 /* 12 + 32 */

/* CA21: ed25519_sign/verify each instantiate this canonical source array.
 * Accounted callers reserve it only while crossing the crypto call. */
#define AXI_ED25519_MESSAGE_SCRATCH_BYTES (64u + ED25519_MAX_MSG)
typedef char axi_ed25519_message_scratch_probe[
    AXI_ED25519_MESSAGE_SCRATCH_BYTES == 64u + ED25519_MAX_MSG ? 1 : -1];

typedef struct {
    uint8_t pk[32];
    uint8_t sig[64];
} axi_sig;

/* Build the domain-separated message that a seal signs. */
void axi_sig_msg(const uint8_t *body, size_t body_len, uint8_t out[AXI_SIG_MSG]);

/* Sign. seed is 32 bytes of the producer's own key material; the caller owns
 * it and this function never keeps a copy. Returns 0 on success. */
int  axi_sig_make(const uint8_t *body, size_t body_len,
                   const uint8_t seed[32], axi_sig *out);

/* Verify a seal against a body. Returns 0 if the signature is good.
 * A non-zero return means the artifact is NOT what its producer signed —
 * the caller must refuse, never warn. */
int  axi_sig_verify(const uint8_t *body, size_t body_len, const axi_sig *s);

/* Serialize a trailer into buf (AXBS_TRAILER bytes). */
void axi_sig_write(const axi_sig *s, uint8_t buf[AXBS_TRAILER]);

/* Parse a trailer. Returns 0 on success, -1 if magic/version are wrong. */
int  axi_sig_read(const uint8_t buf[AXBS_TRAILER], axi_sig *out);

/* Load one operator-selected raw public key. The artifact is never consulted
 * for trust, and caller-owned output is unchanged on every refusal. */
int axi_trusted_pk_load(const char *path, uint8_t out[32]);

/* Load one operator-selected raw signing seed. Caller-owned output is
 * unchanged on refusal and must be zeroed by the successful caller. */
int axi_signing_seed_load(const char *path, uint8_t out[32]);

/* Printing a key is axi_hash_hex()'s job (axi_hash.h) — 32 bytes is 32
 * bytes, and this system gets exactly one hex printer. */

#endif /* AXI_SIGN_H */
