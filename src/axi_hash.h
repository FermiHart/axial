/* axial — content addressing (W14). Bear Core. SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * One hash doctrine: the SAME SHA-256 that seals the Beyond boot chain
 * (toolchain/BearBasm/sha256_ni.h) addresses axial content. A second
 * hash primitive would be a second door /INV-199 spirit/.
 *
 * Address of a cell  = SHA-256 of its SEMANTIC canonical text (no trivia:
 *   comments do not change what executes, so they do not change the address).
 * Address of a unit  = SHA-256 of the full canonical text (provenance).
 * Address of a module= SHA-256 of the .axb bytes; the .axb embeds the hash
 *   of the exact .axs text it was assembled from (src binding).
 */
#ifndef AXI_HASH_H
#define AXI_HASH_H

#include <stdint.h>
#include <stddef.h>

void axi_sha256(const void *data, size_t len, uint8_t out[32]);
void axi_hash_hex(const uint8_t h[32], char out[65]);

/* AXI-INV-019: prove the primitive, do not assume it. 0 = all vectors pass. */
int  axi_hash_selftest(void);

#endif /* AXI_HASH_H */
