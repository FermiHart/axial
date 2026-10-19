/* ADR-059 AXV2-35: trust-snapshot canon for the narrow local profile.
 *
 * Private C interface, fixture-only; no installed ABI promise, no
 * production runner, no Beyond wiring. Defines the exact bytes whose
 * digest becomes an epoch trust_snapshot_root for a SinguOS Genesis
 * v1 page: trust_root = SHA-256("SINGUOS-TRUST-v1" || 0x00 ||
 * page[0:1152]), where page[0:1152] is the genesis header (128) plus
 * the four nodes (4 x 256). Edges, events and reserved are volatile
 * and excluded; the generation is covered implicitly (header bytes
 * 32..39). The page must be exactly 4096 bytes; anything else
 * refuses. Pure: no clock, filesystem or effect.
 */
#ifndef AXI_TRUST_CANON_V1_H
#define AXI_TRUST_CANON_V1_H

#include <stddef.h>
#include <stdint.h>

#define AXI_TRUST_CANON_V1_PAGE_SIZE 4096u
#define AXI_TRUST_CANON_V1_COVERED_SIZE 1152u
#define AXI_TRUST_CANON_V1_OK 0
#define AXI_TRUST_CANON_V1_REFUSED (-1)

/* Returns OK with root written, REFUSED on NULL or short/long page. */
int axi_trust_canon_v1_root(const uint8_t page[4096], uint8_t root[32],
                            size_t page_len);

#endif
