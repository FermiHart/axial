/* axial — arena-per-invocation (W11). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * Memory doctrine (mirrors fuel, W10):
 *   - one arena per invocation; freed wholesale, never piecemeal —
 *     lifetime is structural; correct cleanup remains the caller's obligation;
 *   - a cap ALWAYS exists (default 1 MiB, --mem N). Exhaustion is a
 *     verdict (AXI-R009), never an OOM kill — GAIOLA fail-closed;
 *   - `used` is deterministic: same input, same byte count, and the
 *     golden seals it (--mem-report).
 */
#ifndef AXI_ARENA_H
#define AXI_ARENA_H
#include "axi_mem_account.h"
#include <stddef.h>
#include <stdint.h>

typedef struct axi_ablock {
    struct axi_ablock *next;
    size_t cap, used;
    /* AX30 source ABI: payload must start on a 16-byte boundary on the
     * supported malloc-compatible AMD64 host. Keep sizeof() accounting exact. */
    unsigned char alignment_pad[16u - ((sizeof(void *) + 2u * sizeof(size_t)) % 16u)];
    /* payload follows */
} axi_ablock;

typedef struct axi_arena {
    axi_ablock *head;
    size_t cap;      /* hard ceiling over all blocks */
    size_t used;     /* aligned bytes handed out — deterministic */
    axi_mem_account *account; /* optional; caller-owned and explicit */
} axi_arena;

void  axi_arena_init(axi_arena *a, size_t cap);
/* The account remains caller-owned and must outlive the arena. A NULL account
 * selects the same unaccounted path as axi_arena_init. */
void  axi_arena_init_accounted(axi_arena *a, size_t cap,
                               axi_mem_account *account);
void *axi_arena_alloc(axi_arena *a, size_t n);   /* zeroed; NULL = refusal */
void  axi_arena_free(axi_arena *a);

#endif
