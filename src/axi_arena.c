/* axial — arena-per-invocation (W11). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 * See axi_arena.h for the doctrine.
 */
#include "axi_arena.h"
#include "axi_alloc.h"
#include <stdlib.h>
#include <string.h>

#define ABLOCK_MIN (64u * 1024u)
#define AALIGN     16u
typedef char axi_arena_header_alignment[(sizeof(axi_ablock) % AALIGN == 0) ? 1 : -1];

void axi_arena_init(axi_arena *a, size_t cap) {
    a->head = NULL; a->cap = cap; a->used = 0; a->account = NULL;
}

void axi_arena_init_accounted(axi_arena *a, size_t cap,
                              axi_mem_account *account) {
    axi_arena_init(a, cap);
    a->account = account;
}

void *axi_arena_alloc(axi_arena *a, size_t n) {
    size_t need;
    if (n > (size_t)-1 - (AALIGN - 1)) {
        if (a->account) (void)axi_mem_alloc(a->account, (size_t)-1);
        return NULL;
    }
    need = (n + (AALIGN - 1)) & ~(size_t)(AALIGN - 1);
    if (need == 0) need = AALIGN;
    if (a->used > a->cap || need > a->cap - a->used)
        return NULL;                                /* verdict, not a crash */
    axi_ablock *b = a->head;
    if (!b || b->used > b->cap || need > b->cap - b->used) {
        size_t bc = need > ABLOCK_MIN ? need : ABLOCK_MIN;
        size_t block_size;
        if (bc > a->cap) bc = a->cap;              /* never reserve past the cap */
        if (bc < need) return NULL;
        if (bc > (size_t)-1 - sizeof(axi_ablock)) {
            if (a->account) (void)axi_mem_alloc(a->account, (size_t)-1);
            return NULL;
        }
        block_size = sizeof(axi_ablock) + bc;
        axi_ablock *nb = a->account
            ? axi_mem_alloc(a->account, block_size)
            : axi_malloc(block_size);
        if (!nb) return NULL;
        nb->next = a->head; nb->cap = bc; nb->used = 0;
        a->head = nb;
        b = nb;
    }
    void *p = (uint8_t *)(b + 1) + b->used;
    b->used += need;
    a->used += need;
    memset(p, 0, need);
    return p;
}

void axi_arena_free(axi_arena *a) {
    while (a->head) {
        axi_ablock *b = a->head;
        axi_ablock *nx = b->next;
        if (a->account) {
            if (!axi_mem_free(a->account, b)) return;
        } else {
            free(b);
        }
        a->head = nx;
    }
    a->used = 0;
}
