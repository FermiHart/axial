/* Axial compiler invocation budget. SPDX-License-Identifier: LicenseRef-SPL-1.0 */
#include "axi_compile_budget.h"
#include "axi_alloc.h"
#include "axi.h"
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef union {
    long double ld;
    long long ll;
    void *object;
    void (*function)(void);
} compiler_alignment;

struct axi_compile_block {
    struct axi_compile_block *prev, *next;
    axi_compile_budget *owner;
    size_t size;
    compiler_alignment alignment;
};

void axi_compile_budget_init(axi_compile_budget *b, size_t limit)
{
    if (!b) return;
    memset(b, 0, sizeof *b);
    b->limit = limit;
}

size_t axi_compile_header_bytes(void) { return sizeof(struct axi_compile_block); }

void axi_compile_fail(axi_compile_budget *b, axi_compile_failure cause,
                       size_t request)
{
    if (b && b->failure == AXI_COMPILE_OK) {
        b->failure = cause;
        b->failed_request = request;
    }
    errno = ENOMEM;
}

const char *axi_compile_failure_code(const axi_compile_budget *b)
{
    if (!b) return "AXI-M002";
    switch (b->failure) {
    case AXI_COMPILE_QUOTA: return "AXI-M001";
    case AXI_COMPILE_HOST_OOM: return "AXI-M002";
    case AXI_COMPILE_OVERFLOW: return "AXI-M003";
    case AXI_COMPILE_OWNERSHIP: return "AXI-M004";
    default: return "AXI-M000";
    }
}

static int can_charge(axi_compile_budget *b, size_t n)
{
    if (b->failure != AXI_COMPILE_OK) return 0;
    if (b->live > b->limit || n > b->limit - b->live) {
        axi_compile_fail(b, AXI_COMPILE_QUOTA, n);
        return 0;
    }
    return 1;
}

static void charge(axi_compile_budget *b, size_t n)
{
    b->live += n;
    if (b->live > b->peak) b->peak = b->live;
}

int axi_compile_reserve(axi_compile_budget *b, size_t size)
{
    if (!b) return 1;
    if (!can_charge(b, size)) return 0;
    charge(b, size);
    b->fixed += size;
    return 1;
}

int axi_compile_release(axi_compile_budget *b, size_t size)
{
    if (!b) return 1;
    if (size > b->fixed || size > b->live) {
        axi_compile_fail(b, AXI_COMPILE_OWNERSHIP, size);
        return 0;
    }
    b->fixed -= size;
    b->live -= size;
    return 1;
}

void *axi_compile_malloc(axi_compile_budget *b, size_t size)
{
    struct axi_compile_block *h;
    size_t total;
    if (!b) return axi_malloc(size);
    if (size > SIZE_MAX - sizeof *h) {
        axi_compile_fail(b, AXI_COMPILE_OVERFLOW, size);
        return NULL;
    }
    total = sizeof *h + size;
    if (!can_charge(b, total)) return NULL;
    h = axi_malloc(total);
    if (!h) { axi_compile_fail(b, AXI_COMPILE_HOST_OOM, total); return NULL; }
    h->owner = b;
    h->size = size;
    h->prev = NULL;
    h->next = b->blocks;
    if (h->next) h->next->prev = h;
    b->blocks = h;
    b->allocations++;
    charge(b, total);
    return h + 1;
}

void *axi_compile_calloc(axi_compile_budget *b, size_t count, size_t size)
{
    void *p;
    if (!b) return axi_calloc(count, size);
    if (count && size > SIZE_MAX / count) {
        axi_compile_fail(b, AXI_COMPILE_OVERFLOW, SIZE_MAX);
        return NULL;
    }
    p = axi_compile_malloc(b, count * size);
    if (p) memset(p, 0, count * size);
    return p;
}

int axi_compile_free(axi_compile_budget *b, void *ptr)
{
    struct axi_compile_block *h;
    size_t charged;
    if (!b) { free(ptr); return 1; }
    if (!ptr) return 1;
    h = (struct axi_compile_block *)ptr - 1;
    if (h->owner != b || h->size > SIZE_MAX - sizeof *h) {
        axi_compile_fail(b, AXI_COMPILE_OWNERSHIP, 0);
        return 0;
    }
    charged = h->size + sizeof *h;
    if (charged > b->live || !b->allocations) {
        axi_compile_fail(b, AXI_COMPILE_OWNERSHIP, charged);
        return 0;
    }
    if (h->prev) h->prev->next = h->next;
    else b->blocks = h->next;
    if (h->next) h->next->prev = h->prev;
    b->live -= charged;
    b->allocations--;
    free(h);
    return 1;
}

void *axi_compile_realloc(axi_compile_budget *b, void *ptr, size_t size)
{
    struct axi_compile_block *h, *p, *prev, *next;
    size_t old, total;
    if (!b) return axi_realloc(ptr, size);
    if (!ptr) return axi_compile_malloc(b, size);
    h = (struct axi_compile_block *)ptr - 1;
    if (h->owner != b) {
        axi_compile_fail(b, AXI_COMPILE_OWNERSHIP, 0); return NULL;
    }
    if (size > SIZE_MAX - sizeof *h) {
        axi_compile_fail(b, AXI_COMPILE_OVERFLOW, size); return NULL;
    }
    old = h->size;
    total = sizeof *h + size;
    if (!can_charge(b, size > old ? size - old : 0)) return NULL;
    prev = h->prev; next = h->next;
    p = axi_realloc(h, total);
    if (!p) { axi_compile_fail(b, AXI_COMPILE_HOST_OOM, total); return NULL; }
    if (prev) prev->next = p;
    else b->blocks = p;
    if (next) next->prev = p;
    p->prev = prev; p->next = next; p->owner = b; p->size = size;
    if (size >= old) charge(b, size - old);
    else b->live -= old - size;
    return p + 1;
}

char *axi_compile_strdup(axi_compile_budget *b, const char *s)
{
    size_t n;
    char *p;
    if (!b) return axi_strdup(s);
    if (!s) return NULL;
    n = strlen(s);
    if (n == SIZE_MAX) { axi_compile_fail(b, AXI_COMPILE_OVERFLOW, n); return NULL; }
    p = axi_compile_malloc(b, n + 1);
    if (p) memcpy(p, s, n + 1);
    return p;
}

void axi_compile_budget_destroy(axi_compile_budget *b)
{
    if (!b) return;
    while (b->blocks) (void)axi_compile_free(b, b->blocks + 1);
    (void)axi_compile_release(b, b->fixed);
}

static void *bridge_alloc(void *ctx, size_t size)
{ return axi_compile_malloc(ctx, size); }
static void *bridge_realloc(void *ctx, void *ptr, size_t size)
{ return axi_compile_realloc(ctx, ptr, size); }
static void bridge_free(void *ctx, void *ptr)
{ (void)axi_compile_free(ctx, ptr); }
static int bridge_reserve(void *ctx, size_t size)
{ return axi_compile_reserve(ctx, size); }
static int bridge_release(void *ctx, size_t size)
{ return axi_compile_release(ctx, size); }

void axi_compile_account_init(axi_mem_account *account, axi_compile_budget *b)
{
    axi_mem_host_allocator host;
    if (!b) { axi_mem_account_init(account, SIZE_MAX); return; }
    host.context = b; host.alloc = bridge_alloc;
    host.realloc = bridge_realloc; host.free = bridge_free;
    (void)axi_mem_account_init_with_host(account, SIZE_MAX, &host);
    account->reservation_context = b;
    account->reserve_external = bridge_reserve;
    account->release_external = bridge_release;
}

char *axi_compile_str_unescape(axi_compile_budget *b, const char *lexeme,
                                size_t len, uint32_t *outlen)
{
    uint32_t n;
    char *p;
    if (!b) return axi_str_unescape(lexeme, len, outlen);
    if (axi_str_decoded_length(lexeme, len, &n) != 0) return NULL;
    p = axi_compile_malloc(b, (size_t)n + 1);
    if (!p) return NULL;
    if (axi_str_decode_into(lexeme, len, p, (size_t)n + 1, &n) != 0) {
        (void)axi_compile_free(b, p);
        return NULL;
    }
    if (outlen) *outlen = n;
    return p;
}
