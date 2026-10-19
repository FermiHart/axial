/* Bounded compiler ownership, nested backend and refusal atomicity. */
#include "axi_compile_budget.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { \
    fprintf(stderr, "compiler_budget:%d: %s\n", __LINE__, #c); return 1; \
} } while (0)

int main(int argc, char **argv)
{
    axi_compile_budget a, b;
    axi_mem_account backend;
    size_t h = axi_compile_header_bytes(), peak;
    unsigned char *p, *q;
    (void)argv;
    axi_compile_budget_init(&a, 4096);
    if (argc > 1) {
        CHECK(axi_compile_malloc(&a, 8) == NULL);
        CHECK(a.failure == AXI_COMPILE_HOST_OOM && !a.live && !a.allocations);
        puts("compiler budget host OOM PASS");
        return 0;
    }
    p = axi_compile_calloc(&a, 16, 1);
    CHECK(p != NULL && a.live == h + 16);
    for (unsigned i = 0; i < 16; i++) CHECK(p[i] == 0);
    memcpy(p, "invocation-data", 16);
    q = axi_compile_realloc(&a, p, 128);
    CHECK(q && memcmp(q, "invocation-data", 16) == 0);
    p = q;
    CHECK(a.live == h + 128 && a.allocations == 1);
    peak = a.peak;
    q = axi_compile_realloc(&a, p, 16);
    CHECK(q && a.live == h + 16 && a.peak == peak);
    p = q;
    CHECK(axi_compile_reserve(&a, 512));
    axi_compile_account_init(&backend, &a);
    q = axi_mem_alloc(&backend, 31);
    CHECK(q && a.live == h + 16 + 512 + h + axi_mem_header_bytes() + 31);
    CHECK(axi_mem_reserve(&backend, 1024));
    CHECK(a.fixed == 1536 && backend.fixed == 1024);
    CHECK(axi_mem_release(&backend, 1024));
    CHECK(axi_mem_free(&backend, q));
    CHECK(axi_compile_release(&a, 512));
    CHECK(axi_compile_free(&a, p));
    CHECK(!a.live && !a.fixed && !a.allocations && !a.blocks);

    /* Quota denial preserves the last live allocation and its contents. */
    axi_compile_budget_init(&a, h + 16);
    p = axi_compile_malloc(&a, 16);
    CHECK(p != NULL);
    memcpy(p, "invocation-data", 16);
    CHECK(axi_compile_realloc(&a, p, 17) == NULL);
    CHECK(a.failure == AXI_COMPILE_QUOTA && a.live == h + 16);
    CHECK(memcmp(p, "invocation-data", 16) == 0);
    CHECK(axi_compile_free(&a, p));
    CHECK(!a.live && a.failure == AXI_COMPILE_QUOTA);
    CHECK(axi_compile_malloc(&a, 1) == NULL); /* sticky refusal */

    /* Independent invocations cannot lend quota or reclaim each other's data. */
    axi_compile_budget_init(&a, 4096);
    axi_compile_budget_init(&b, 4096);
    p = (unsigned char *)axi_compile_strdup(&a, "owned-a");
    q = (unsigned char *)axi_compile_strdup(&b, "owned-b");
    CHECK(p && q && strcmp((char *)p, "owned-a") == 0);
    CHECK(!axi_compile_free(&b, p));
    CHECK(b.failure == AXI_COMPILE_OWNERSHIP && a.allocations == 1);
    CHECK(strcmp((char *)q, "owned-b") == 0);
    axi_compile_budget_destroy(&a);
    axi_compile_budget_destroy(&b);
    CHECK(!a.live && !b.live);

    axi_compile_budget_init(&a, SIZE_MAX);
    CHECK(axi_compile_calloc(&a, SIZE_MAX, 2) == NULL);
    CHECK(a.failure == AXI_COMPILE_OVERFLOW && a.live == 0);
    axi_compile_budget_init(&a, SIZE_MAX);
    CHECK(axi_compile_malloc(&a, SIZE_MAX) == NULL);
    CHECK(a.failure == AXI_COMPILE_OVERFLOW && a.live == 0);

    /* Backend fixed workspace and compiler heap compete for the SAME cap. */
    axi_compile_budget_init(&a, 1024);
    CHECK(axi_compile_reserve(&a, 1000));
    axi_compile_account_init(&backend, &a);
    CHECK(!axi_mem_reserve(&backend, 25));
    CHECK(a.failure == AXI_COMPILE_QUOTA && a.live == 1000 && !backend.live);
    CHECK(axi_compile_release(&a, 1000));
    CHECK(!a.live);
    printf("compiler budget: %u checks PASS\n", checks);
    return 0;
}
