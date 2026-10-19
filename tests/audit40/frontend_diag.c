/* Audit40 W01: bounded malformed-source diagnostics. */
#include "axi.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(int argc, char **argv)
{
    size_t n = argc > 1 ? (size_t)strtoul(argv[1], NULL, 10) : 65536u;
    char *src = malloc(n + 1);
    axi_diags ds;
    axi_lexer lx;
    axi_token token;
    clock_t begin;
    assert(src && n >= AXI_DIAG_MAX && n < INT_MAX);
    memset(src, '@', n);
    src[n] = '\0';
    axi_diags_init(&ds);
    axi_lex_init(&lx, src, n, &ds);
    begin = clock();
    axi_lex_next(&lx, &token);
    printf("invalid_bytes=%lu cpu_seconds=%.6f\n", (unsigned long)n,
           (double)(clock() - begin) / CLOCKS_PER_SEC);
    assert(token.kind == T_EOF && lx.pos == n);
    assert(ds.n == AXI_DIAG_MAX && ds.dropped == (int)n - AXI_DIAG_MAX);
    for (int i = 0; i < ds.n; i++) {
        assert(strcmp(ds.d[i].code, "AXI-L001") == 0);
        assert(ds.d[i].off == (uint32_t)i && ds.d[i].col == (uint32_t)i + 1);
    }
    ds.dropped = INT_MAX;
    axi_diag_add_source(&ds, "AXI-L001", src, 0, 1, "full", "full");
    axi_diag_add(&ds, "AXI-L001", 1, 1, 1, "full", "full");
    assert(ds.dropped == INT_MAX);
    free(src);
    puts("frontend W01: PASS");
    return 0;
}
