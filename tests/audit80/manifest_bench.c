/* W78 matched benchmark: checked source -> contract AXS, with real quota. */
#include "axi_codegen.h"
#include "axi_hash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "manifest_fixture.h"

int main(int argc, char **argv)
{
    axi_compile_budget budget;
    axi_diags ds;
    axi_node *unit;
    char *input, *reference;
    size_t n = 0, capacity, text_len = 0, retained;
    uint8_t hash[32];
    char hex[65];
    unsigned cells, iterations, i;
    clock_t begin, end;
    struct timespec wall_begin, wall_end;
    int fixture = argc == 2 && !strcmp(argv[1], "--fixture");
    if (!fixture && argc != 3) return 2;
    cells = fixture ? 4 : (unsigned)strtoul(argv[1], NULL, 10);
    iterations = fixture ? 1 : (unsigned)strtoul(argv[2], NULL, 10);
    if (!cells || cells > 256 || !iterations || iterations > 100000) return 2;
    axi_compile_budget_init(&budget, AXI_COMPILE_DEFAULT_LIMIT);
    capacity = (size_t)cells * 512 + 1;
    input = fixture ? axi_compile_strdup(&budget, source)
                    : axi_compile_malloc(&budget, capacity);
    if (!input) return 1;
    if (fixture) n = strlen(input);
    for (i = 0; !fixture && i < cells; i++) {
        /* Reverse source order, positional params, two errors, option and
         * two laws. No effects, signing, runtime execution or file I/O. */
        int wrote = snprintf(input + n, capacity - n,
            "policy cell_%03u : fn(z: u64, a: bool) -> err.Zed | ok | u64 | err.Alpha\n"
            "  fuel 1000\n{\n  if a { ret err.Zed }\n  ret z\n}\n"
            "proof {\n  true\n  1 == 1\n}\n", cells - i - 1);
        if (wrote <= 0 || (size_t)wrote >= capacity - n) return 1;
        n += (size_t)wrote;
    }
    axi_diags_init(&ds);
    unit = axi_parse_unit_budget(input, n, "manifest-benchmark", &ds, &budget);
    if (!unit || ds.n) return 1;
    axi_type_check(unit, &ds);
    if (ds.n || !unit->contract_checked) return 1;
    reference = axi_codegen_contract_v1(unit, &text_len);
    if (!reference || !text_len) return 1;
    if (fixture) {
        if (fwrite(reference, 1, text_len, stdout) != text_len) return 1;
        if (!axi_compile_free(&budget, reference)) return 1;
        axi_ast_free(unit);
        if (!axi_compile_free(&budget, input) || budget.live || budget.fixed ||
                budget.allocations || budget.blocks || budget.failure != AXI_COMPILE_OK)
            return 1;
        return 0;
    }
    axi_sha256(reference, text_len, hash);
    axi_hash_hex(hash, hex);
    retained = budget.live;
    if (clock_gettime(CLOCK_MONOTONIC, &wall_begin)) return 1;
    begin = clock();
    for (i = 0; i < iterations; i++) {
        size_t len = 0;
        char *text = axi_codegen_contract_v1(unit, &len);
        if (!text || len != text_len || memcmp(text, reference, len)) return 1;
        if (!axi_compile_free(&budget, text) || budget.live != retained || budget.fixed)
            return 1;
    }
    end = clock();
    if (clock_gettime(CLOCK_MONOTONIC, &wall_end)) return 1;
    if (!axi_compile_free(&budget, reference)) return 1;
    axi_ast_free(unit);
    if (!axi_compile_free(&budget, input) || budget.live || budget.fixed ||
            budget.allocations || budget.blocks || budget.failure != AXI_COMPILE_OK)
        return 1;
    printf("{\"cells\":%u,\"iterations\":%u,\"cpu_seconds\":%.9f,"
           "\"wall_seconds\":%.9f,\"text_bytes\":%lu,\"text_sha256\":\"%s\","
           "\"invocation_peak\":%lu,\"live\":0,\"fixed\":0}\n",
           cells, iterations, (double)(end - begin) / CLOCKS_PER_SEC,
           (double)(wall_end.tv_sec - wall_begin.tv_sec) +
               (double)(wall_end.tv_nsec - wall_begin.tv_nsec) / 1e9,
           (unsigned long)text_len, hex, (unsigned long)budget.peak);
    return 0;
}
