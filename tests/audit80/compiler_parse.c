#include "axi_ast.h"
#include "axi_compile_budget.h"
#include <stdio.h>
#include <string.h>

static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { \
    fprintf(stderr, "compiler_parse:%d: %s\n", __LINE__, #c); return 1; \
} } while (0)

int main(void)
{
    static const char source[] =
        "cell answer : fn() -> u64\n  fuel 100\n  pure\n{\n"
        "  let kept = 99\n  if true { ret kept }\n  ret 42\n}\n";
    axi_compile_budget budget;
    axi_diags ds;
    axi_node *unit;
    char *copy;
    size_t peak, source_charge, nalloc;
    axi_compile_budget_init(&budget, AXI_COMPILE_DEFAULT_LIMIT);
    copy = axi_compile_strdup(&budget, source);
    CHECK(copy != NULL);
    source_charge = budget.live;
    axi_diags_init(&ds);
    unit = axi_parse_unit_budget(copy, strlen(copy), "test", &ds, &budget);
    CHECK(unit && !ds.n && unit->budget == &budget);
    peak = budget.peak;
    nalloc = budget.allocations;
    CHECK(nalloc > 10 && budget.live > source_charge);
    axi_ast_free(unit);
    CHECK(budget.allocations == 1 && budget.live == source_charge);
    CHECK(axi_compile_free(&budget, copy));
    CHECK(!budget.live && !budget.fixed);

    for (unsigned short_by = 0; short_by < 2; short_by++) {
        axi_compile_budget_init(&budget, peak - short_by);
        copy = axi_compile_strdup(&budget, source);
        CHECK(copy != NULL);
        axi_diags_init(&ds);
        unit = axi_parse_unit_budget(copy, strlen(copy), "test", &ds, &budget);
        if (short_by) {
            CHECK(unit == NULL && budget.failure == AXI_COMPILE_QUOTA);
            CHECK(ds.n == 1 && strcmp(ds.d[0].code, "AXI-M001") == 0);
            CHECK(budget.allocations == 1 && budget.live == source_charge);
        } else {
            CHECK(unit && !ds.n && budget.peak == peak && budget.allocations == nalloc);
            axi_ast_free(unit);
        }
        CHECK(axi_compile_free(&budget, copy));
        CHECK(!budget.live && !budget.fixed && !budget.blocks);
    }
    /* Syntax recovery owns nodes even before they join the published tree. */
    axi_compile_budget_init(&budget, 1024);
    axi_diags_init(&ds);
    unit = axi_parse_unit_budget("cell broken : fn( { if", strlen("cell broken : fn( { if"), "bad", &ds, &budget);
    if (unit) axi_ast_free(unit);
    CHECK(!budget.live && !budget.allocations && !budget.fixed);
    printf("compiler parser: %u checks PASS, source+AST peak=%zu allocations=%zu\n",
           checks, peak, nalloc);
    return 0;
}
