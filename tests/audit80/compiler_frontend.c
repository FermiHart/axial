#include "axi_ast.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { \
    fprintf(stderr, "compiler_frontend:%d: %s\n", __LINE__, #c); return 1; \
} } while (0)

int main(void)
{
    static const char source[] =
        "cell one : fn() -> u64\n  fuel 100\n  pure\n{\n  ret 1\n}\n\n"
        "cell two : fn() -> u64\n  fuel 100\n  pure\n{\n  ret one()\n}\n";
    axi_compile_budget b;
    axi_diags ds;
    axi_node *unit;
    char *src, *text;
    size_t tree_live, peak;
    for (int phase = 0; phase < 3; phase++) {
        axi_compile_budget_init(&b, AXI_COMPILE_DEFAULT_LIMIT);
        src = axi_compile_strdup(&b, source);
        CHECK(src != NULL);
        axi_diags_init(&ds);
        unit = axi_parse_unit_budget(src, strlen(src), "test", &ds, &b);
        CHECK(unit && !ds.n);
        tree_live = b.live;
        if (phase == 1) b.limit = tree_live + 512;
        text = axi_canon_render(src, strlen(src), unit);
        if (phase == 1) {
            CHECK(!text && b.failure == AXI_COMPILE_QUOTA && b.live == tree_live);
        } else {
            CHECK(text && strcmp(text, source) == 0);
            CHECK(axi_compile_free(&b, text) && b.live == tree_live);
            if (phase == 2) b.limit = tree_live + 512;
            axi_type_check(unit, &ds);
            if (phase == 2) {
                CHECK(ds.n && !unit->contract_checked && b.failure == AXI_COMPILE_QUOTA);
            } else {
                CHECK(!ds.n && unit->contract_checked && b.failure == AXI_COMPILE_OK);
            }
            CHECK(b.live == tree_live);
        }
        peak = b.peak;
        axi_ast_free(unit);
        CHECK(axi_compile_free(&b, src));
        CHECK(!b.live && !b.fixed && !b.allocations);
        CHECK(b.peak == peak);
    }
    /* The old library front doors also return NULL, instead of exit(2), when
     * a budgeted expression/type cannot be rendered. The host continues. */
    axi_compile_budget_init(&b, AXI_COMPILE_DEFAULT_LIMIT);
    axi_diags_init(&ds);
    unit = axi_parse_unit_budget(source, sizeof source - 1, "test", &ds, &b);
    CHECK(unit != NULL);
    b.limit = b.live;
    text = axi_canon_type_str(unit->list->a->b->list);
    CHECK(text == NULL && b.failure == AXI_COMPILE_QUOTA);
    CHECK(axi_canon_expr_str(unit->list->b->list->a) == NULL);
    axi_ast_free(unit);
    CHECK(!b.live);
    puts("compiler frontend: recoverable format/type refusals PASS");
    printf("compiler frontend: %u checks PASS\n", checks);
    return 0;
}
