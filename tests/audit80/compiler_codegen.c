#include "axi_codegen.h"
#include "axi_iface.h"
#include <stdio.h>
#include <string.h>

static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { \
    fprintf(stderr, "compiler_codegen:%d: %s\n", __LINE__, #c); return 1; \
} } while (0)

int main(void)
{
    static const char source[] =
        "cell text : fn() -> str\n  fuel 100\n  pure\n{\n  ret \"a\\n\\0\"\n}\n\n"
        "cell fail : fn() -> u64 | err.No\n  fuel 100\n  pure\n{\n  ret err.No\n}\n";
    axi_compile_budget b;
    axi_diags ds;
    axi_node *unit;
    char *src, *text;
    size_t live, n = 99;
    for (int phase = 0; phase < 4; phase++) {
        axi_compile_budget_init(&b, AXI_COMPILE_DEFAULT_LIMIT);
        src = axi_compile_strdup(&b, source);
        CHECK(src != NULL);
        axi_diags_init(&ds);
        unit = axi_parse_unit_budget(src, strlen(src), "test", &ds, &b);
        CHECK(unit && !ds.n);
        axi_type_check(unit, &ds);
        CHECK(!ds.n && unit->contract_checked);
        live = b.live;
        if (phase == 1) b.limit = live + 200;
        text = axi_codegen(unit, &n);
        if (phase == 1) CHECK(!text && n == 0 && b.failure == AXI_COMPILE_QUOTA);
        else {
            CHECK(text && n && strstr(text, "err \"No\"") && strstr(text, "\\n\\0"));
            CHECK(axi_compile_free(&b, text) && b.live == live);
            if (phase >= 2) b.limit = live + 200;
            text = phase == 3 ? axi_iface_json(unit) : axi_iface_render(unit);
            if (phase >= 2) CHECK(!text && b.failure == AXI_COMPILE_QUOTA);
            else {
                CHECK(text && strstr(text, "iface-hash"));
                CHECK(axi_compile_free(&b, text));
            }
        }
        CHECK(b.live == live && !b.fixed);
        axi_ast_free(unit);
        CHECK(axi_compile_free(&b, src));
        CHECK(!b.live && !b.allocations && !b.blocks);
    }
    printf("compiler codegen/iface: %u checks PASS\n", checks);
    return 0;
}
