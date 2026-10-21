/* Numeric workspace must participate in each compiler invocation's quota.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0 */
#include "axi_ast.h"
#include "axi_numeric.h"
#include <stdio.h>
#include <string.h>

static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { \
    fprintf(stderr, "compiler_numeric:%d: %s\n", __LINE__, #c); return 1; \
} } while (0)

static const char source[] =
    "cell decimal : fn() -> f64\n  fuel 100\n  pure\n{\n  ret 0.3\n}\n";

static int parse_workspace(void)
{
    axi_compile_budget b;
    axi_diags ds;
    axi_node *unit;
    size_t peak;
    axi_compile_budget_init(&b, AXI_COMPILE_DEFAULT_LIMIT);
    axi_diags_init(&ds);
    unit = axi_parse_unit_budget(source, sizeof source - 1, "decimal", &ds, &b);
    CHECK(unit && !ds.n);
    CHECK(b.peak >= b.live + AXI_NUMERIC_SCRATCH_BYTES);
    peak = b.peak;
    axi_ast_free(unit);
    CHECK(!b.live && !b.fixed && !b.allocations && !b.blocks);
    for (unsigned short_by = 0; short_by < 2; short_by++) {
        axi_compile_budget_init(&b, peak - short_by);
        axi_diags_init(&ds);
        unit = axi_parse_unit_budget(source, sizeof source - 1, "decimal", &ds, &b);
        if (short_by) {
            CHECK(!unit && b.failure == AXI_COMPILE_QUOTA);
            CHECK(ds.n == 1 && !strcmp(ds.d[0].code, "AXI-M001"));
        } else {
            CHECK(unit && !ds.n && b.peak == peak);
            axi_ast_free(unit);
        }
        CHECK(!b.live && !b.fixed && !b.allocations && !b.blocks);
    }
    return 0;
}

static int expression_workspace(void)
{
    axi_compile_budget b;
    axi_node literal;
    char *text;
    size_t peak;
    uint64_t bits = UINT64_C(0x3fd3333333333333);
    memset(&literal, 0, sizeof literal);
    literal.kind = N_FLOAT;
    literal.budget = &b;
    memcpy(&literal.fval, &bits, sizeof bits);
    axi_compile_budget_init(&b, AXI_COMPILE_DEFAULT_LIMIT);
    text = axi_canon_expr_str_fallible(&literal);
    CHECK(text && !strcmp(text, "0.3"));
    CHECK(b.peak >= b.live + AXI_NUMERIC_SCRATCH_BYTES && !b.fixed);
    peak = b.peak;
    CHECK(axi_compile_free(&b, text));
    CHECK(!b.live && !b.fixed && !b.allocations && !b.blocks);
    for (unsigned short_by = 0; short_by < 2; short_by++) {
        axi_compile_budget_init(&b, peak - short_by);
        text = axi_canon_expr_str_fallible(&literal);
        if (short_by) CHECK(!text && b.failure == AXI_COMPILE_QUOTA);
        else {
            CHECK(text && !strcmp(text, "0.3") && b.peak == peak);
            CHECK(axi_compile_free(&b, text));
        }
        CHECK(!b.live && !b.fixed && !b.allocations && !b.blocks);
    }
    /* A semantic formatter refusal must release its reservation too. */
    bits = UINT64_C(0x7ff0000000000000);
    memcpy(&literal.fval, &bits, sizeof bits);
    axi_compile_budget_init(&b, AXI_COMPILE_DEFAULT_LIMIT);
    CHECK(axi_canon_expr_str_fallible(&literal) == NULL);
    CHECK(b.failure == AXI_COMPILE_OK);
    CHECK(!b.live && !b.fixed && !b.allocations && !b.blocks);
    return 0;
}

static int canonical_workspace(void)
{
    axi_compile_budget b;
    axi_diags ds;
    axi_node *unit;
    char *text;
    size_t peak = 0, tree_live;
    for (unsigned pass = 0; pass < 3; pass++) {
        axi_compile_budget_init(&b, AXI_COMPILE_DEFAULT_LIMIT);
        axi_diags_init(&ds);
        unit = axi_parse_unit_budget(source, sizeof source - 1, "decimal", &ds, &b);
        CHECK(unit && !ds.n);
        tree_live = b.live;
        if (pass) b.limit = peak - (pass == 2);
        text = axi_canon_render(source, sizeof source - 1, unit);
        if (pass == 2) CHECK(!text && b.failure == AXI_COMPILE_QUOTA);
        else {
            CHECK(text && !strcmp(text, source));
            CHECK(b.peak >= tree_live + AXI_NUMERIC_SCRATCH_BYTES
                  + sizeof(axi_diags) + sizeof(axi_lexer) + sizeof(axi_token));
            if (!pass) peak = b.peak;
            else CHECK(b.peak == peak);
            CHECK(axi_compile_free(&b, text));
        }
        CHECK(b.live == tree_live && !b.fixed);
        axi_ast_free(unit);
        CHECK(!b.live && !b.fixed && !b.allocations && !b.blocks);
    }
    return 0;
}

int main(void)
{
    CHECK(parse_workspace() == 0);
    CHECK(expression_workspace() == 0);
    CHECK(canonical_workspace() == 0);
    printf("compiler numeric workspace: %u checks PASS, scratch=%zu bytes\n",
           checks, (size_t)AXI_NUMERIC_SCRATCH_BYTES);
    return 0;
}
