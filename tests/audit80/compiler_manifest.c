/* W78: one projection, unchanged manifest wire bytes, bounded ownership. */
#include "axi_alloc.h"
#include "axi_codegen.h"
#include "axi_contract.h"
#include "axi_iface.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { \
    fprintf(stderr, "compiler_manifest:%d: %s\n", __LINE__, #c); return 1; \
} } while (0)

#include "manifest_fixture.h"

static int all_zero(const void *p, size_t n)
{
    const unsigned char *b = p;
    size_t i;
    for (i = 0; i < n; i++) if (b[i]) return 0;
    return 1;
}

static int projection_checks(int budgeted, int phase)
{
    axi_compile_budget budget, strings;
    axi_compile_budget *owner = budgeted ? &budget : NULL;
    axi_mem_account account;
    axi_diags ds;
    axi_node *unit;
    char *src;
    size_t retained;
    axi_arena arena, reference;
    axb_manifest output[4], old;
    axb_cell cells[4];
    axb_mod body = {0};
    static const char *const names[] = {"alpha_more", "zulu", "alpha", "caps"};
    unsigned i;
    int rc;
    axi_compile_budget_init(&budget, AXI_COMPILE_DEFAULT_LIMIT);
    axi_compile_budget_init(&strings, AXI_COMPILE_DEFAULT_LIMIT);
    axi_compile_account_init(&account, &strings);
    src = axi_compile_strdup(owner, source);
    CHECK(src != NULL);
    axi_diags_init(&ds);
    unit = axi_parse_unit_budget(src, strlen(src), "manifest", &ds, owner);
    CHECK(unit && !ds.n);
    axi_type_check(unit, &ds);
    CHECK(!ds.n && unit->contract_checked);
    retained = budget.live;
    memset(cells, 0, sizeof cells);
    for (i = 0; i < 4; i++) cells[i].name = (char *)names[i];
    body.cells = cells;
    body.n = 4;
    axi_arena_init_accounted(&arena, phase == 2 ? 96 : 1024 * 1024, &account);
    axi_arena_init(&reference, 1024 * 1024);
    if (phase == 1) cells[2].name = "alpha_suffix";
    if (phase == 3) budget.limit = retained;
    if (phase == 4) strings.limit = 1;
    if (phase == 5) unit->contract_checked = 0;
    memset(output, 0xa5, sizeof output);
    rc = axi_iface_manifests_v1(unit, &body, output, &arena);
    CHECK(budget.live == retained && !budget.fixed);
    if (phase) {
        CHECK(rc != 0 && all_zero(output, sizeof output));
        CHECK(budget.failure == (phase == 3 ? AXI_COMPILE_QUOTA : AXI_COMPILE_OK));
        CHECK(strings.failure == (phase == 4 ? AXI_COMPILE_QUOTA : AXI_COMPILE_OK));
        if (phase == 1 || phase == 2) CHECK(arena.used > 0);
    } else {
        unsigned char a[AXB_MANIFEST_MAX_BYTES], b[AXB_MANIFEST_MAX_BYTES];
        CHECK(rc == 0 && arena.used > 0 && strings.live > 0);
        for (i = 0; i < 4; i++) {
            size_t na = 0, nb = 0;
            uint8_t hash[32];
            /* The length-delimited single-cell API never needs a NUL. */
            char name[64];
            size_t len = strlen(names[i]);
            memset(name, 'x', sizeof name);
            memcpy(name, names[i], len);
            CHECK(axi_iface_manifest_v1(unit, name, len, &old, &reference) == 0);
            CHECK(axb_manifest_v1_encode(&old, a, sizeof a, &na) == 0);
            CHECK(axb_manifest_v1_encode(&output[i], b, sizeof b, &nb) == 0);
            CHECK(na == nb && !memcmp(a, b, na));
            CHECK(all_zero(output[i].body_hash, sizeof output[i].body_hash));
            CHECK(axi_manifest_iface_hash_v1(names[i], &output[i], hash) == 0);
            CHECK(!memcmp(hash, output[i].iface_hash, sizeof hash));
        }
        CHECK(output[1].nparams == 2 &&
              !strcmp(output[1].params[0].name.p, "second") &&
              !strcmp(output[1].params[1].name.p, "first"));
        CHECK(output[1].nreturns == 2 && output[1].returns[0].tag == AXB_MT_U64 &&
              output[1].returns[1].tag == AXB_MT_OK);
        CHECK(output[1].nerrors == 2 && !strcmp(output[1].errors[0].p, "Alpha") &&
              !strcmp(output[1].errors[1].p, "Zed"));
        CHECK(output[2].nlaws == 4 && output[2].flags == AXB_MANIFEST_FLAG_POLICY);
        CHECK(output[3].ncaps == 2 && !strcmp(output[3].caps[0].p, "fs.Read") &&
              !strcmp(output[3].caps[1].p, "io.Write"));
        memset(&old, 0xa5, sizeof old);
        CHECK(axi_iface_manifest_v1(unit, "alph", 4, &old, &reference) != 0 &&
              all_zero(&old, sizeof old));
        CHECK(axi_iface_manifest_v1(unit, NULL, 0, &old, &reference) != 0);
    }
    axi_arena_free(&reference);
    axi_arena_free(&arena);
    CHECK(!account.live && !account.active_count && !account.fixed);
    CHECK(!strings.live && !strings.allocations && !strings.fixed && !strings.blocks);
    CHECK(budget.live == retained && !budget.fixed);
    axi_ast_free(unit);
    CHECK(axi_compile_free(owner, src));
    CHECK(!budget.live && !budget.allocations && !budget.fixed && !budget.blocks);
    return 0;
}

static int codegen_failpoint(void)
{
    axi_compile_budget b;
    axi_diags ds;
    axi_node *unit;
    char *src, *text;
    size_t n = 99, live;
    axi_alloc_failpoint_suspend();
    axi_compile_budget_init(&b, AXI_COMPILE_DEFAULT_LIMIT);
    src = axi_compile_strdup(&b, source);
    CHECK(src != NULL);
    axi_diags_init(&ds);
    unit = axi_parse_unit_budget(src, strlen(src), "manifest", &ds, &b);
    CHECK(unit && !ds.n);
    axi_type_check(unit, &ds);
    CHECK(!ds.n && unit->contract_checked);
    live = b.live;
    axi_alloc_failpoint_resume();
    text = axi_codegen_contract_v1(unit, &n);
    axi_alloc_failpoint_suspend();
    if (text) CHECK(n > 0 && b.failure == AXI_COMPILE_OK);
    else CHECK(!n && b.failure == AXI_COMPILE_HOST_OOM);
    CHECK(axi_compile_free(&b, text));
    CHECK(b.live == live && !b.fixed);
    axi_ast_free(unit);
    CHECK(axi_compile_free(&b, src));
    CHECK(!b.live && !b.allocations && !b.fixed && !b.blocks);
    printf("{\"failure\":\"%s\",\"checks\":%u,\"live\":%lu,\"fixed\":%lu}\n",
           axi_compile_failure_code(&b), checks, (unsigned long)b.live,
           (unsigned long)b.fixed);
    return 0;
}

int main(int argc, char **argv)
{
    int phase;
    if (argc == 2 && !strcmp(argv[1], "--failpoint")) return codegen_failpoint();
    CHECK(argc == 1);
    CHECK(projection_checks(0, 0) == 0);
    for (phase = 0; phase < 6; phase++) CHECK(projection_checks(1, phase) == 0);
    CHECK(codegen_failpoint() == 0);
    printf("compiler manifests: %u checks PASS\n", checks);
    return 0;
}
