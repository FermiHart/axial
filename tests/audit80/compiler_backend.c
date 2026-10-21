/* Source/assembler/signature ownership shares one caller-owned quota. */
#include "axi_codegen.h"
#include "axi_contract.h"
#include "axi_sign.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { \
    fprintf(stderr, "compiler_backend:%d: %s\n", __LINE__, #c); return 1; \
} } while (0)

int main(void)
{
    static const char source[] =
        "cell text : fn() -> str\n  fuel 100\n  pure\n{\n  ret \"a\\n\\0\"\n}\n\n"
        "cell fail : fn() -> u64 | err.No\n  fuel 100\n  pure\n{\n  ret err.No\n}\n";
    const unsigned char seed[32] = {1}; /* disposable deterministic test key */
    char target[] = "/tmp/axi80-budget-publish-XXXXXX";
    int fd = mkstemp(target);
    CHECK(fd >= 0 && write(fd, "before", 6) == 6 && close(fd) == 0);
    for (int phase = 0; phase < 5; phase++) {
        axi_compile_budget b;
        axi_mem_account account;
        axi_diags ds;
        axi_node *unit;
        axb_contract_mod model = {0}, legacy = {0}, decoded = {0};
        axi_sig sig;
        char *src, *axs = NULL;
        unsigned char *signed_bytes = NULL, *reference = NULL;
        size_t n = 99, live, retained, size = 0, reference_size = 0;
        axi_compile_budget_init(&b, AXI_COMPILE_DEFAULT_LIMIT);
        axi_compile_account_init(&account, &b);
        src = axi_compile_strdup(&b, source);
        CHECK(src != NULL);
        axi_diags_init(&ds);
        unit = axi_parse_unit_budget(src, strlen(src), "test", &ds, &b);
        CHECK(unit && !ds.n);
        axi_type_check(unit, &ds);
        CHECK(!ds.n && unit->contract_checked);
        live = b.live;
        if (phase == 1) b.limit = live + 200;
        axs = axi_codegen_contract_v1(unit, &n);
        if (phase == 1) {
            CHECK(!axs && !n && b.failure == AXI_COMPILE_QUOTA && b.live == live);
            goto cleanup;
        }
        CHECK(axs && n && strstr(axs, "contract 1"));
        retained = b.live;
        if (phase == 2) b.limit = retained + 200;
        if (phase == 2) {
            CHECK(axb_contract_v1_parse_accounted(axs, n, &model, &account) != 0);
            CHECK(b.failure == AXI_COMPILE_QUOTA && b.live == retained);
            goto cleanup;
        }
        CHECK(axb_contract_v1_parse_accounted(axs, n, &model, &account) == 0);
        CHECK(model.body.builder_account == &account && !account.fixed);
        retained = b.live;
        if (phase >= 3) b.limit = retained + 200;
        if (phase == 3) {
            signed_bytes = (unsigned char *)1;
            size = 17;
            CHECK(axb_contract_v7_encode_signed_accounted(&model, seed,
                  &signed_bytes, &size, &account) != 0);
            CHECK(signed_bytes == (unsigned char *)1 && size == 17);
            CHECK(b.failure == AXI_COMPILE_QUOTA && b.live == retained && !account.fixed);
            goto cleanup;
        }
        if (phase == 4) {
            char saved[7] = {0};
            FILE *f;
            CHECK(axb_contract_v7_write_signed_accounted(&model, seed, target, &account) != 0);
            CHECK(b.failure == AXI_COMPILE_QUOTA && b.live == retained);
            f = fopen(target, "rb");
            CHECK(f && fread(saved, 1, 7, f) == 6 && !strcmp(saved, "before"));
            CHECK(fclose(f) == 0);
            goto cleanup;
        }
        CHECK(axb_contract_v7_encode_signed_accounted(&model, seed,
              &signed_bytes, &size, &account) == 0);
        CHECK(axb_contract_v1_parse(axs, n, &legacy) == 0);
        CHECK(axb_contract_v7_encode_signed(&legacy, seed, &reference, &reference_size) == 0);
        CHECK(size == reference_size && !memcmp(signed_bytes, reference, size));
        CHECK(axi_sig_read(signed_bytes + size - AXBS_TRAILER, &sig) == 0);
        CHECK(axb_contract_v7_decode_trusted_accounted(&decoded, signed_bytes,
              size, sig.pk, &account) == 0);
        CHECK(decoded.nmanifest == 2 && decoded.body.builder_account == NULL);
        axb_contract_mod_free(&decoded);
        axb_contract_mod_free(&legacy);
        free(reference);
        CHECK(axi_mem_free(&account, signed_bytes));
        CHECK(b.live == retained && !account.fixed);
cleanup:
        axb_contract_mod_free(&model);
        CHECK(!account.live && !account.active_count && !account.fixed);
        CHECK(axi_compile_free(&b, axs));
        CHECK(b.live == live && !b.fixed);
        axi_ast_free(unit);
        CHECK(axi_compile_free(&b, src));
        CHECK(!b.live && !b.allocations && !b.blocks);
    }
    CHECK(unlink(target) == 0);
    printf("compiler backend: %u checks PASS\n", checks);
    return 0;
}
