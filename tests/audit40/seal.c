/* Independent proof-record mutations and optional multi-law benchmark. */
#include "axi_contract.h"
#include "axi_mem_account.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr, "seal:%d: %s\n", __LINE__, #x); return 1; \
} } while (0)

int main(int argc, char **argv)
{
    axb_contract_mod model;
    axi_mem_account account;
    char source[32768];
    unsigned i, laws = 64;
    size_t n = 0;
    unsigned long iterations = 0;
    if (argc == 4 && strcmp(argv[1], "--bench") == 0) {
        iterations = strtoul(argv[2], NULL, 10);
        laws = (unsigned)strtoul(argv[3], NULL, 10);
        if (iterations == 0 || iterations > 100000 || laws == 0 || laws > 64) return 2;
    } else if (argc != 1) return 2;
    memset(&model, 0, sizeof model);
    for (i = 0; i < laws; i++) {
        int wrote = snprintf(source + n, sizeof source - n,
            "cell law_%03u nregs=1\n  contract 1\n    ret bool\n"
            "    fuel 1000\n    pure\n  endcontract\n"
            "  k0 u64 1\n  ldk r0 k0\n  eq r0 r0 r0\n  ret r0\nend\n", i);
        CHECK(wrote > 0 && (size_t)wrote < sizeof source - n);
        n += (size_t)wrote;
    }
    CHECK(axb_contract_v1_parse(source, n, &model) == 0);
    model.seal.present = 1;
    model.seal.version = AXPC_VERSION;
    model.seal.maturity = AXPC_MATURITY_CHECKED;
    model.seal.law_count = laws;
    model.seal.aggregate_budget = (uint64_t)laws * 1000;
    model.seal.aggregate_fuel_used = (uint64_t)laws * 3;
    axb_checker_protocol_id(model.seal.checker_protocol_id);
    axb_checker_semantics_root(model.seal.checker_semantics_root);
    for (i = 0; i < laws; i++) {
        axb_seal_law *law = &model.seal.laws[i];
        law->cell_index = i;
        law->name.p = model.body.cells[i].name;
        law->name.len = (uint32_t)strlen(law->name.p);
        memcpy(law->iface_hash, model.manifest[i].iface_hash, 32);
        memcpy(law->body_hash, model.manifest[i].body_hash, 32);
        law->budget = 1000;
        law->fuel_used = 3; /* three unit-cost opcodes, no calls/effects */
        law->result_kind = AXPC_RESULT_BOOL;
        law->verdict = AXPC_VERDICT_TRUE;
    }
    CHECK(axb_contract_seal_subject_root(&model, model.seal.subject_root) == 0);
    CHECK(axb_contract_seal_verify(&model, 1) == 0);
    axi_mem_account_init(&account, 16u * 1024u * 1024u);
    CHECK(axb_contract_seal_verify_accounted(&model, 1, &account) == 0);
    CHECK(account.live == 0 && account.active_count == 0 && account.peak > 0);
    if (iterations) {
        struct timespec begin, end;
        unsigned long k;
        CHECK(clock_gettime(CLOCK_MONOTONIC, &begin) == 0);
        for (k = 0; k < iterations; k++)
            if (axb_contract_seal_verify(&model, 1) != 0) return 1;
        CHECK(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
        printf("{\"case\":\"seal_verify\",\"laws\":%u,\"iterations\":%lu,"
               "\"seconds\":%.9f,\"fuel_per_verification\":%llu}\n", laws, iterations,
               (double)(end.tv_sec - begin.tv_sec) + (double)(end.tv_nsec - begin.tv_nsec)/1e9,
               (unsigned long long)model.seal.aggregate_fuel_used);
    } else {
        model.seal.laws[0].fuel_used++;
        model.seal.aggregate_fuel_used++;
        CHECK(axb_contract_seal_verify(&model, 0) == 0);
        CHECK(axb_contract_seal_verify(&model, 1) != 0); /* execution matters */
        model.seal.laws[0].fuel_used--;
        model.seal.aggregate_fuel_used--;
        model.seal.laws[0].verdict = 0;
        CHECK(axb_contract_seal_verify(&model, 1) != 0);
        model.seal.laws[0].verdict = AXPC_VERDICT_TRUE;
        model.seal.laws[0].name.len--;
        CHECK(axb_contract_seal_verify(&model, 1) != 0);
        model.seal.laws[0].name.len++;
        model.seal.subject_root[0] ^= 1;
        CHECK(axb_contract_seal_verify(&model, 1) != 0);
        model.seal.subject_root[0] ^= 1;
        model.seal.checker_semantics_root[0] ^= 1;
        CHECK(axb_contract_seal_verify(&model, 1) != 0);
        model.seal.checker_semantics_root[0] ^= 1;
        axi_mem_account_init(&account, 1);
        CHECK(axb_contract_seal_verify_accounted(&model, 1, &account) != 0);
        CHECK(account.live == 0 && account.active_count == 0
              && account.failure == AXI_MEM_QUOTA_EXCEEDED);
        printf("audit seal: %u checks PASS\n", checks);
    }
    axb_contract_mod_free(&model);
    return 0;
}
