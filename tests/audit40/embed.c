/* Public frozen-v1 integration and optional warm-context performance probe. */
#include <axial/axi_embed_v1.h>
#include "axi_contract.h"
#include "axi_sign.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr, "embed:%d: %s\n", __LINE__, #x); return 1; \
} } while (0)

static double seconds(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
    char source[65536], name[32];
    axb_contract_mod model;
    axi_embed_v1_context *context = NULL;
    axi_embed_v1_context_options options = {0};
    axi_embed_v1_eval_request request = {0};
    axi_embed_v1_outcome outcome = {0};
    uint8_t seed[32] = {0}, *module = NULL;
    axi_sig identity;
    size_t n = 0, module_len = 0;
    unsigned i, cells = 256;
    unsigned long iterations = 0;
    if (argc == 4 && strcmp(argv[1], "--bench") == 0) {
        iterations = strtoul(argv[2], NULL, 10);
        cells = (unsigned)strtoul(argv[3], NULL, 10);
        if (iterations == 0 || iterations > 10000000 || cells == 0 || cells > 256) return 2;
    } else if (argc != 1) return 2;
    memset(&model, 0, sizeof model);
    for (i = 0; i < cells; i++) {
        int wrote = snprintf(source + n, sizeof source - n,
            "cell cell%03u nregs=1\n  contract 1\n    ret u64\n"
            "    fuel 10\n    pure\n  endcontract\n"
            "  k0 u64 %u\n  ldk r0 k0\n  ret r0\nend\n", cells - 1 - i, i);
        CHECK(wrote > 0 && (size_t)wrote < sizeof source - n);
        n += (size_t)wrote;
    }
    CHECK(axb_contract_v1_parse(source, n, &model) == 0);
    CHECK(axb_contract_v7_encode_signed(&model, seed, &module, &module_len) == 0);
    CHECK(axi_sig_make(seed, 0, seed, &identity) == 0);
    options.abi_version = AXI_EMBED_V1_ABI_VERSION;
    options.struct_size = sizeof options;
    options.admission_profile = AXI_EMBED_V1_ADMIT_SIGNATURE_VALID;
    options.module.data = module;
    options.module.len = module_len;
    memcpy(options.trusted_producer_pk, identity.pk, 32);
    CHECK(axi_embed_v1_context_create(&options, &context, NULL) == 0 && context);
    free(module);
    request.abi_version = AXI_EMBED_V1_ABI_VERSION;
    request.struct_size = sizeof request;
    request.fuel_limit = 10;
    request.cell.data = (const uint8_t *)name;
    for (i = 0; i < cells; i++) {
        request.cell.len = (uint64_t)snprintf(name, sizeof name, "cell%03u", cells - 1 - i);
        memcpy(request.expected_iface_hash, model.manifest[i].iface_hash, 32);
        outcome.abi_version = AXI_EMBED_V1_ABI_VERSION;
        outcome.struct_size = sizeof outcome;
        CHECK(axi_embed_v1_eval(context, &request, &outcome, NULL) == 0);
        CHECK(outcome.kind == AXI_EMBED_V1_OUTCOME_VALUE
              && outcome.value.kind == AXI_EMBED_V1_VALUE_U64
              && outcome.value.bits == i && outcome.fuel_used == 2);
    }
    if (iterations) {
        double start = seconds();
        uint64_t checksum = 0;
        unsigned long k;
        for (k = 0; k < iterations; k++) {
            if (axi_embed_v1_eval(context, &request, &outcome, NULL) != 0
                    || outcome.kind != AXI_EMBED_V1_OUTCOME_VALUE
                    || outcome.fuel_used != 2 || outcome.value.bits != cells - 1) return 1;
            checksum += outcome.value.bits;
        }
        printf("{\"case\":\"embed_last_cell\",\"cells\":%u,\"iterations\":%lu,"
               "\"seconds\":%.9f,\"checksum\":%llu}\n", cells, iterations,
               seconds() - start, (unsigned long long)checksum);
    } else {
        request.cell.len = 4;
        memcpy(name, "cell", 4); /* Prefixes are not names. */
        CHECK(axi_embed_v1_eval(context, &request, &outcome, NULL) == 0
              && outcome.kind == AXI_EMBED_V1_OUTCOME_REFUSED);
        request.cell.len = 8;
        memcpy(name, "cell000x", 8);
        CHECK(axi_embed_v1_eval(context, &request, &outcome, NULL) == 0
              && outcome.kind == AXI_EMBED_V1_OUTCOME_REFUSED);
        request.cell.len = 7;
        memcpy(name, "cell000", 7);
        request.expected_iface_hash[0] ^= 1;
        CHECK(axi_embed_v1_eval(context, &request, &outcome, NULL) == 0
              && outcome.kind == AXI_EMBED_V1_OUTCOME_REFUSED);
        request.expected_iface_hash[0] ^= 1;
        request.fuel_limit = 0;
        CHECK(axi_embed_v1_eval(context, &request, &outcome, NULL) == 0
              && outcome.kind == AXI_EMBED_V1_OUTCOME_TRAP
              && (outcome.flags & AXI_EMBED_V1_OUTCOME_F_FUEL_EXHAUSTED));
        printf("audit embed: %u checks PASS\n", checks);
    }
    axi_embed_v1_context_destroy(context);
    axb_contract_mod_free(&model);
    return 0;
}
