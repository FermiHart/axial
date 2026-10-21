#include "runtime_fixture.h"
#include <stdio.h>

int main(void)
{
    runtime80_fixture fixture;
    axi_embed_v1_context *context = NULL;
    runtime80_case test;
    unsigned i, sample, checks = 0;
    if (runtime80_fixture_init(&fixture, 32, 0) != 0
            || runtime80_context(&fixture, AXI_EMBED_V1_ADMIT_SIGNATURE_VALID, &context) != 0) return 1;
    for (i = 0; i < RUNTIME80_CASES; i++) for (sample = 0; sample < 32; sample++) {
        if (runtime80_prepare(&fixture, i, sample, &test) != 0
                || axi_embed_v1_eval(context, &test.request, &test.outcome, NULL) != 0
                || runtime80_result(&test) != 0) {
            fprintf(stderr, "workload %s sample %u: outcome=%u fuel=%llu value=%u bits=%llu\n",
                runtime80_case_names[i], sample, test.outcome.kind,
                (unsigned long long)test.outcome.fuel_used, test.outcome.value.kind,
                (unsigned long long)test.outcome.value.bits);
            return 1;
        }
        checks++;
    }
    axi_embed_v1_context_destroy(context); runtime80_fixture_free(&fixture);
    printf("audit80 workloads: %u cases x 32 inputs = %u checks PASS\n", RUNTIME80_CASES, checks);
    return 0;
}
