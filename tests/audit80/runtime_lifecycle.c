#include "runtime_fixture.h"
#include "runtime_track.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { fprintf(stderr, "lifecycle:%d: %s\n", __LINE__, #c); return 1; } } while (0)

int main(void)
{
    const unsigned sizes[] = {13, 64, 256};
    unsigned s, cycle;
    size_t point, calls = 0;
    runtime80_fixture f;
    runtime80_case test;
    axi_embed_v1_context *context;
    runtime80_allocation_stats stats;
    for (s = 0; s < 3; s++) {
        unsigned laws = s ? 16 : 0;
        CHECK(runtime80_fixture_init(&f, sizes[s], laws) == 0);
        for (cycle = 0; cycle < 8; cycle++) {
            unsigned profile = laws ? AXI_EMBED_V1_ADMIT_CHECKED : AXI_EMBED_V1_ADMIT_SIGNATURE_VALID;
            runtime80_track_begin(0);
            CHECK(runtime80_context(&f, profile, &context) == 0);
            CHECK(runtime80_prepare(&f, cycle % RUNTIME80_CASES, cycle, &test) == 0);
            CHECK(axi_embed_v1_eval(context, &test.request, &test.outcome, NULL) == 0);
            CHECK(runtime80_result(&test) == 0);
            axi_embed_v1_context_destroy(context);
            stats = runtime80_track_end();
            CHECK(stats.live_before == stats.live_after && stats.failures == 0);
            if (cycle == 0)
                printf("{\"case\":\"lifecycle\",\"cells\":%u,\"laws\":%u,\"calls\":%zu,\"peak_extra_bytes\":%zu}\n",
                    sizes[s], laws, stats.calls, stats.peak_bytes - stats.live_before);
        }
        runtime80_fixture_free(&f);
    }
    CHECK(runtime80_fixture_init(&f, 13, 0) == 0);
    runtime80_track_begin(0);
    CHECK(runtime80_context(&f, AXI_EMBED_V1_ADMIT_SIGNATURE_VALID, &context) == 0);
    axi_embed_v1_context_destroy(context);
    stats = runtime80_track_end(); calls = stats.calls;
    for (point = 1; point <= calls; point++) {
        int status;
        runtime80_track_begin(point);
        context = NULL;
        status = runtime80_context(&f, AXI_EMBED_V1_ADMIT_SIGNATURE_VALID, &context);
        if (context) axi_embed_v1_context_destroy(context);
        stats = runtime80_track_end();
        CHECK(stats.failures == 1);
        CHECK(status == AXI_EMBED_V1_STATUS_OUT_OF_MEMORY && context == NULL);
        CHECK(stats.live_before == stats.live_after);
    }
    /* Once admitted, module storage belongs to the context. */
    CHECK(runtime80_context(&f, AXI_EMBED_V1_ADMIT_SIGNATURE_VALID, &context) == 0);
    CHECK(runtime80_prepare(&f, 4, 0, &test) == 0);
    runtime80_fixture_free(&f);
    CHECK(axi_embed_v1_eval(context, &test.request, &test.outcome, NULL) == 0);
    CHECK(runtime80_result(&test) == 0);
    axi_embed_v1_context_destroy(context);
    axi_embed_v1_context_destroy(NULL);
    printf("audit80 lifecycle: %u checks, %zu allocation failpoints PASS\n", checks, calls);
    return 0;
}
