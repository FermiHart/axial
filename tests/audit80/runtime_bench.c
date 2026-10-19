/* Timing lane: no allocation wrappers and no correctness timing threshold. */
#include "runtime_fixture.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    runtime80_fixture fixture;
    axi_embed_v1_context *context;
    unsigned cells, laws, count, i;
    uint64_t create_ns = 0, destroy_ns = 0, before;
    if (argc != 5 || strcmp(argv[1], "context")) return 2;
    cells = (unsigned)strtoul(argv[2], NULL, 10);
    laws = (unsigned)strtoul(argv[3], NULL, 10);
    count = (unsigned)strtoul(argv[4], NULL, 10);
    if (!count || count > 10000 || runtime80_fixture_init(&fixture, cells, laws) != 0) return 2;
    for (i = 0; i < count; i++) {
        before = runtime80_now_ns();
        if (runtime80_context(&fixture, laws ? AXI_EMBED_V1_ADMIT_CHECKED
                             : AXI_EMBED_V1_ADMIT_SIGNATURE_VALID, &context)) return 1;
        create_ns += runtime80_now_ns() - before;
        before = runtime80_now_ns();
        axi_embed_v1_context_destroy(context);
        destroy_ns += runtime80_now_ns() - before;
    }
    printf("{\"case\":\"context\",\"cells\":%u,\"laws\":%u,\"iterations\":%u,"
           "\"module_bytes\":%zu,\"create_ns\":%llu,\"destroy_ns\":%llu}\n",
           cells, laws, count, fixture.len, (unsigned long long)create_ns,
           (unsigned long long)destroy_ns);
    runtime80_fixture_free(&fixture);
    return 0;
}
