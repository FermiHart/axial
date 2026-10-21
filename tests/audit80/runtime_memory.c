#include "runtime_fixture.h"
#include "runtime_track.h"
#include "axi_mem_account.h"
#include "axi_json.h"
#include "axi_vm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { fprintf(stderr, "memory:%d: %s\n", __LINE__, #c); return 1; } } while (0)

int main(void)
{
    runtime80_fixture f;
    axi_embed_v1_context *contexts[8] = {0};
    runtime80_allocation_stats stats;
    runtime80_case test;
    unsigned i, count, cycle;
    struct rusage usage;
    const size_t bytes = (AXI_JSON_SCRATCH_SIZE - 11u) / 2u;
    char *json = malloc(bytes * 2 + 16);
    uint8_t *workspace = malloc(bytes);
    CHECK(json && workspace);
    memcpy(json, "{\"role\":\"", 9);
    for (i = 0; i < bytes; i++) { json[9 + 2 * i] = '\\'; json[10 + 2 * i] = 'n'; }
    memcpy(json + 9 + bytes * 2, "\"}", 3);
    json[11 + bytes * 2] = ' '; /* valid JSON at the documented input bound */
    json[AXI_JSON_SCRATCH_SIZE] = '\0';
    CHECK(runtime80_fixture_init(&f, 256, 64) == 0);
    for (count = 1; count <= 8; count *= 2) {
        runtime80_track_begin(0);
        for (i = 0; i < count; i++) CHECK(runtime80_context(&f, AXI_EMBED_V1_ADMIT_CHECKED, &contexts[i]) == 0);
        stats = runtime80_track_end();
        printf("{\"case\":\"retained_contexts\",\"count\":%u,\"cells\":256,\"laws\":64,"
               "\"live_extra_bytes\":%zu,\"peak_extra_bytes\":%zu}\n", count,
               stats.live_after - stats.live_before, stats.peak_bytes - stats.live_before);
        runtime80_track_begin(0);
        for (i = 0; i < count; i++) axi_embed_v1_context_destroy(contexts[i]);
        { runtime80_allocation_stats freed = runtime80_track_end();
          CHECK(freed.live_after == stats.live_before); }
    }
    CHECK(runtime80_context(&f, AXI_EMBED_V1_ADMIT_CHECKED, &contexts[0]) == 0);
    for (cycle = 0; cycle < 48; cycle++) {
        CHECK(runtime80_prepare(&f, 4, cycle, &test) == 0);
        test.args[0].payload.data = (const uint8_t *)json;
        test.args[0].payload.len = AXI_JSON_SCRATCH_SIZE;
        test.request.workspace.data = workspace;
        test.request.workspace.capacity = cycle % 3 == 1 ? bytes - 1 : bytes;
        memset(workspace, 0xa5, bytes);
        runtime80_track_begin(cycle % 3 == 2 ? 1 : 0);
        CHECK(axi_embed_v1_eval(contexts[0], &test.request, &test.outcome, NULL) == 0);
        stats = runtime80_track_end();
        CHECK(stats.live_after == stats.live_before);
        if (cycle % 3 == 0) {
            CHECK(test.outcome.kind == AXI_EMBED_V1_OUTCOME_VALUE && test.outcome.fuel_used == 10);
            CHECK(test.outcome.workspace_used == bytes && test.outcome.value.payload.data == workspace);
            for (i = 0; i < bytes; i++) if (workspace[i] != '\n') return 1;
        } else if (cycle % 3 == 1) {
            CHECK(test.outcome.kind == AXI_EMBED_V1_OUTCOME_BUFFER_TOO_SMALL);
            CHECK(test.outcome.workspace_required == bytes && workspace[0] == 0xa5);
        } else {
            CHECK(stats.failures == 1 && test.outcome.kind == AXI_EMBED_V1_OUTCOME_TRAP);
            CHECK(workspace[0] == 0xa5 && test.outcome.fuel_used == 9);
        }
        if (cycle < 3) printf("{\"case\":\"large_json_%u\",\"input_bytes\":%zu,\"output_bytes\":%zu,"
                   "\"calls\":%zu,\"peak_extra_bytes\":%zu,\"retained_extra_bytes\":%zu}\n",
                   cycle, (size_t)test.args[0].payload.len, bytes, stats.calls,
                   stats.peak_bytes - stats.live_before, stats.live_after - stats.live_before);
    }
    CHECK(runtime80_prepare(&f, 4, 0, &test) == 0);
    json[AXI_JSON_SCRATCH_SIZE] = ' ';
    json[AXI_JSON_SCRATCH_SIZE + 1u] = '\0';
    test.args[0].payload.data = (const uint8_t *)json;
    test.args[0].payload.len = AXI_JSON_SCRATCH_SIZE + 1u;
    runtime80_track_begin(0);
    CHECK(axi_embed_v1_eval(contexts[0], &test.request, &test.outcome, NULL) == 0);
    stats = runtime80_track_end();
    CHECK(test.outcome.kind == AXI_EMBED_V1_OUTCOME_TRAP && test.outcome.fuel_used == 0);
    CHECK(stats.calls == 0 && stats.live_after == stats.live_before && test.workspace[0] == 0xa5);
    {
        const size_t limits[] = {0, 4096, 131072};
        axi_vval arg = {0}, value;
        arg.kind = VB_U64; arg.bits = 77;
        for (i = 0; i < 3; i++) {
            axi_mem_account account;
            axi_diags diags;
            uint64_t fuel = 0;
            int exhausted = 0, ok;
            axi_mem_account_init(&account, limits[i]); axi_diags_init(&diags);
            ok = axi_vm_run_contract_cell_preverified_accounted_diag(&f.model, 5, &arg, 1,
                       &value, 100, &fuel, &exhausted, &diags, &account);
            CHECK(account.live == 0 && account.active_count == 0 && account.peak <= limits[i]);
            if (i < 2) CHECK(!ok && account.denied_failure == AXI_MEM_QUOTA_EXCEEDED);
            else CHECK(ok && value.kind == VB_U64 && value.bits == 78 && fuel == 38);
            printf("{\"case\":\"accounted_calls\",\"limit_bytes\":%zu,\"peak_bytes\":%zu,\"ok\":%s}\n",
                    limits[i], account.peak, ok ? "true" : "false");
        }
    }
    axi_embed_v1_context_destroy(contexts[0]); runtime80_fixture_free(&f);
    free(json); free(workspace);
    runtime80_track_begin(0); stats = runtime80_track_end();
    CHECK(stats.live_after == 0 && stats.blocks == 0);
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
#ifdef __linux__
        printf("{\"case\":\"process_high_water\",\"ru_maxrss_linux_kib\":%ld}\n", usage.ru_maxrss);
#endif
    }
    printf("audit80 memory: %u checks PASS\n", checks);
    return 0;
}
