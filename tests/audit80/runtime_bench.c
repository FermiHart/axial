/* Uninstrumented synthetic timing lane. No performance pass/fail threshold. */
#include "runtime_fixture.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define POOL_INPUTS 64u
#define POOL_SIZE (RUNTIME80_CASES * POOL_INPUTS)

static int number(const char *text, unsigned max, unsigned *out)
{
    char *end;
    unsigned long value;
    if (!text || !*text || *text == '-') return -1;
    errno = 0; value = strtoul(text, &end, 10);
    if (errno || *end || value > max || value > UINT_MAX) return -1;
    *out = (unsigned)value;
    return 0;
}

static void samples(const uint64_t *values, unsigned count)
{
    unsigned i;
    putchar('[');
    for (i = 0; i < count; i++) printf("%s%llu", i ? "," : "", (unsigned long long)values[i]);
    putchar(']');
}

static runtime80_case *make_pool(const runtime80_fixture *fixture)
{
    runtime80_case *pool = calloc(POOL_SIZE, sizeof *pool);
    unsigned input, which;
    if (!pool) return NULL;
    for (input = 0; input < POOL_INPUTS; input++)
        for (which = 0; which < RUNTIME80_CASES; which++)
            if (runtime80_prepare(fixture, which, input,
                                  &pool[input * RUNTIME80_CASES + which])) {
                free(pool); return NULL;
            }
    return pool;
}

/* Checking is deliberately included in the amortized throughput loop, but
 * excluded from individual eval latency intervals. Every result is checked. */
static int validated_loop(axi_embed_v1_context *context, runtime80_case *pool,
                          unsigned count)
{
    unsigned i, which;
    for (i = 0; i < count; i++) for (which = 0; which < RUNTIME80_CASES; which++) {
        runtime80_case *test = &pool[(i % POOL_INPUTS) * RUNTIME80_CASES + which];
        if (axi_embed_v1_eval(context, &test->request, &test->outcome, NULL)
                || runtime80_result(test)) return -1;
    }
    return 0;
}

static int context_bench(unsigned cells, unsigned laws, unsigned count)
{
    runtime80_fixture fixture;
    axi_embed_v1_context *context;
    unsigned i;
    uint64_t create_ns = 0, destroy_ns = 0, before;
    uint64_t *create = calloc(count, sizeof *create), *destroy = calloc(count, sizeof *destroy);
    if (!create || !destroy || runtime80_fixture_init(&fixture, cells, laws)) return 1;
    if (runtime80_context(&fixture, laws ? AXI_EMBED_V1_ADMIT_CHECKED
                          : AXI_EMBED_V1_ADMIT_SIGNATURE_VALID, &context)) return 1;
    axi_embed_v1_context_destroy(context);
    for (i = 0; i < count; i++) {
        before = runtime80_now_ns();
        if (runtime80_context(&fixture, laws ? AXI_EMBED_V1_ADMIT_CHECKED
                             : AXI_EMBED_V1_ADMIT_SIGNATURE_VALID, &context)) return 1;
        create[i] = runtime80_now_ns() - before; create_ns += create[i];
        before = runtime80_now_ns();
        axi_embed_v1_context_destroy(context);
        destroy[i] = runtime80_now_ns() - before; destroy_ns += destroy[i];
    }
    printf("{\"case\":\"context\",\"cells\":%u,\"laws\":%u,\"iterations\":%u,"
           "\"module_bytes\":%zu,\"create_ns\":%llu,\"destroy_ns\":%llu,\"create_samples_ns\":",
           cells, laws, count, fixture.len, (unsigned long long)create_ns,
           (unsigned long long)destroy_ns);
    samples(create, count); printf(",\"destroy_samples_ns\":"); samples(destroy, count); puts("}");
    runtime80_fixture_free(&fixture); free(create); free(destroy);
    return 0;
}

static int latency_bench(unsigned count)
{
    runtime80_fixture fixture;
    axi_embed_v1_context *context;
    runtime80_case *pool;
    uint64_t *latencies = calloc((size_t)count * RUNTIME80_CASES, sizeof *latencies);
    uint64_t clock_pairs[256], before, elapsed;
    unsigned i, which;
    if (!latencies || runtime80_fixture_init(&fixture, 64, 16)) return 1;
    pool = make_pool(&fixture);
    if (!pool || runtime80_context(&fixture, AXI_EMBED_V1_ADMIT_CHECKED, &context)) return 1;
    if (validated_loop(context, pool, 256)) return 1;
    for (i = 0; i < 256; i++) {
        before = runtime80_now_ns(); clock_pairs[i] = runtime80_now_ns() - before;
    }
    for (i = 0; i < count; i++) for (which = 0; which < RUNTIME80_CASES; which++) {
        runtime80_case *test = &pool[(i % POOL_INPUTS) * RUNTIME80_CASES + which];
        int rc;
        before = runtime80_now_ns();
        rc = axi_embed_v1_eval(context, &test->request, &test->outcome, NULL);
        latencies[(size_t)which * count + i] = runtime80_now_ns() - before;
        if (rc || runtime80_result(test)) return 1;
    }
    before = runtime80_now_ns();
    if (validated_loop(context, pool, count)) return 1;
    elapsed = runtime80_now_ns() - before;
    printf("{\"case\":\"mixed_latency\",\"cells\":64,\"laws\":16,\"iterations_per_case\":%u,"
           "\"validated_loop_operations\":%u,\"validated_loop_ns\":%llu,\"clock_pair_ns\":",
           count, count * RUNTIME80_CASES, (unsigned long long)elapsed);
    samples(clock_pairs, 256); printf(",\"workloads\":[");
    for (which = 0; which < RUNTIME80_CASES; which++) {
        printf("%s{\"name\":\"%s\",\"outcome\":%u,\"fuel\":%llu,\"latency_ns\":",
               which ? "," : "", runtime80_case_names[which], pool[which].kind,
               (unsigned long long)pool[which].fuel);
        samples(latencies + (size_t)which * count, count); putchar('}');
    }
    puts("]}");
    axi_embed_v1_context_destroy(context); runtime80_fixture_free(&fixture);
    free(pool); free(latencies);
    return 0;
}

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    unsigned ready, done;
    int start;
} bench_gate;

typedef struct {
    bench_gate *gate;
    const runtime80_fixture *fixture;
    axi_embed_v1_context *context;
    runtime80_case *pool;
    unsigned iterations;
    int failed;
} bench_worker;

static void *worker_main(void *opaque)
{
    bench_worker *worker = opaque;
    runtime80_case *pool = worker->pool;
    if (!pool || validated_loop(worker->context, pool, 64)) worker->failed = 1;
    pthread_mutex_lock(&worker->gate->mutex);
    worker->gate->ready++; pthread_cond_broadcast(&worker->gate->condition);
    while (!worker->gate->start) pthread_cond_wait(&worker->gate->condition, &worker->gate->mutex);
    pthread_mutex_unlock(&worker->gate->mutex);
    if (!worker->failed && validated_loop(worker->context, pool, worker->iterations)) worker->failed = 1;
    pthread_mutex_lock(&worker->gate->mutex);
    worker->gate->done++; pthread_cond_broadcast(&worker->gate->condition);
    pthread_mutex_unlock(&worker->gate->mutex);
    return NULL;
}

static int parallel_bench(unsigned workers, unsigned count)
{
    runtime80_fixture fixture;
    axi_embed_v1_context *context;
    pthread_t threads[8];
    bench_worker arguments[8];
    bench_gate gate = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, 0, 0};
    unsigned i;
    uint64_t before, elapsed;
    if (runtime80_fixture_init(&fixture, 64, 16)
            || runtime80_context(&fixture, AXI_EMBED_V1_ADMIT_CHECKED, &context)) return 1;
    memset(arguments, 0, sizeof arguments);
    for (i = 0; i < workers; i++) {
        arguments[i].gate = &gate; arguments[i].fixture = &fixture;
        arguments[i].context = context; arguments[i].iterations = count;
        arguments[i].pool = make_pool(&fixture);
        if (pthread_create(&threads[i], NULL, worker_main, &arguments[i])) return 1;
    }
    pthread_mutex_lock(&gate.mutex);
    while (gate.ready != workers) pthread_cond_wait(&gate.condition, &gate.mutex);
    before = runtime80_now_ns(); gate.start = 1; pthread_cond_broadcast(&gate.condition);
    while (gate.done != workers) pthread_cond_wait(&gate.condition, &gate.mutex);
    elapsed = runtime80_now_ns() - before;
    pthread_mutex_unlock(&gate.mutex);
    for (i = 0; i < workers; i++) {
        if (pthread_join(threads[i], NULL) || arguments[i].failed) return 1;
        free(arguments[i].pool);
    }
    printf("{\"case\":\"parallel_validated_loop\",\"workers\":%u,\"operations\":%u,\"elapsed_ns\":%llu}\n",
           workers, workers * count * RUNTIME80_CASES, (unsigned long long)elapsed);
    pthread_cond_destroy(&gate.condition); pthread_mutex_destroy(&gate.mutex);
    axi_embed_v1_context_destroy(context); runtime80_fixture_free(&fixture);
    return 0;
}

int main(int argc, char **argv)
{
    unsigned first, second, count;
    if (argc == 5 && !strcmp(argv[1], "context")
            && !number(argv[2], 256, &first) && !number(argv[3], 64, &second)
            && !number(argv[4], 10000, &count) && count)
        return context_bench(first, second, count);
    if (argc == 3 && !strcmp(argv[1], "latency")
            && !number(argv[2], 100000, &count) && count)
        return latency_bench(count);
    if (argc == 4 && !strcmp(argv[1], "parallel")
            && !number(argv[2], 8, &first) && first
            && !number(argv[3], 100000, &count) && count)
        return parallel_bench(first, count);
    return 2;
}

