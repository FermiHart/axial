/* Only immutable context/model state is shared. Requests, diagnostics,
 * workspaces, outputs and test counters belong to individual threads. */
#include "runtime_fixture.h"
#include "axi_hash.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A fresh namespace tests concurrent first use without resetting any
 * production state. Expected bytes use the independently named hash door. */
#define SHA256NI_CTX_TYPE audit80_sha_context
#define SHA256NI_PREFIX audit80_sha_
#include "sha256_ni.h"

#define THREADS 8u
#define ROUNDS 240u
typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t ready;
    unsigned waiting;
    int start;
} rendezvous;
typedef struct {
    const runtime80_fixture *fixture;
    const axi_embed_v1_context *shared;
    rendezvous *barrier;
    unsigned id, completed;
    int failed;
    uint8_t input[1024], expected[32];
} worker;

static void *run_worker(void *raw)
{
    worker *w = raw;
    axi_embed_v1_context *own = NULL;
    const axi_embed_v1_context *context = w->shared;
    runtime80_case test;
    unsigned i;
    pthread_mutex_lock(&w->barrier->lock);
    w->barrier->waiting++; pthread_cond_broadcast(&w->barrier->ready);
    while (!w->barrier->start) pthread_cond_wait(&w->barrier->ready, &w->barrier->lock);
    pthread_mutex_unlock(&w->barrier->lock);
    {
        audit80_sha_context hash;
        uint8_t digest[32];
        audit80_sha_init(&hash); audit80_sha_update(&hash, w->input, sizeof w->input);
        audit80_sha_final(&hash, digest);
        if (memcmp(digest, w->expected, 32)) { w->failed = 1; return NULL; }
    }
    if (!context) {
        if (runtime80_context(w->fixture, AXI_EMBED_V1_ADMIT_CHECKED, &own)) { w->failed = 1; return NULL; }
        context = own;
    }
    for (i = 0; i < ROUNDS; i++) {
        unsigned which = (i + w->id) % RUNTIME80_CASES;
        if (runtime80_prepare(w->fixture, which, i * THREADS + w->id, &test)
                || axi_embed_v1_eval(context, &test.request, &test.outcome, NULL)
                || runtime80_result(&test)) { w->failed = 1; break; }
        w->completed++;
    }
    axi_embed_v1_context_destroy(own);
    return NULL;
}

static int exercise(const runtime80_fixture *f, const axi_embed_v1_context *shared)
{
    pthread_t threads[THREADS];
    worker workers[THREADS];
    rendezvous barrier = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, 0};
    unsigned i, created = 0, completed = 0;
    int failed = 0;
    memset(workers, 0, sizeof workers);
    for (i = 0; i < THREADS; i++) {
        workers[i].id = i; workers[i].fixture = f; workers[i].shared = shared; workers[i].barrier = &barrier;
        memset(workers[i].input, (int)('a' + i), sizeof workers[i].input);
        axi_sha256(workers[i].input, sizeof workers[i].input, workers[i].expected);
        if (pthread_create(&threads[i], NULL, run_worker, &workers[i])) { failed = 1; break; }
        created++;
    }
    pthread_mutex_lock(&barrier.lock);
    while (barrier.waiting != created) pthread_cond_wait(&barrier.ready, &barrier.lock);
    barrier.start = 1; pthread_cond_broadcast(&barrier.ready);
    pthread_mutex_unlock(&barrier.lock);
    for (i = 0; i < created; i++) {
        if (pthread_join(threads[i], NULL)) failed = 1;
        failed |= workers[i].failed; completed += workers[i].completed;
    }
    pthread_cond_destroy(&barrier.ready); pthread_mutex_destroy(&barrier.lock);
    printf("audit80 concurrency: %s, %u workers, %u evaluations, %s\n",
           shared ? "shared immutable context" : "isolated create/eval/destroy",
           created, completed, failed ? "FAIL" : "PASS");
    return failed || completed != THREADS * ROUNDS;
}

int main(void)
{
    runtime80_fixture f;
    axi_embed_v1_context *shared = NULL;
    int failed;
    if (runtime80_fixture_init(&f, 64, 16)) return 1;
    failed = exercise(&f, NULL);
    if (runtime80_context(&f, AXI_EMBED_V1_ADMIT_CHECKED, &shared)) return 1;
    failed |= exercise(&f, shared);
    /* Destroy happens after every reader joined, never concurrently. */
    axi_embed_v1_context_destroy(shared); runtime80_fixture_free(&f);
    return failed;
}
