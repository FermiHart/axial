/* GNU/ELF test-link instrumentation. Counts requested bytes in direct calls;
 * allocator metadata, libc-internal allocation and stack are not included. */
#include "runtime_track.h"
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
void __real_free(void *);

typedef struct { void *pointer; size_t size; } tracked;
static tracked allocations[65536];
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static size_t live, blocks, fail_at;
static int measuring;
static runtime80_allocation_stats stats;

static size_t locate(void *p)
{
    size_t i;
    for (i = 0; i < sizeof allocations / sizeof allocations[0]; i++)
        if (allocations[i].pointer == p) return i;
    return i;
}

static int fail_now(void)
{
    if (!measuring) return 0;
    stats.calls++;
    if (fail_at && stats.calls == fail_at) { stats.failures++; errno = ENOMEM; return 1; }
    return 0;
}

static void add(void *p, size_t size)
{
    size_t slot;
    if (!p) return;
    slot = locate(NULL);
    if (slot == sizeof allocations / sizeof allocations[0] || size > SIZE_MAX - live) abort();
    allocations[slot].pointer = p; allocations[slot].size = size;
    live += size; blocks++;
    if (measuring && live > stats.peak_bytes) stats.peak_bytes = live;
}

static void remove_at(size_t slot)
{
    if (slot == sizeof allocations / sizeof allocations[0]) return;
    live -= allocations[slot].size; blocks--;
    allocations[slot].pointer = NULL; allocations[slot].size = 0;
}

void *__wrap_malloc(size_t n)
{
    void *p;
    pthread_mutex_lock(&mutex);
    p = fail_now() ? NULL : __real_malloc(n); add(p, n);
    pthread_mutex_unlock(&mutex); return p;
}

void *__wrap_calloc(size_t n, size_t size)
{
    void *p;
    pthread_mutex_lock(&mutex);
    p = fail_now() ? NULL : __real_calloc(n, size);
    if (p && size && n > SIZE_MAX / size) abort();
    add(p, n * size);
    pthread_mutex_unlock(&mutex); return p;
}

void *__wrap_realloc(void *p, size_t n)
{
    void *next;
    size_t slot;
    pthread_mutex_lock(&mutex);
    slot = p ? locate(p) : sizeof allocations / sizeof allocations[0];
    if (fail_now()) next = NULL;
    else {
        next = __real_realloc(p, n);
        if (next || n == 0) { remove_at(slot); add(next, n); }
    }
    pthread_mutex_unlock(&mutex); return next;
}

void __wrap_free(void *p)
{
    pthread_mutex_lock(&mutex);
    if (p) remove_at(locate(p));
    __real_free(p);
    pthread_mutex_unlock(&mutex);
}

void runtime80_track_begin(size_t failure)
{
    pthread_mutex_lock(&mutex);
    stats = (runtime80_allocation_stats){0};
    stats.live_before = stats.peak_bytes = live;
    fail_at = failure; measuring = 1;
    pthread_mutex_unlock(&mutex);
}

runtime80_allocation_stats runtime80_track_end(void)
{
    runtime80_allocation_stats result;
    pthread_mutex_lock(&mutex);
    measuring = 0; stats.live_after = live; stats.blocks = blocks; result = stats;
    pthread_mutex_unlock(&mutex); return result;
}
