#ifndef AUDIT80_RUNTIME_TRACK_H
#define AUDIT80_RUNTIME_TRACK_H
#include <stddef.h>
typedef struct {
    size_t calls, failures, live_before, live_after, peak_bytes, blocks;
} runtime80_allocation_stats;
/* Test executable link wrappers only; no product hooks or malloc metadata. */
void runtime80_track_begin(size_t fail_at);
runtime80_allocation_stats runtime80_track_end(void);
#endif
