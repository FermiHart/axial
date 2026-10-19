/* ADR-059 AXV2-17: read-only diagnostics. See header. */
#include "axi_local_diag_v1.h"

#include "axi_local_attempt_v1.h"
#include "axi_local_epoch_v1.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct {
    unsigned records;
    unsigned committed;
    unsigned failed;
    unsigned unknowns;
    unsigned stale;
    uint8_t has_epoch;
    uint64_t epoch_generation;
} acc;

static int visit(const axi_local_attempt_v1_record_view *view, void *ctx)
{
    acc *a = ctx;
    a->records++;
    switch (view->state) {
    case AXI_LOCAL_ATTEMPT_V1_COMMITTED:
        a->committed++;
        break;
    case AXI_LOCAL_ATTEMPT_V1_FAILED:
        a->failed++;
        break;
    case AXI_LOCAL_ATTEMPT_V1_UNKNOWN:
        a->unknowns++;
        break;
    default:
        break;
    }
    if (a->has_epoch && view->has_epoch_link
            && view->epoch_generation != a->epoch_generation) {
        a->stale++;
    }
    return 0;
}

int axi_local_diag_v1_collect(const char *store_dir,
                             axi_local_diag_v1_report *out)
{
    int sdfd = -1, lockfd = -1, rc;
    acc a;
    axi_local_epoch_v1 epoch;
    if (!out) {
        return AXI_LOCAL_DIAG_V1_REFUSED;
    }
    memset(out, 0, sizeof(*out));
    if (axi_local_attempt_v1_store_check(store_dir) !=
        AXI_LOCAL_ATTEMPT_V1_OK) {
        return AXI_LOCAL_DIAG_V1_REFUSED;
    }
    out->store_ok = 1;
    out->mono_ns = axi_local_attempt_v1_now_mono();
    sdfd = open(store_dir, O_RDONLY | O_DIRECTORY);
    if (sdfd < 0) {
        return AXI_LOCAL_DIAG_V1_REFUSED;
    }
    /* Liveness probe: single nonblocking shared attempt, never waited. */
    lockfd = openat(sdfd, "owner.lock", O_RDONLY);
    if (lockfd < 0) {
        out->lock_state = AXI_LOCAL_DIAG_V1_LOCK_FREE;
    } else if (flock(lockfd, LOCK_SH | LOCK_NB) != 0) {
        close(lockfd);
        lockfd = -1;
        out->lock_state = (errno == EWOULDBLOCK)
            ? AXI_LOCAL_DIAG_V1_LOCK_BUSY
            : AXI_LOCAL_DIAG_V1_LOCK_FREE;
        if (errno != EWOULDBLOCK) {
            close(sdfd);
            return AXI_LOCAL_DIAG_V1_REFUSED;
        }
    } else {
        out->lock_state = AXI_LOCAL_DIAG_V1_LOCK_FREE;
        flock(lockfd, LOCK_UN);
        close(lockfd);
        lockfd = -1;
    }
    close(sdfd);
    sdfd = -1;
    /* Epoch generation first: staleness compares record links against
     * it during the same pass. */
    memset(&epoch, 0, sizeof(epoch));
    rc = axi_local_epoch_v1_current(store_dir, &epoch);
    if (rc == AXI_LOCAL_EPOCH_V1_OK) {
        out->has_epoch = 1;
        out->epoch_generation = epoch.generation;
        memcpy(out->epoch_deployment, epoch.deployment, 16);
    } else if (rc != AXI_LOCAL_EPOCH_V1_REFUSED) {
        memset(out, 0, sizeof(*out));
        return AXI_LOCAL_DIAG_V1_CORRUPT;
    }
    /* Progress and uncertainty come from the same scan the operator and
     * the evidence paths read: one truth, three readers. Bounded by a
     * 100 ms budget: a busy store reports busy with zeroed counts
     * instead of hanging, and the next poll converges. */
    memset(&a, 0, sizeof(a));
    a.has_epoch = out->has_epoch;
    a.epoch_generation = out->epoch_generation;
    rc = axi_local_attempt_v1_scan_timed(
        store_dir, visit, &a,
        axi_local_attempt_v1_now_mono() + 100000000u);
    if (rc == AXI_LOCAL_ATTEMPT_V1_TIMEOUT) {
        out->records = 0;
        out->committed = 0;
        out->failed = 0;
        out->unknowns = 0;
        out->stale = 0;
        out->capacity_used = 0;
        return AXI_LOCAL_DIAG_V1_OK;
    }
    if (rc != AXI_LOCAL_ATTEMPT_V1_OK) {
        memset(out, 0, sizeof(*out));
        return (rc == AXI_LOCAL_ATTEMPT_V1_CORRUPT)
            ? AXI_LOCAL_DIAG_V1_CORRUPT : AXI_LOCAL_DIAG_V1_REFUSED;
    }
    out->records = a.records;
    out->committed = a.committed;
    out->failed = a.failed;
    out->unknowns = a.unknowns;
    out->stale = a.stale;
    out->capacity_used = a.records;
    out->capacity_max = AXI_LOCAL_ATTEMPT_V1_MAX_RECORDS;
    return AXI_LOCAL_DIAG_V1_OK;
}
