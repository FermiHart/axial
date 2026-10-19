/* ADR-059 AXV2-17: consistent operational diagnostics for the narrow
 * local profile. Private C interface; read-only by construction. One
 * call reports liveness, progress, uncertainty, epoch generation and a
 * domain-labeled clock sample with states coherent across the API, the
 * operator view and the evidence (all three read the same durable
 * records through the same scan). Diagnostics never retry, never shell
 * out, never hook recovery and never effect anything.
 *
 * KNOWN GAP (not silently worked around): per-record staleness against
 * the active epoch is unknowable -- v1 attempt records carry no epoch
 * linkage and no timestamps. Reporting it would require a record format
 * migration (deferred, explicit, out of this wave). The report carries
 * the active epoch generation so staleness remains revisitable.
 */
#ifndef AXI_LOCAL_DIAG_V1_H
#define AXI_LOCAL_DIAG_V1_H

#include <stddef.h>
#include <stdint.h>

#define AXI_LOCAL_DIAG_V1_OK 0
#define AXI_LOCAL_DIAG_V1_REFUSED (-1)
#define AXI_LOCAL_DIAG_V1_CORRUPT (-2)

#define AXI_LOCAL_DIAG_V1_LOCK_FREE 0u
#define AXI_LOCAL_DIAG_V1_LOCK_BUSY 1u

typedef struct {
    uint8_t store_ok;
    uint8_t lock_state;
    unsigned records;
    unsigned committed;
    unsigned failed;
    unsigned unknowns;
    unsigned stale;
    unsigned capacity_used;
    unsigned capacity_max;
    uint8_t has_epoch;
    uint64_t epoch_generation;
    uint8_t epoch_deployment[16];
    uint64_t mono_ns;
} axi_local_diag_v1_report;

/* Fill *out from durable state only. Returns OK, REFUSED (unowned /
 * missing store) or CORRUPT (unreadable record or epoch). Never writes,
 * never retries a refused lock (busy is reported, not waited on). */
int axi_local_diag_v1_collect(const char *store_dir,
                             axi_local_diag_v1_report *out);

#endif
