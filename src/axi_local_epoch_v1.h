/* ADR-059 AXV2-12 / D03: explicit trust-epoch lifecycle for the narrow
 * local profile. Private C interface, fixture-only; no installed ABI
 * promise. An epoch pins one deployment, one trust snapshot root and one
 * policy (binary/module/producer/iface) with a monotone generation.
 * Rotation is explicit (provision then activate in generation order);
 * old evidence keeps its own identities and stays readable forever, but
 * no new grant or mutation is accepted under a superseded epoch.
 * Activation serializes on the owner lock, so no live committer can slip
 * between validation and effect: stranded ATTEMPTED records stay stranded
 * (UNKNOWN), never rewritten by rotation. No quiescence gate is needed
 * beyond the lock, and none is imposed (it would deadlock rotation on
 * stranded records).
 */
#ifndef AXI_LOCAL_EPOCH_V1_H
#define AXI_LOCAL_EPOCH_V1_H

#include <stddef.h>
#include <stdint.h>

#include "axi_local_admission_v1.h"

#define AXI_LOCAL_EPOCH_V1_OK 0
#define AXI_LOCAL_EPOCH_V1_REFUSED (-1)
#define AXI_LOCAL_EPOCH_V1_CORRUPT (-2)

typedef struct {
    uint64_t generation;
    uint8_t deployment[16];
    uint8_t trust_snapshot_root[32];
    uint8_t policy_binary[32];
    uint8_t policy_module[32];
    uint8_t policy_producer[32];
    uint8_t policy_iface[32];
} axi_local_epoch_v1;

/* Stage a pending epoch. Pins must all be nonzero; deployment/trust/policy
 * mismatch nothing yet -- this only stages. Returns the assigned generation
 * (active + 1, or 1 when no epoch is active) in *out_generation when
 * non-null. Overwriting an unactivated pending epoch is allowed (it was
 * never active); the returned generation always follows the active one.
 * No effect, no grant, no mutation beyond the pending file. */
int axi_local_epoch_v1_provision(const char *store_dir,
                                 const axi_local_epoch_v1 *pins,
                                 uint64_t *out_generation);

/* Activate the pending epoch. Requires a pending epoch whose generation
 * equals both the requested generation and active + 1 (or 1 with no
 * active epoch). Downgrades, replays and double activations refuse.
 * Atomic temp + rename + fsyncs; old records are untouched. */
int axi_local_epoch_v1_activate(const char *store_dir,
                                uint64_t generation);

/* Read the active epoch. Returns OK with *out filled, or REFUSED when no
 * epoch is active (legacy pre-epoch store). Never fails on old content:
 * evidence keeps its own identities. */
int axi_local_epoch_v1_current(const char *store_dir,
                               axi_local_epoch_v1 *out);

/* Enforcement at the owner door (call with the owner lock held): when an
 * active epoch file exists under dirfd, the caller's pins must equal it
 * byte-for-byte. Returns 0 on match or when no epoch file exists
 * (legacy grandfathered store), -1 on mismatch (no new grant/mutation;
 * old state stays recovery/status-only), -2 on unreadable/corrupt file,
 * -3 on transient resource exhaustion (EMFILE/ENFILE/ENOMEM: refuse and
 * re-query, never CORRUPT -- AXI-INV-217). Single layout authority for
 * the 192-byte epoch record. */
int axi_local_epoch_v1_enforce(int dirfd,
                               const axi_local_admission_v1_pins *pins);

/* Read the active epoch file under an open dirfd. Returns 0 with
 * *present set (1: *out filled; 0: no epoch file, *out zeroed), -2 on
 * transient resource exhaustion (AXI-INV-217), or -1 on
 * unreadable/corrupt content. */
int axi_local_epoch_v1_read_at(int dirfd, axi_local_epoch_v1 *out,
                               int *present);

#endif
