/* ADR-059 AXV2-13 / D04: minimal consumer integration interface for the
 * narrow local profile. Private C interface; no installed ABI promise and
 * deliberately NO new ABI: no new wire format, version, codec or effect.
 * This module only orchestrates 05/06/AG1/07/08/09/AER2 behind documented
 * ownership rules. Every function validates its inputs first (NULL matrix,
 * sizes, versions) and never exposes static state: two identical calls
 * with identical inputs behave identically.
 *
 * Ownership: callers own all buffers, pins and observations, which must
 * stay live and stable during the call. Outputs are written only on
 * documented paths; refused calls leave *out zeroed where stated.
 * Keys (grant-issuer pk, receipt-issuer seed) always come from the caller;
 * this module never generates, stores or selects keys.
 */
#ifndef AXI_LOCAL_CONSUMER_V1_H
#define AXI_LOCAL_CONSUMER_V1_H

#include <stddef.h>
#include <stdint.h>

#include "axi_aer2_v1.h"
#include "axi_local_action_v1.h"
#include "axi_local_admission_v1.h"
#include "axi_local_attempt_v1.h"

#define AXI_LOCAL_CONSUMER_V1_OK 0
#define AXI_LOCAL_CONSUMER_V1_REFUSED (-1)
#define AXI_LOCAL_CONSUMER_V1_INVALID (-2)
#define AXI_LOCAL_CONSUMER_V1_TIMEOUT (-3)
#define AXI_LOCAL_CONSUMER_V1_STORE_FULL (-4)
#define AXI_LOCAL_CONSUMER_V1_CORRUPT (-5)

/* Appraisal only: decode canonical action bytes, run the common admission
 * path. No grant minted or consumed, no effect, no receipt. Always writes
 * *out (admitted/refusal/profile/context echo) unless a pointer is NULL,
 * which returns INVALID. */
int axi_local_consumer_v1_authorize(
    const void *action_bytes, size_t action_len,
    const axi_local_admission_v1_pins *pins,
    const axi_local_admission_v1_observed *observed,
    axi_local_admission_v1_result *out);

/* One-call authorize -> consume -> effect -> terminal. Maps owner results
 * onto consumer codes (OK/COMMITTED-implied, REFUSED, TIMEOUT, STORE_FULL,
 * CORRUPT). When receipt_seed is non-null, also emits a signed AER2
 * terminal bound to the attempt (artifact = policy module digest from
 * the decoded action); aer2_out (493 bytes) is written only then, and
 * only on terminal success. NULL aer2_out with non-null seed is INVALID.
 * attempt_out is always written on OK/REFUSED/TIMEOUT paths. */
int axi_local_consumer_v1_commit(
    const char *store_dir, const uint8_t *grant_signed, size_t grant_len,
    const uint8_t issuer_pk[32], const void *action_bytes, size_t action_len,
    const axi_local_admission_v1_pins *pins,
    const axi_local_admission_v1_observed *observed,
    const uint8_t *payload, size_t payload_len, uint64_t supplied_time,
    uint64_t deadline_mono_ns, const uint8_t *receipt_seed,
    uint8_t aer2_out[AXI_AER2_V1_SIGNED_SIZE],
    axi_local_attempt_v1_outcome *attempt_out);

/* Read-only query of one grant: durable state, never an effect. */
int axi_local_consumer_v1_query(const char *store_dir,
                                const uint8_t grant_root[32],
                                axi_local_attempt_v1_outcome *out);

/* Store reconciliation summary: counts durable records and stranded
 * (UNKNOWN-reported) ones. Read-only. */
int axi_local_consumer_v1_scan_count(const char *store_dir,
                                     unsigned *records, unsigned *unknowns);

/* Terminal evidence for an observed owner outcome (e.g. from query):
 * decision/attempt/outcome evidence signed by receipt_seed. Pure. */
int axi_local_consumer_v1_evidence(
    const axi_local_action_roots_v1 *roots, const uint8_t artifact[32],
    const uint8_t *grant_root, int has_grant,
    const axi_local_admission_v1_result *admitted, uint8_t coverage_complete,
    uint8_t profile, uint8_t decision, uint8_t owner_state,
    const uint8_t receipt_seed[32],
    uint8_t aer2_out[AXI_AER2_V1_SIGNED_SIZE]);

#endif
