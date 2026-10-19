/* ADR-059 AXV2-06 / AXI-INV-185: one common appraisal path for the local
 * profile. Pure bytes-to-decision check; no clock read, filesystem, signing,
 * spend or effect. The owner supplies pinned values and locally measured
 * observations; the claimed action arrives as canonical bytes and is decoded
 * through the AXV2-ACTION-v1 codec before any comparison. */
#ifndef AXI_LOCAL_ADMISSION_V1_H
#define AXI_LOCAL_ADMISSION_V1_H

#include <stddef.h>
#include <stdint.h>

#define AXI_LOCAL_ADMISSION_V1_DOMAIN "AXV2-ADMISSION-v1"
#define AXI_LOCAL_ADMISSION_V1_OK 0
#define AXI_LOCAL_ADMISSION_V1_REFUSED (-1)

enum {
    AXI_LOCAL_ADMISSION_V1_DEV = 1,
    AXI_LOCAL_ADMISSION_V1_PROD = 2
};

enum {
    AXI_LOCAL_ADMISSION_V1_ADMITTED = 0,
    AXI_LOCAL_ADMISSION_V1_REFUSE_INPUT = 1,
    AXI_LOCAL_ADMISSION_V1_REFUSE_PROFILE = 2,
    AXI_LOCAL_ADMISSION_V1_REFUSE_TRUST = 3,
    AXI_LOCAL_ADMISSION_V1_REFUSE_POLICY = 4,
    AXI_LOCAL_ADMISSION_V1_REFUSE_BINDING = 5,
    AXI_LOCAL_ADMISSION_V1_REFUSE_COVERAGE = 6,
    AXI_LOCAL_ADMISSION_V1_REFUSE_CLOCK = 7,
    AXI_LOCAL_ADMISSION_V1_REFUSE_TIME = 8
};

/* Provisioned once per deployment epoch by the owner. Never taken from the
 * requester. All roots/identities must be non-zero; a zero pin is a
 * misprovisioned owner and refuses with INPUT. */
typedef struct {
    uint8_t deployment[16];
    uint8_t trust_snapshot_root[32];
    uint8_t policy_binary[32];
    uint8_t policy_module[32];
    uint8_t policy_producer[32];
    uint8_t policy_iface[32];
} axi_local_admission_v1_pins;

/* Locally measured by the owner at appraisal time. boot is the locally read
 * boot UUID (linux host: boot ID; Beyond: native boot identity once mapped).
 * now_ns is the locally read CLOCK_BOOTTIME nanosecond sample with its
 * availability flag. coverage_complete is the owner-checked single-door
 * coverage/complete-channel bit. profile is explicitly selected by the
 * operator; PROD never falls back to DEV. */
typedef struct {
    uint8_t boot[16];
    uint64_t now_ns;
    uint8_t clock_available;
    uint8_t coverage_complete;
    uint8_t profile;
} axi_local_admission_v1_observed;

typedef struct {
    uint8_t admitted;
    uint8_t refusal;
    uint8_t profile;
    uint8_t context_root[32];
} axi_local_admission_v1_result;

/* Appraise canonical AXV2-ACTION-v1 bytes. Success (admitted) returns 0,
 * refusal returns AXI_LOCAL_ADMISSION_V1_REFUSED. *out is always written
 * when out is non-null, including refusals; a decode/shape failure yields
 * REFUSE_INPUT with a zero context root (nothing unvalidated is bound).
 * Callers supply live, stable spans. No heap, clock, signature or effect.
 * Null out, null action bytes or null pins/observed refuse with INPUT.
 *
 * Order is fixed: INPUT, PROFILE, TRUST, POLICY, BINDING, COVERAGE, CLOCK,
 * TIME. First refusal wins. Context root binds the compared claimed,
 * pinned and observed values (494-byte layout in the .c); INPUT from an
 * undecodable action binds zeros. */
int axi_local_admission_v1_appraise(const void *action_bytes, size_t action_len,
                                    const axi_local_admission_v1_pins *pins,
                                    const axi_local_admission_v1_observed *observed,
                                    axi_local_admission_v1_result *out);

#endif
