/* ADR-059 AXV2-09 / D02: AER2 terminal-evidence successor for the narrow
 * local profile. Private C interface; no installed ABI promise. AER1's
 * codec and corpus stay byte-identical and untouched: AER2 is a separate
 * codec/verifier with its own magic, version, domains and the UNKNOWN
 * outcome. See docs/pilot/V2-Evidence-09.md for the profile contract.
 *
 * Wire: magic "AER2", BE32 version 2, 13 axis bytes, 10 roots, fuel and
 * five resource u64s (389-byte body, 493-byte signed envelope with "AERS"
 * trailer carrying BE32 version 2). Root domain "AXI-AER2-BODY-v2" binds
 * with no NUL; signature message is "AXI-AER2-SIGN-v2" plus one NUL plus
 * SHA-256(body).
 *
 * Validity (beyond the AER1 shape it extends): NONE exactly when
 * NOT_ATTEMPTED; UNKNOWN only when ATTEMPTED; every attempted terminal
 * binds nonzero grant, policy and artifact roots; coverage COMPLETE
 * requires a coverage root (unreachable in the narrow profile: local
 * test receipts never claim it).
 */
#ifndef AXI_AER2_V1_H
#define AXI_AER2_V1_H

#include <stddef.h>
#include <stdint.h>

#include "axi_local_action_v1.h"
#include "axi_local_admission_v1.h"
#include "axi_local_attempt_v1.h"
#include "axi_resource_envelope.h"

#define AXI_AER2_V1_ROOTS 10u
#define AXI_AER2_V1_BODY_SIZE (4u + 4u + 13u + (AXI_AER2_V1_ROOTS * 32u) + 8u + (5u * 8u))
#define AXI_AER2_V1_SIGNED_SIZE (AXI_AER2_V1_BODY_SIZE + 104u)
#define AXI_AER2_V1_MAGIC "AER2"
#define AXI_AER2_V1_VERSION 2u
#define AXI_AER2_V1_BODY_DOMAIN "AXI-AER2-BODY-v2"
#define AXI_AER2_V1_SIG_DOMAIN "AXI-AER2-SIGN-v2"

#define AXI_AER2_V1_DECISION_UNPROVEN 0u
#define AXI_AER2_V1_DECISION_ALLOW    1u
#define AXI_AER2_V1_DECISION_DENY     2u

#define AXI_AER2_V1_ATTEMPT_NOT_ATTEMPTED 0u
#define AXI_AER2_V1_ATTEMPT_ATTEMPTED     1u

#define AXI_AER2_V1_OUTCOME_NONE        0u
#define AXI_AER2_V1_OUTCOME_PARTIAL     1u
#define AXI_AER2_V1_OUTCOME_COMMITTED   2u
#define AXI_AER2_V1_OUTCOME_FAILED      3u
#define AXI_AER2_V1_OUTCOME_COMPENSATED 4u
#define AXI_AER2_V1_OUTCOME_UNKNOWN     5u

#define AXI_AER2_V1_COVERAGE_UNKNOWN  0u
#define AXI_AER2_V1_COVERAGE_PARTIAL  1u
#define AXI_AER2_V1_COVERAGE_COMPLETE 2u

#define AXI_AER2_V1_PROFILE_DEV  1u
#define AXI_AER2_V1_PROFILE_PROD 2u

#define AXI_AER2_V1_OPACITY_CLEAR        1u
#define AXI_AER2_V1_OPACITY_CONFIDENTIAL 2u

#define AXI_AER2_V1_MATURITY_DEV      1u
#define AXI_AER2_V1_MATURITY_TESTED   2u
#define AXI_AER2_V1_MATURITY_ATTESTED 3u

typedef struct {
    uint8_t decision;
    uint8_t attempt;
    uint8_t outcome;
    uint8_t evidence;
    uint8_t coverage;
    uint8_t profile;
    uint8_t opacity;
    uint8_t maturity;
    uint8_t has_policy_root;
    uint8_t has_grant_root;
    uint8_t has_coverage_root;
    uint8_t has_episode_root;
    uint8_t has_artifact_root;
    uint8_t principal_root[32];
    uint8_t artifact_root[32];
    uint8_t policy_root[32];
    uint8_t grant_root[32];
    uint8_t action_root[32];
    uint8_t coverage_root[32];
    uint8_t budget_root[32];
    uint8_t episode_root[32];
    uint8_t ledger_tip[32];
    uint8_t journal_tip[32];
    uint64_t fuel_used;
    axi_resource_vector resources;
} axi_aer2_v1;

int axi_aer2_v1_encode(const axi_aer2_v1 *receipt,
                       uint8_t out[AXI_AER2_V1_BODY_SIZE]);
int axi_aer2_v1_decode(axi_aer2_v1 *receipt, const uint8_t *bytes,
                       size_t len);
void axi_aer2_v1_root(const axi_aer2_v1 *receipt, uint8_t out[32]);
int axi_aer2_v1_encode_signed(const axi_aer2_v1 *receipt,
                              const uint8_t seed[32],
                              uint8_t out[AXI_AER2_V1_SIGNED_SIZE]);
int axi_aer2_v1_decode_signed(axi_aer2_v1 *receipt, const uint8_t *bytes,
                              size_t len, const uint8_t trusted_pk[32]);

/* Independent verifier: own reader, own validity, shares no code with the
 * producer or the AER1 line. Verifies framing ("AER2"/2, "AERS"/2),
 * pinned signer key, ed25519 signature and v2 validity; writes the parsed
 * receipt on success. No receipt is produced here. */
int axi_aer2_v1_verify_signed(axi_aer2_v1 *receipt, const uint8_t *bytes,
                              size_t len, const uint8_t trusted_pk[32]);

/* Narrow-profile producer: decision/attempt/outcome evidence from one
 * owner outcome. Pure: no clock, filesystem, signing or effect.
 *
 * - roots: decoded AXV2-ACTION-v1 identities. Principal, action and
 *   budget digests are always required (validity needs them nonzero);
 *   the policy digest is required except for UNPROVEN, which may leave
 *   it unbound.
 * - artifact: the executed-artifact digest, i.e. the policy module
 *   digest from the descriptor (32 nonzero bytes).
 * - grant_root/has_grant: the consumed AG1 grant root (1) or none (0).
 * - admitted: the 06 appraisal result, or NULL when no appraisal ran.
 * - coverage_complete/profile: the owner-observed door bit and profile.
 * - decision: ALLOW, DENY or UNPROVEN. owner_state: one of
 *   NOT_ATTEMPTED/ATTEMPTED/COMMITTED/UNKNOWN/FAILED.
 *
 * Mapping: ALLOW+COMMITTED/FAILED/UNKNOWN terminal or NOT_ATTEMPTED/NONE;
 * in-flight ATTEMPTED refuses (no terminal observed); DENY needs
 * NOT_ATTEMPTED with roots; UNPROVEN needs NOT_ATTEMPTED, roots required,
 * policy optional, grant forbidden. Coverage is PARTIAL with
 * coverage_root=admission context only for admitted PROD with the door
 * bit; otherwise UNKNOWN with no root (COMPLETE never emitted here).
 * Maturity is DEV for dev profile, TESTED for prod fixture -- never
 * ATTESTED from this producer. Returns 0 with *out written, else -1
 * with *out zeroed. */
int axi_aer2_v1_from_attempt(const axi_local_action_roots_v1 *roots,
                             const uint8_t artifact[32],
                             const uint8_t *grant_root, int has_grant,
                             const axi_local_admission_v1_result *admitted,
                             uint8_t coverage_complete, uint8_t profile,
                             uint8_t decision, uint8_t owner_state,
                             axi_aer2_v1 *out);

#endif
