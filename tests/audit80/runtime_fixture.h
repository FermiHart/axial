/* Synthetic, reproducible runtime workloads. No production traffic supplied.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0 */
#ifndef AUDIT80_RUNTIME_FIXTURE_H
#define AUDIT80_RUNTIME_FIXTURE_H
#include <axial/axi_embed_v1.h>
#include "axi_contract.h"

typedef struct {
    axb_contract_mod model;
    uint8_t *bytes;
    size_t len;
    uint8_t pk[32];
} runtime80_fixture;

typedef struct {
    axi_embed_v1_eval_request request;
    axi_embed_v1_outcome outcome;
    axi_embed_v1_value args[3];
    uint8_t workspace[256];
    uint32_t kind, value_kind, flags;
    uint64_t bits, fuel;
    const char *payload;
    size_t payload_len;
} runtime80_case;

#define RUNTIME80_CASES 12u
extern const char *const runtime80_case_names[RUNTIME80_CASES];
int runtime80_fixture_init(runtime80_fixture *f, unsigned cells, unsigned laws);
int runtime80_chain_init(runtime80_fixture *f, unsigned depth, unsigned registers);
int runtime80_fixture_resign(runtime80_fixture *f);
void runtime80_fixture_free(runtime80_fixture *f);
int runtime80_context(const runtime80_fixture *f, unsigned profile,
                       axi_embed_v1_context **out);
int runtime80_prepare(const runtime80_fixture *f, unsigned which, unsigned input,
                       runtime80_case *test);
int runtime80_result(const runtime80_case *test);
uint64_t runtime80_now_ns(void);
#endif
