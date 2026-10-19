#ifndef AXI_COVERAGE_V1_H
#define AXI_COVERAGE_V1_H

#include <stddef.h>
#include <stdint.h>

#include "axi_effect.h"

#define AXI_COVERAGE_V1_DOMAIN "AXI-COVERAGE-MANIFEST-v1"
#define AXI_COVERAGE_V1_CHANNEL_DOMAIN "AXI-COVERAGE-CHANNEL-v1"
#define AXI_COVERAGE_V1_MAX_CHANNEL 64u

enum {
    AXI_COVERAGE_V1_CLASS_HOST_EFFECT = 1
};

enum {
    AXI_COVERAGE_V1_SUPPORT_SUPPORTED = 1
};

enum {
    AXI_COVERAGE_V1_OPACITY_CLEAR = 1
};

enum {
    AXI_COVERAGE_V1_MATURITY_CHECKED = 1
};

typedef struct {
    uint8_t action_class;
    char door[AXI_CAPNAME];
    uint8_t receipt_required;
    uint8_t opacity;
    uint8_t support;
    uint8_t maturity;
} axi_coverage_v1_row;

typedef struct {
    uint8_t channel_id[32];
    uint64_t high_water;
    uint8_t terminal[AXI_COVERAGE_V1_MAX_CHANNEL];
} axi_coverage_v1_channel;

/* Channel state is caller-owned. Operations require a nonzero ID, bounded
 * high_water, binary active terminals, and zero unused slots. Malformed
 * restored state refuses (has_gap returns 1); it cannot pre-complete a
 * future reservation. Callers still own synchronization and authenticity. */

size_t axi_coverage_v1_manifest_count(void);
const axi_coverage_v1_row *axi_coverage_v1_manifest_at(size_t index);
int axi_coverage_v1_classify(const char *door, axi_coverage_v1_row *out);
int axi_coverage_v1_verify_runtime(void);
int axi_coverage_v1_runtime_root(uint8_t out[32]);
void axi_coverage_v1_channel_init(axi_coverage_v1_channel *channel,
                                  const uint8_t channel_id[32]);
int axi_coverage_v1_channel_reserve(axi_coverage_v1_channel *channel,
                                    uint64_t *seq_out);
int axi_coverage_v1_channel_terminal(axi_coverage_v1_channel *channel,
                                     uint64_t seq);
int axi_coverage_v1_channel_has_gap(const axi_coverage_v1_channel *channel);
int axi_coverage_v1_channel_root(const axi_coverage_v1_channel *channel,
                                 uint8_t out[32]);

#endif /* AXI_COVERAGE_V1_H */
