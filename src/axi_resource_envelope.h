#ifndef AXI_RESOURCE_ENVELOPE_H
#define AXI_RESOURCE_ENVELOPE_H

#include <stddef.h>
#include <stdint.h>
#include "axi_handle_table.h"

#define AXI_RESOURCE_ENVELOPE_PROTOCOL "AXI-RESOURCE-ENVELOPE-v1"
#define AXI_RESOURCE_MAX_OWNED_OUTPUTS 1024u

struct axi_mem_account;

typedef uint64_t (*axi_monotonic_now_fn)(void *opaque, int *ok);

typedef enum {
    AXI_RESOURCE_OK = 0,
    AXI_RESOURCE_DEADLINE,
    AXI_RESOURCE_CALLS,
    AXI_RESOURCE_INPUT_BYTES,
    AXI_RESOURCE_OUTPUT_BYTES,
    AXI_RESOURCE_HANDLES,
    AXI_RESOURCE_CHILDREN,
    AXI_RESOURCE_CORRUPT
} axi_resource_result;

typedef struct axi_resource_vector {
    uint64_t calls;
    uint64_t input_bytes;
    uint64_t output_bytes;
    uint64_t handles;
    uint64_t children;
} axi_resource_vector;

typedef struct axi_resource_envelope {
    axi_resource_vector ceiling;
    axi_resource_vector spent;
    axi_resource_vector reserved;
    uint64_t live_handles;
    uint64_t deadline_ns;
    axi_monotonic_now_fn now;
    void *clock_opaque;
    axi_resource_result first_denial;
    axi_handle_table handles;
    intptr_t fs_root_fd;
    uint8_t fs_root_identity[32];
    void *owned_outputs[AXI_RESOURCE_MAX_OWNED_OUTPUTS];
    uint32_t owned_output_count;
} axi_resource_envelope;

void axi_resource_envelope_init(axi_resource_envelope *envelope,
                                const axi_resource_vector *ceiling,
                                uint64_t deadline_ns,
                                axi_monotonic_now_fn now,
                                void *clock_opaque);
axi_resource_result axi_resource_check_deadline(axi_resource_envelope *envelope);
axi_resource_result axi_resource_reserve(axi_resource_envelope *envelope,
                                         const axi_resource_vector *amount);
axi_resource_result axi_resource_commit(axi_resource_envelope *envelope,
                                        const axi_resource_vector *reserved,
                                        const axi_resource_vector *actual);
axi_resource_result axi_resource_release(axi_resource_envelope *envelope,
                                          const axi_resource_vector *amount);
axi_resource_result axi_resource_absorb_child(axi_resource_envelope *envelope,
                                              const axi_resource_vector *spent);
axi_resource_result axi_resource_handle_closed(axi_resource_envelope *envelope);
int axi_resource_envelope_valid(const axi_resource_envelope *envelope);
const char *axi_resource_result_name(axi_resource_result result);
void *axi_resource_output_alloc(axi_resource_envelope *envelope,
                                struct axi_mem_account *account, size_t size);
int axi_resource_outputs_free(axi_resource_envelope *envelope,
                              struct axi_mem_account *account);

#endif
