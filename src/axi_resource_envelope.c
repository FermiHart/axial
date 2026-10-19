#include "axi_resource_envelope.h"
#include "axi_mem_account.h"

#include <string.h>

static axi_resource_result deny(axi_resource_envelope *envelope,
                                axi_resource_result result)
{
    if (envelope && envelope->first_denial == AXI_RESOURCE_OK)
        envelope->first_denial = result;
    return result;
}

static int add_fits(uint64_t spent, uint64_t reserved, uint64_t add,
                    uint64_t ceiling)
{
    return spent <= ceiling && reserved <= ceiling - spent
        && add <= ceiling - spent - reserved;
}

static int sub_fits(uint64_t value, uint64_t amount)
{
    return amount <= value;
}

void axi_resource_envelope_init(axi_resource_envelope *envelope,
                                const axi_resource_vector *ceiling,
                                uint64_t deadline_ns,
                                axi_monotonic_now_fn now,
                                void *clock_opaque)
{
    if (!envelope) return;
    memset(envelope, 0, sizeof *envelope);
    if (ceiling) envelope->ceiling = *ceiling;
    envelope->deadline_ns = deadline_ns;
    envelope->now = now;
    envelope->clock_opaque = clock_opaque;
    axi_handle_table_init(&envelope->handles);
}

axi_resource_result axi_resource_check_deadline(axi_resource_envelope *envelope)
{
    int ok = 0;
    uint64_t now;
    if (!envelope || !envelope->now || envelope->deadline_ns == 0)
        return deny(envelope, AXI_RESOURCE_CORRUPT);
    if (envelope->first_denial != AXI_RESOURCE_OK)
        return envelope->first_denial;
    now = envelope->now(envelope->clock_opaque, &ok);
    if (!ok) return deny(envelope, AXI_RESOURCE_CORRUPT);
    if (now >= envelope->deadline_ns)
        return deny(envelope, AXI_RESOURCE_DEADLINE);
    return AXI_RESOURCE_OK;
}

axi_resource_result axi_resource_reserve(axi_resource_envelope *envelope,
                                         const axi_resource_vector *amount)
{
    axi_resource_result result;
    if (!envelope || !amount) return deny(envelope, AXI_RESOURCE_CORRUPT);
    result = axi_resource_check_deadline(envelope);
    if (result != AXI_RESOURCE_OK) return result;
#define RESERVE_FIELD(field, code) \
    if (!add_fits(envelope->spent.field, envelope->reserved.field, \
                  amount->field, envelope->ceiling.field)) \
        return deny(envelope, code)
    RESERVE_FIELD(calls, AXI_RESOURCE_CALLS);
    RESERVE_FIELD(input_bytes, AXI_RESOURCE_INPUT_BYTES);
    RESERVE_FIELD(output_bytes, AXI_RESOURCE_OUTPUT_BYTES);
    RESERVE_FIELD(children, AXI_RESOURCE_CHILDREN);
#undef RESERVE_FIELD
    if (!add_fits(envelope->live_handles, envelope->reserved.handles,
                  amount->handles, envelope->ceiling.handles))
        return deny(envelope, AXI_RESOURCE_HANDLES);
    envelope->reserved.calls += amount->calls;
    envelope->reserved.input_bytes += amount->input_bytes;
    envelope->reserved.output_bytes += amount->output_bytes;
    envelope->reserved.handles += amount->handles;
    envelope->reserved.children += amount->children;
    return AXI_RESOURCE_OK;
}

axi_resource_result axi_resource_commit(axi_resource_envelope *envelope,
                                        const axi_resource_vector *reserved,
                                        const axi_resource_vector *actual)
{
    if (!envelope || !reserved || !actual)
        return deny(envelope, AXI_RESOURCE_CORRUPT);
#define COMMIT_CHECK(field) \
    if (!sub_fits(envelope->reserved.field, reserved->field) \
            || actual->field > reserved->field \
            || !add_fits(envelope->spent.field, 0, actual->field, \
                         envelope->ceiling.field)) \
        return deny(envelope, AXI_RESOURCE_CORRUPT)
    COMMIT_CHECK(calls);
    COMMIT_CHECK(input_bytes);
    COMMIT_CHECK(output_bytes);
    COMMIT_CHECK(children);
#undef COMMIT_CHECK
    if (!sub_fits(envelope->reserved.handles, reserved->handles)
            || actual->handles > reserved->handles
            || !add_fits(envelope->live_handles, 0, actual->handles,
                         envelope->ceiling.handles)
            || actual->handles > UINT64_MAX - envelope->spent.handles)
        return deny(envelope, AXI_RESOURCE_CORRUPT);
#define COMMIT_FIELD(field) \
    envelope->reserved.field -= reserved->field; \
    envelope->spent.field += actual->field
    COMMIT_FIELD(calls);
    COMMIT_FIELD(input_bytes);
    COMMIT_FIELD(output_bytes);
    COMMIT_FIELD(children);
#undef COMMIT_FIELD
    envelope->reserved.handles -= reserved->handles;
    envelope->spent.handles += actual->handles;
    envelope->live_handles += actual->handles;
    return envelope->first_denial;
}

axi_resource_result axi_resource_release(axi_resource_envelope *envelope,
                                          const axi_resource_vector *amount)
{
    if (!envelope || !amount) return deny(envelope, AXI_RESOURCE_CORRUPT);
#define RELEASE_CHECK(field) \
    if (!sub_fits(envelope->reserved.field, amount->field)) \
        return deny(envelope, AXI_RESOURCE_CORRUPT)
    RELEASE_CHECK(calls);
    RELEASE_CHECK(input_bytes);
    RELEASE_CHECK(output_bytes);
    RELEASE_CHECK(handles);
    RELEASE_CHECK(children);
#undef RELEASE_CHECK
    envelope->reserved.calls -= amount->calls;
    envelope->reserved.input_bytes -= amount->input_bytes;
    envelope->reserved.output_bytes -= amount->output_bytes;
    envelope->reserved.handles -= amount->handles;
    envelope->reserved.children -= amount->children;
    return envelope->first_denial;
}

axi_resource_result axi_resource_absorb_child(axi_resource_envelope *envelope,
                                              const axi_resource_vector *spent)
{
    if (!envelope || !spent) return deny(envelope, AXI_RESOURCE_CORRUPT);
#define ABSORB_CHECK(field, code) \
    if (!add_fits(envelope->spent.field, envelope->reserved.field, \
                  spent->field, envelope->ceiling.field)) \
        return deny(envelope, code)
    ABSORB_CHECK(calls, AXI_RESOURCE_CALLS);
    ABSORB_CHECK(input_bytes, AXI_RESOURCE_INPUT_BYTES);
    ABSORB_CHECK(output_bytes, AXI_RESOURCE_OUTPUT_BYTES);
    ABSORB_CHECK(children, AXI_RESOURCE_CHILDREN);
#undef ABSORB_CHECK
    if (spent->handles > UINT64_MAX - envelope->spent.handles)
        return deny(envelope, AXI_RESOURCE_CORRUPT);
    envelope->spent.calls += spent->calls;
    envelope->spent.input_bytes += spent->input_bytes;
    envelope->spent.output_bytes += spent->output_bytes;
    envelope->spent.handles += spent->handles;
    envelope->spent.children += spent->children;
    return envelope->first_denial;
}

axi_resource_result axi_resource_handle_closed(axi_resource_envelope *envelope)
{
    if (!envelope || envelope->live_handles == 0)
        return deny(envelope, AXI_RESOURCE_CORRUPT);
    envelope->live_handles--;
    return envelope->first_denial;
}

int axi_resource_envelope_valid(const axi_resource_envelope *envelope)
{
    if (!envelope || !envelope->now || envelope->deadline_ns == 0) return 0;
#define VALID_FIELD(field) \
    if (!add_fits(envelope->spent.field, envelope->reserved.field, 0, \
                  envelope->ceiling.field)) return 0
    VALID_FIELD(calls);
    VALID_FIELD(input_bytes);
    VALID_FIELD(output_bytes);
    VALID_FIELD(children);
#undef VALID_FIELD
    if (!add_fits(envelope->live_handles, envelope->reserved.handles, 0,
                  envelope->ceiling.handles)) return 0;
    return 1;
}

const char *axi_resource_result_name(axi_resource_result result)
{
    switch (result) {
    case AXI_RESOURCE_OK: return "OK";
    case AXI_RESOURCE_DEADLINE: return "DEADLINE";
    case AXI_RESOURCE_CALLS: return "CALLS";
    case AXI_RESOURCE_INPUT_BYTES: return "INPUT_BYTES";
    case AXI_RESOURCE_OUTPUT_BYTES: return "OUTPUT_BYTES";
    case AXI_RESOURCE_HANDLES: return "HANDLES";
    case AXI_RESOURCE_CHILDREN: return "CHILDREN";
    default: return "CORRUPT";
    }
}

void *axi_resource_output_alloc(axi_resource_envelope *envelope,
                                axi_mem_account *account, size_t size)
{
    void *output;
    if (!envelope || !account || size == 0
            || envelope->owned_output_count >= AXI_RESOURCE_MAX_OWNED_OUTPUTS)
        return NULL;
    output = axi_mem_alloc(account, size);
    if (!output) return NULL;
    envelope->owned_outputs[envelope->owned_output_count++] = output;
    return output;
}

int axi_resource_outputs_free(axi_resource_envelope *envelope,
                              axi_mem_account *account)
{
    int ok = 1;
    if (!envelope || !account) return 0;
    while (envelope->owned_output_count) {
        void *output = envelope->owned_outputs[--envelope->owned_output_count];
        envelope->owned_outputs[envelope->owned_output_count] = NULL;
        if (!axi_mem_free(account, output)) ok = 0;
    }
    return ok;
}
