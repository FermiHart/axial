/* axial - isolated explicit memory accounting protocol v1.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 */
#include "axi_mem_account.h"
#include "axi_alloc.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define AXI_MEM_HEADER_MAGIC UINT64_C(0x4158494d454d7631)
#define AXI_MEM_HEADER_FREED UINT64_C(0x4158494d46524545)
#define AXI_MEM_STATE_LIVE  UINT32_C(0x4c495645)
#define AXI_MEM_STATE_FREED UINT32_C(0x46524545)

/* C99 has no max_align_t. A union of every standard scalar alignment class
 * gives the malloc-compatible alignment required for ordinary C99 objects. */
typedef union axi_mem_max_align {
    long double long_double_value;
    long long long_long_value;
    void *object_pointer;
    void (*function_pointer)(void);
} axi_mem_max_align;

struct axi_mem_allocation_header {
    uint64_t magic;
    uint32_t state;
    axi_mem_account *owner;
    size_t charged;
    size_t requested;
    struct axi_mem_allocation_header *previous;
    struct axi_mem_allocation_header *next;
    axi_mem_max_align alignment;
};

static void *default_alloc(void *context, size_t size)
{
    (void)context;
    return axi_malloc(size); /* INV-309 / AXI-INV-096 */
}

static void *default_realloc(void *context, void *ptr, size_t size)
{
    (void)context;
    return axi_realloc(ptr, size); /* INV-309 / AXI-INV-096 */
}

static void default_free(void *context, void *ptr)
{
    (void)context;
    free(ptr);
}

static void clear_failure(axi_mem_account *account)
{
    account->failure = AXI_MEM_FAILURE_NONE;
    account->failed_request = 0;
}

static void fail(axi_mem_account *account, axi_mem_failure_cause cause,
                 size_t request)
{
    account->failure = cause;
    account->failed_request = request;
    if (account->denied_failure == AXI_MEM_FAILURE_NONE) {
        account->denied_failure = cause;
        account->denied_request = request;
    }
}

static void initialize(axi_mem_account *account, size_t limit,
                       const axi_mem_host_allocator *host)
{
    /* INV-507 / AXI-INV-157: every account owns one explicit host and scope. */
    account->limit = limit;
    account->live = 0;
    account->peak = 0;
    account->fixed = 0;
    account->failure = AXI_MEM_FAILURE_NONE;
    account->failed_request = 0;
    account->denied_failure = AXI_MEM_FAILURE_NONE;
    account->denied_request = 0;
    account->host = *host;
    account->active = NULL;
    account->active_count = 0;
}

void axi_mem_account_init(axi_mem_account *account, size_t limit)
{
    axi_mem_host_allocator host;
    if (!account) return;
    host.context = NULL;
    host.alloc = default_alloc;
    host.realloc = default_realloc;
    host.free = default_free;
    initialize(account, limit, &host);
}

int axi_mem_account_init_with_host(axi_mem_account *account, size_t limit,
                                   const axi_mem_host_allocator *host)
{
    if (!account) return 0;
    if (!host || !host->alloc || !host->realloc || !host->free) {
        axi_mem_account_init(account, limit);
        fail(account, AXI_MEM_ACCOUNT_CORRUPTION, 0);
        return 0;
    }
    initialize(account, limit, host);
    return 1;
}

size_t axi_mem_header_bytes(void)
{
    return sizeof(struct axi_mem_allocation_header);
}

int axi_mem_charge_size(size_t payload_size, size_t *charged_size)
{
    if (!charged_size || payload_size > (size_t)-1 - axi_mem_header_bytes())
        return 0;
    *charged_size = axi_mem_header_bytes() + payload_size;
    return 1;
}

static int header_valid(const struct axi_mem_allocation_header *header,
                        const axi_mem_account *account)
{
    size_t expected;
    return header->magic == AXI_MEM_HEADER_MAGIC
        && header->state == AXI_MEM_STATE_LIVE
        && header->owner == account
        && axi_mem_charge_size(header->requested, &expected)
        && header->charged == expected;
}

static int account_valid(const axi_mem_account *account, const void *ptr,
                          struct axi_mem_allocation_header **found)
{
    const struct axi_mem_allocation_header *header;
    const struct axi_mem_allocation_header *previous = NULL;
    struct axi_mem_allocation_header *candidate = NULL;
    size_t total = 0;
    size_t i;

    if (!account || !account->host.alloc || !account->host.realloc
            || !account->host.free || account->live > account->peak
            || account->live > account->limit)
        return 0;
    if (account->active_count > account->live / axi_mem_header_bytes())
        return 0;
    header = account->active;
    for (i = 0; i < account->active_count; i++) {
        size_t before = total;
        if (!header || !header_valid(header, account)
                || header->previous != previous)
            return 0;
        total += header->charged;
        if (total < before) return 0;
        if ((const void *)(header + 1) == ptr)
            candidate = (struct axi_mem_allocation_header *)header;
        previous = header;
        header = header->next;
    }
    if (header || account->fixed > (size_t)-1 - total
            || total + account->fixed != account->live) return 0;
    /* Do not stop at a matching pointer: every header and the total must
     * still validate. Publish the match only after the complete scan. */
    if (found) *found = candidate;
    return 1;
}

static int begin_operation_find(axi_mem_account *account, const void *ptr,
                                 struct axi_mem_allocation_header **found)
{
    if (found) *found = NULL;
    if (!account) return 0;
    clear_failure(account);
    if (!account_valid(account, ptr, found)) {
        fail(account, AXI_MEM_ACCOUNT_CORRUPTION, 0);
        return 0;
    }
    return 1;
}

static int begin_operation(axi_mem_account *account)
{
    return begin_operation_find(account, NULL, NULL);
}

static void *payload(struct axi_mem_allocation_header *header)
{
    return (void *)(header + 1);
}

int axi_mem_reserve(axi_mem_account *account, size_t size)
{
    if (!begin_operation(account)) return 0;
    if (size > account->limit - account->live) {
        fail(account, AXI_MEM_QUOTA_EXCEEDED, size);
        return 0;
    }
    if (size > (size_t)-1 - account->fixed) {
        fail(account, AXI_MEM_SIZE_OVERFLOW, size);
        return 0;
    }
    account->fixed += size;
    account->live += size;
    if (account->live > account->peak) account->peak = account->live;
    return 1;
}

int axi_mem_release(axi_mem_account *account, size_t size)
{
    if (!begin_operation(account)) return 0;
    if (size > account->fixed) {
        fail(account, AXI_MEM_ACCOUNT_CORRUPTION, size);
        return 0;
    }
    account->fixed -= size;
    account->live -= size;
    return 1;
}

static void link_first(axi_mem_account *account,
                       struct axi_mem_allocation_header *header)
{
    header->previous = NULL;
    header->next = account->active;
    if (account->active) account->active->previous = header;
    account->active = header;
    account->active_count++;
}

static void replace_link(axi_mem_account *account,
                         struct axi_mem_allocation_header *new_header,
                         struct axi_mem_allocation_header *previous,
                         struct axi_mem_allocation_header *next)
{
    if (previous) previous->next = new_header;
    else account->active = new_header;
    if (next) next->previous = new_header;
    new_header->previous = previous;
    new_header->next = next;
}

static void unlink_header(axi_mem_account *account,
                          struct axi_mem_allocation_header *header)
{
    if (header->previous) header->previous->next = header->next;
    else account->active = header->next;
    if (header->next) header->next->previous = header->previous;
    account->active_count--;
}

void *axi_mem_alloc(axi_mem_account *account, size_t size)
{
    struct axi_mem_allocation_header *header;
    size_t charged;

    if (!begin_operation(account)) return NULL;
    if (!axi_mem_charge_size(size, &charged)) {
        fail(account, AXI_MEM_SIZE_OVERFLOW, size);
        return NULL;
    }
    if (charged > account->limit - account->live) {
        fail(account, AXI_MEM_QUOTA_EXCEEDED, charged);
        return NULL;
    }

    account->live += charged;
    header = (struct axi_mem_allocation_header *)
        account->host.alloc(account->host.context, charged);
    if (!header) {
        account->live -= charged;
        fail(account, AXI_MEM_HOST_OUT_OF_MEMORY, charged);
        return NULL;
    }
    header->magic = AXI_MEM_HEADER_MAGIC;
    header->state = AXI_MEM_STATE_LIVE;
    header->owner = account;
    header->charged = charged;
    header->requested = size;
    link_first(account, header);
    if (account->live > account->peak) account->peak = account->live;
    return payload(header);
}

void *axi_mem_calloc(axi_mem_account *account, size_t count, size_t size)
{
    size_t total;
    void *ptr;

    if (count != 0 && size > (size_t)-1 / count) {
        if (account) {
            if (!begin_operation(account)) return NULL;
            fail(account, AXI_MEM_SIZE_OVERFLOW, (size_t)-1);
        }
        return NULL;
    }
    total = count * size;
    ptr = axi_mem_alloc(account, total);
    if (ptr) memset(ptr, 0, total);
    return ptr;
}

void *axi_mem_realloc(axi_mem_account *account, void *ptr, size_t size)
{
    struct axi_mem_allocation_header *header;
    struct axi_mem_allocation_header *resized;
    struct axi_mem_allocation_header *previous;
    struct axi_mem_allocation_header *next;
    size_t old_charged;
    size_t new_charged;
    size_t growth;

    if (!ptr) return axi_mem_alloc(account, size);
    if (!begin_operation_find(account, ptr, &header)) return NULL;
    if (!header) {
        fail(account, AXI_MEM_ACCOUNT_CORRUPTION, 0);
        return NULL;
    }
    if (!axi_mem_charge_size(size, &new_charged)) {
        fail(account, AXI_MEM_SIZE_OVERFLOW, size);
        return NULL;
    }
    old_charged = header->charged;
    if (new_charged == old_charged) return ptr;

    if (new_charged > old_charged) {
        growth = new_charged - old_charged;
        if (growth > account->limit - account->live) {
            fail(account, AXI_MEM_QUOTA_EXCEEDED, new_charged);
            return NULL;
        }
        account->live += growth;
    }

    previous = header->previous;
    next = header->next;
    resized = (struct axi_mem_allocation_header *)account->host.realloc(
        account->host.context, header, new_charged);
    if (!resized) {
        if (new_charged > old_charged)
            account->live -= new_charged - old_charged;
        fail(account, AXI_MEM_HOST_OUT_OF_MEMORY, new_charged);
        return NULL;
    }

    replace_link(account, resized, previous, next);
    resized->magic = AXI_MEM_HEADER_MAGIC;
    resized->state = AXI_MEM_STATE_LIVE;
    resized->owner = account;
    resized->charged = new_charged;
    resized->requested = size;
    if (new_charged < old_charged)
        account->live -= old_charged - new_charged;
    if (account->live > account->peak) account->peak = account->live;
    return payload(resized);
}

int axi_mem_free(axi_mem_account *account, void *ptr)
{
    struct axi_mem_allocation_header *header;
    size_t charged;

    if (!begin_operation_find(account, ptr, &header)) return 0;
    if (!ptr) return 1;
    if (!header) {
        fail(account, AXI_MEM_ACCOUNT_CORRUPTION, 0);
        return 0;
    }
    charged = header->charged;
    unlink_header(account, header);
    account->live -= charged;
    header->magic = AXI_MEM_HEADER_FREED;
    header->state = AXI_MEM_STATE_FREED;
    header->owner = NULL;
    header->charged = 0;
    header->requested = 0;
    header->previous = NULL;
    header->next = NULL;
    account->host.free(account->host.context, header);
    return 1;
}
