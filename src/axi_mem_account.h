/* axial - isolated explicit memory accounting protocol v1.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 */
#ifndef AXI_MEM_ACCOUNT_H
#define AXI_MEM_ACCOUNT_H

#include <stddef.h>

#define AXI_MEM_ACCOUNT_PROTOCOL_ID "AXI-MEM-ACCOUNT-v1"

typedef enum axi_mem_failure_cause {
    AXI_MEM_FAILURE_NONE = 0,
    AXI_MEM_QUOTA_EXCEEDED,
    AXI_MEM_HOST_OUT_OF_MEMORY,
    AXI_MEM_SIZE_OVERFLOW,
    AXI_MEM_ACCOUNT_CORRUPTION
} axi_mem_failure_cause;

typedef void *(*axi_mem_host_alloc_fn)(void *context, size_t size);
typedef void *(*axi_mem_host_realloc_fn)(void *context, void *ptr, size_t size);
typedef void (*axi_mem_host_free_fn)(void *context, void *ptr);

typedef struct axi_mem_host_allocator {
    void *context;
    axi_mem_host_alloc_fn alloc;
    axi_mem_host_realloc_fn realloc;
    axi_mem_host_free_fn free;
} axi_mem_host_allocator;

struct axi_mem_allocation_header;

typedef struct axi_mem_account {
    size_t limit;
    size_t live;
    size_t peak;
    size_t fixed;
    axi_mem_failure_cause failure;
    size_t failed_request;
    axi_mem_failure_cause denied_failure;
    size_t denied_request;
    axi_mem_host_allocator host;
    struct axi_mem_allocation_header *active;
    size_t active_count;
} axi_mem_account;

/* Host callbacks must have malloc/realloc/free semantics, return storage aligned
 * for every ordinary C99 object, and must not re-enter the same account. */
void axi_mem_account_init(axi_mem_account *account, size_t limit);
int axi_mem_account_init_with_host(axi_mem_account *account, size_t limit,
                                   const axi_mem_host_allocator *host);

size_t axi_mem_header_bytes(void);
int axi_mem_charge_size(size_t payload_size, size_t *charged_size);

/* Charge storage whose host lifetime is external to this allocator (stack,
 * TLS, caller-independent fixed records). Release must use the exact charge. */
int axi_mem_reserve(axi_mem_account *account, size_t size);
int axi_mem_release(axi_mem_account *account, size_t size);

/* NULL indicates refusal; account->failure names the cause. axi_mem_free
 * returns zero for ownership/corruption refusal and is a no-op for NULL. */
void *axi_mem_alloc(axi_mem_account *account, size_t size);
void *axi_mem_calloc(axi_mem_account *account, size_t count, size_t size);
void *axi_mem_realloc(axi_mem_account *account, void *ptr, size_t size);
int axi_mem_free(axi_mem_account *account, void *ptr);

#endif /* AXI_MEM_ACCOUNT_H */
