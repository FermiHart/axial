/* Axial compiler invocation budget. SPDX-License-Identifier: LicenseRef-SPL-1.0 */
#ifndef AXI_COMPILE_BUDGET_H
#define AXI_COMPILE_BUDGET_H

#include <stddef.h>
#include <stdint.h>
#include "axi_mem_account.h"

#define AXI_COMPILE_DEFAULT_LIMIT (256u * 1024u * 1024u)

typedef enum {
    AXI_COMPILE_OK = 0,
    AXI_COMPILE_QUOTA,
    AXI_COMPILE_HOST_OOM,
    AXI_COMPILE_OVERFLOW,
    AXI_COMPILE_OWNERSHIP
} axi_compile_failure;

struct axi_compile_block;
typedef struct axi_compile_budget {
    size_t limit, live, peak, fixed, allocations, failed_request;
    axi_compile_failure failure;
    struct axi_compile_block *blocks;
} axi_compile_budget;

/* One caller-owned budget per invocation. It must outlive its AST, sources,
 * returned renderings and backend accounts. Independent budgets share no
 * mutable state. Calls on the same budget must be externally serialized.
 * Accounting includes requested storage, allocation headers, and explicit
 * workspace reservations; it is not a measurement/limit of process RSS,
 * libc's private bookkeeping or the operating system's page cache. */
void axi_compile_budget_init(axi_compile_budget *b, size_t limit);
void axi_compile_budget_destroy(axi_compile_budget *b);
size_t axi_compile_header_bytes(void);
const char *axi_compile_failure_code(const axi_compile_budget *b);
int axi_compile_reserve(axi_compile_budget *b, size_t size);
int axi_compile_release(axi_compile_budget *b, size_t size);
void axi_compile_fail(axi_compile_budget *b, axi_compile_failure cause,
                       size_t request);

/* NULL selects the legacy malloc/free-compatible path. With a budget, every
 * pointer must be released through the same budget. Like C free/realloc,
 * pointers must be live allocation bases, never arbitrary/interior addresses.
 * The private compiler allocator does not replace the runtime account's
 * adversarial-pointer/integrity protocol. Failure is sticky until reinit;
 * cleanup remains available and never erases the first refusal. */
void *axi_compile_malloc(axi_compile_budget *b, size_t size);
void *axi_compile_calloc(axi_compile_budget *b, size_t count, size_t size);
void *axi_compile_realloc(axi_compile_budget *b, void *ptr, size_t size);
char *axi_compile_strdup(axi_compile_budget *b, const char *s);
int axi_compile_free(axi_compile_budget *b, void *ptr);
char *axi_compile_str_unescape(axi_compile_budget *b, const char *lexeme,
                                size_t len, uint32_t *outlen);

/* An internal backend account forwards both allocations and fixed reservations
 * to the same compiler budget. Its host storage stays owned by b. */
void axi_compile_account_init(axi_mem_account *account,
                               axi_compile_budget *b);

#endif
