/* axial - internal allocation door and deterministic CA04 failpoints.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 */
#ifndef AXI_ALLOC_H
#define AXI_ALLOC_H

#include <stddef.h>

void *axi_malloc(size_t size);
void *axi_calloc(size_t count, size_t size);
void *axi_realloc(void *ptr, size_t size);
char *axi_strdup(const char *s);

/* Test guard control: setup may be outside the allocation interval under
 * proof. These are no-ops unless AXI_ALLOC_FAILPOINT is compiled in. */
void axi_alloc_failpoint_suspend(void);
void axi_alloc_failpoint_resume(void);

#endif /* AXI_ALLOC_H */
