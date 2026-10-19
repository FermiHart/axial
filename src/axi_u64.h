/* axial - canonical textual u64 parser. Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 */
#ifndef AXI_U64_H
#define AXI_U64_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    AXI_U64_OK = 0,
    AXI_U64_SYNTAX,   /* invalid argument, policy, or byte grammar */
    AXI_U64_ZERO,     /* canonical zero under positive-only policy */
    AXI_U64_OVERFLOW  /* canonical digits exceed UINT64_MAX */
} axi_u64_status;

typedef enum {
    AXI_U64_ZERO_PERMITTED = 0,
    AXI_U64_POSITIVE_ONLY
} axi_u64_policy;

/* Parses exactly length bytes. On refusal, *out is unchanged. */
axi_u64_status axi_u64_parse(const char *bytes, size_t length,
                             axi_u64_policy policy, uint64_t *out);

typedef enum {
    AXI_ARITH_OK = 0, AXI_ARITH_INVALID, AXI_ARITH_OVERFLOW,
    AXI_ARITH_UNDERFLOW, AXI_ARITH_DIVZERO
} axi_arith_status;
/* Output unchanged on error. Existing + - * / % semantics are unchanged. */
axi_arith_status axi_u64_add_checked(uint64_t a, uint64_t b, uint64_t *out);
axi_arith_status axi_u64_sub_checked(uint64_t a, uint64_t b, uint64_t *out);
axi_arith_status axi_u64_mul_checked(uint64_t a, uint64_t b, uint64_t *out);
axi_arith_status axi_u64_div_checked(uint64_t a, uint64_t b, uint64_t *out);
axi_arith_status axi_u64_mod_checked(uint64_t a, uint64_t b, uint64_t *out);
int axi_u64_budget_fits(uint64_t used, uint64_t cost, uint64_t limit);
int axi_u64_product_fits(uint64_t count, uint64_t size, uint64_t remaining);
#endif /* AXI_U64_H */
