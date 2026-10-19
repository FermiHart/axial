/* axial - canonical textual u64 parser. Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 */
#include "axi_u64.h"

#include <stdint.h>

axi_u64_status axi_u64_parse(const char *bytes, size_t length,
                             axi_u64_policy policy, uint64_t *out)
{
    /* INV-507 / AXI-INV-157: one length-aware door defines textual u64. */
    uint64_t value = 0;
    int overflow = 0;
    size_t i;

    if (bytes == NULL || out == NULL || length == 0)
        return AXI_U64_SYNTAX;
    if (policy != AXI_U64_ZERO_PERMITTED &&
        policy != AXI_U64_POSITIVE_ONLY)
        return AXI_U64_SYNTAX;
    if (length > 1 && (unsigned char)bytes[0] == (unsigned char)'0')
        return AXI_U64_SYNTAX;

    for (i = 0; i < length; i++) {
        unsigned char c = (unsigned char)bytes[i];
        uint64_t digit;

        if (c < (unsigned char)'0' || c > (unsigned char)'9')
            return AXI_U64_SYNTAX;
        digit = (uint64_t)(c - (unsigned char)'0');
        if (!overflow) {
            if (value > (UINT64_MAX - digit) / UINT64_C(10)) {
                overflow = 1;
            } else {
                value = value * UINT64_C(10) + digit;
            }
        }
    }

    if (overflow) return AXI_U64_OVERFLOW;
    if (value == 0 && policy == AXI_U64_POSITIVE_ONLY)
        return AXI_U64_ZERO;
    *out = value;
    return AXI_U64_OK;
}

/* AX30-MATH: explicit arithmetic status; no silent sentinel or saturation. */
axi_arith_status axi_u64_add_checked(uint64_t a, uint64_t b, uint64_t *out)
{
    if (!out) return AXI_ARITH_INVALID;
    if (b > UINT64_MAX - a) return AXI_ARITH_OVERFLOW;
    *out = a + b; return AXI_ARITH_OK;
}
axi_arith_status axi_u64_sub_checked(uint64_t a, uint64_t b, uint64_t *out)
{
    if (!out) return AXI_ARITH_INVALID;
    if (b > a) return AXI_ARITH_UNDERFLOW;
    *out = a - b; return AXI_ARITH_OK;
}
axi_arith_status axi_u64_mul_checked(uint64_t a, uint64_t b, uint64_t *out)
{
    if (!out) return AXI_ARITH_INVALID;
    if (a && b > UINT64_MAX / a) return AXI_ARITH_OVERFLOW;
    *out = a * b; return AXI_ARITH_OK;
}
axi_arith_status axi_u64_div_checked(uint64_t a, uint64_t b, uint64_t *out)
{
    if (!out) return AXI_ARITH_INVALID;
    if (!b) return AXI_ARITH_DIVZERO;
    *out = a / b; return AXI_ARITH_OK;
}
axi_arith_status axi_u64_mod_checked(uint64_t a, uint64_t b, uint64_t *out)
{
    if (!out) return AXI_ARITH_INVALID;
    if (!b) return AXI_ARITH_DIVZERO;
    *out = a % b; return AXI_ARITH_OK;
}
int axi_u64_budget_fits(uint64_t used, uint64_t cost, uint64_t limit)
{
    return used <= limit && cost <= limit - used;
}
int axi_u64_product_fits(uint64_t count, uint64_t size, uint64_t remaining)
{
    return !count || size <= remaining / count;
}
