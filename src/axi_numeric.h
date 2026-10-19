/* Axial decimal/binary64 conversion — integer-only, locale-independent.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 */
#ifndef AXI_NUMERIC_H
#define AXI_NUMERIC_H

#include <stddef.h>
#include <stdint.h>

/* Every binary64 rounding boundary has at most 768 significant decimal
 * digits. The 800-digit prefix plus a nonzero-tail bit is therefore exact
 * for every rounding decision, even when source literals are much longer.
 * 96 limbs hold the largest retained numerator and 5^1123 times a 54-bit
 * boundary significand (< 2664 bits). Shifts are compared virtually.
 */
#define AXI_NUMERIC_DIGITS 800
#define AXI_NUMERIC_LIMBS 96
#define AXI_F64_DECIMAL_CAP 384

typedef struct {
    uint32_t limb[AXI_NUMERIC_LIMBS];
    unsigned n;
} axi_numeric_big;

/* Explicit, caller-owned scratch. No heap allocation, recursion, global
 * mutable tables, floating-point operations, or input-sized buffers.
 * The formatter and parser reuse the same objects; no nested conversion
 * retains another workspace. Numeric helper functions have no other arrays.
 */
typedef struct {
    axi_numeric_big a, b, product;
    char digits[AXI_NUMERIC_DIGITS];
    char text[AXI_F64_DECIMAL_CAP];
    char small[24];
} axi_numeric_workspace;

#define AXI_NUMERIC_SCRATCH_BYTES (sizeof(axi_numeric_workspace))

enum {
    AXI_DECIMAL_OK = 0,
    AXI_DECIMAL_INVALID = 1,
    AXI_DECIMAL_OVERFLOW = 2
};

/* Read exactly [0-9][0-9_]* '.' [0-9][0-9_]*, with no sign or exponent.
 * Round once to binary64, nearest with ties to even. Gradual underflow may
 * produce +0; overflow refuses instead of returning infinity. On refusal
 * out_bits is unchanged. Source, output, and scratch must be disjoint;
 * workspace and out_bits are required. All results are raw IEEE bits, so
 * this function does not depend on the host's floating-point environment.
 */
int axi_f64_from_decimal(const char *source, size_t len, uint64_t *out_bits,
                         axi_numeric_workspace *workspace);

#endif
