/* Axial decimal/binary64 conversion.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * This implementation is original integer arithmetic. Its contract is
 * round-to-nearest/ties-to-even, not whatever rounding mode libc inherits.
 * See docs/audit80/frontend.md for the prefix bound and midpoint proof.
 */
#include "axi_numeric.h"
#include <string.h>

#define F64_INFINITY UINT64_C(0x7ff0000000000000)
#define F64_FRACTION UINT64_C(0x000fffffffffffff)
#define F64_HIDDEN   UINT64_C(0x0010000000000000)

static void big_set(axi_numeric_big *a, uint64_t value)
{
    a->n = 0;
    if (value) {
        a->limb[a->n++] = (uint32_t)value;
        if (value >> 32) a->limb[a->n++] = (uint32_t)(value >> 32);
    }
}

/* a = a * factor + add. Bounds are checked before publishing a new limb. */
static int big_mul_add(axi_numeric_big *a, uint32_t factor, uint32_t add)
{
    uint64_t carry = add;
    unsigned i;
    for (i = 0; i < a->n; i++) {
        uint64_t v = (uint64_t)a->limb[i] * factor + carry;
        a->limb[i] = (uint32_t)v;
        carry = v >> 32;
    }
    if (carry) {
        if (a->n == AXI_NUMERIC_LIMBS) return 0;
        a->limb[a->n++] = (uint32_t)carry;
    }
    return 1;
}

/* dst and a do not overlap. Two 32-bit products avoid non-C99 __int128. */
static int big_mul_u64(axi_numeric_big *dst, const axi_numeric_big *a,
                       uint64_t factor)
{
    uint32_t lo = (uint32_t)factor, hi = (uint32_t)(factor >> 32);
    uint64_t carry = 0;
    unsigned i;
    if (!a->n || !factor) { big_set(dst, 0); return 1; }
    if (a->n > AXI_NUMERIC_LIMBS - 2) return 0;
    for (i = 0; i < a->n; i++) {
        uint64_t v = (uint64_t)a->limb[i] * lo + carry;
        dst->limb[i] = (uint32_t)v;
        carry = v >> 32;
    }
    dst->limb[a->n] = (uint32_t)carry;
    carry = 0;
    for (i = 0; i < a->n; i++) {
        uint64_t v = (uint64_t)a->limb[i] * hi + dst->limb[i + 1] + carry;
        dst->limb[i + 1] = (uint32_t)v;
        carry = v >> 32;
    }
    dst->limb[a->n + 1] = (uint32_t)carry;
    dst->n = a->n + 2;
    while (dst->n && !dst->limb[dst->n - 1]) dst->n--;
    return 1;
}

static int big_bits(const axi_numeric_big *a)
{
    uint32_t top;
    int bits;
    if (!a->n) return 0;
    bits = (int)(a->n - 1) * 32;
    top = a->limb[a->n - 1];
    while (top) { top >>= 1; bits++; }
    return bits;
}

/* Read a word of a left shift without constructing an oversized integer. */
static uint32_t shifted_word(const axi_numeric_big *a, unsigned shift,
                             unsigned word)
{
    unsigned whole = shift / 32, part = shift % 32, i;
    uint32_t value = 0;
    if (word < whole) return 0;
    i = word - whole;
    if (i < a->n) value = a->limb[i] << part;
    if (part && i && i - 1 < a->n) value |= a->limb[i - 1] >> (32 - part);
    return value;
}

static int big_cmp_scaled(const axi_numeric_big *a, int ae,
                           const axi_numeric_big *b, int be)
{
    int ab, bb, common;
    unsigned i;
    if (!a->n) return b->n ? -1 : 0;
    if (!b->n) return 1;
    ab = big_bits(a) + ae;
    bb = big_bits(b) + be;
    if (ab != bb) return ab < bb ? -1 : 1;
    common = ae < be ? ae : be;
    i = (unsigned)(ab - common + 31) / 32;
    while (i) {
        uint32_t av, bv;
        i--;
        av = shifted_word(a, (unsigned)(ae - common), i);
        bv = shifted_word(b, (unsigned)(be - common), i);
        if (av != bv) return av < bv ? -1 : 1;
    }
    return 0;
}

/* The prepared decimal is a / b * 2^e10, with b an exact power of five.
 * Compare with the boundary above finite nonnegative binary64 `lower`:
 * (2*M + 1) * 2^(E-1). This also gives the subnormal/normal boundary and
 * the overflow threshold above the largest finite value without infinity
 * arithmetic. The boundary above zero is exactly 2^-1075.
 */
static int decimal_boundary(axi_numeric_workspace *w, int e10, int sticky,
                             uint64_t lower, int *comparison)
{
    uint64_t m = lower & F64_FRACTION;
    unsigned field = (unsigned)(lower >> 52);
    int exponent = -1075, cmp;
    if (field) { m |= F64_HIDDEN; exponent = (int)field - 1076; }
    if (!big_mul_u64(&w->product, &w->b, m * 2 + 1)) return 0;
    cmp = big_cmp_scaled(&w->a, e10, &w->product, exponent);
    /* No binary64 boundary can lie strictly inside an 800-digit decimal
     * prefix bucket: every such boundary has <=768 significant digits.
     * A discarded nonzero suffix therefore matters exactly on equality.
     */
    if (!cmp && sticky) cmp = 1;
    *comparison = cmp;
    return 1;
}

static int decimal_round(axi_numeric_workspace *w, int e10, int sticky,
                         uint64_t *bits)
{
    uint64_t lo = 0, hi = F64_INFINITY;
    int i;
    big_set(&w->b, 1);
    if (e10 >= 0) {
        for (i = 0; i < e10; i++) if (!big_mul_add(&w->a, 5, 0)) return AXI_DECIMAL_INVALID;
    } else {
        for (i = 0; i < -e10; i++) if (!big_mul_add(&w->b, 5, 0)) return AXI_DECIMAL_INVALID;
    }
    while (lo < hi) {
        uint64_t mid = lo + (hi - lo) / 2;
        int cmp;
        if (!decimal_boundary(w, e10, sticky, mid, &cmp)) return AXI_DECIMAL_INVALID;
        if (cmp < 0 || (!cmp && !(mid & 1))) hi = mid;
        else lo = mid + 1;
    }
    if (lo == F64_INFINITY) return AXI_DECIMAL_OVERFLOW;
    *bits = lo;
    return AXI_DECIMAL_OK;
}

int axi_f64_from_decimal(const char *source, size_t len, uint64_t *out_bits,
                         axi_numeric_workspace *w)
{
    size_t i;
    unsigned kept = 0, last_nonzero = 0;
    int point = 0, dotted = 0, significant = 0, sticky = 0;
    uint64_t bits;
    int status;
    if (!source || !len || !out_bits || !w || source[0] < '0' || source[0] > '9')
        return AXI_DECIMAL_INVALID;
    /* Only this scan depends on input length. Saturating `point` cannot
     * lose a later cancellation: integer positions only increase it, and
     * leading fractional zeroes only decrease it before significance.
     */
    for (i = 0; i < len; i++) {
        char c = source[i];
        if (c == '_') continue;
        if (c == '.') {
            if (dotted || i + 1 == len || source[i + 1] < '0' || source[i + 1] > '9')
                return AXI_DECIMAL_INVALID;
            dotted = 1;
            continue;
        }
        if (c < '0' || c > '9') return AXI_DECIMAL_INVALID;
        if (!dotted) {
            if ((significant || c != '0') && point < 4096) point++;
        } else if (!significant && c == '0' && point > -4096) point--;
        if (c != '0') significant = 1;
        if (significant) {
            if (kept < AXI_NUMERIC_DIGITS) {
                w->digits[kept++] = c;
                if (c != '0') last_nonzero = kept;
            } else if (c != '0') sticky = 1;
        }
    }
    if (!dotted) return AXI_DECIMAL_INVALID;
    if (!significant || point < -323) { *out_bits = 0; return AXI_DECIMAL_OK; }
    if (point > 309) return AXI_DECIMAL_OVERFLOW;
    if (!sticky) kept = last_nonzero;
    big_set(&w->a, 0);
    for (i = 0; i < kept; i++)
        if (!big_mul_add(&w->a, 10, (uint32_t)(w->digits[i] - '0')))
            return AXI_DECIMAL_INVALID;
    status = decimal_round(w, point - (int)kept, sticky, &bits);
    if (status == AXI_DECIMAL_OK) *out_bits = bits;
    return status;
}
