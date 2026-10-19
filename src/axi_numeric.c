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

/* The prepared decimal is a * 2^e10 for e10 >= 0, otherwise a / b * 2^e10.
 * In the latter case b is an exact power of five; in the former case the
 * formatter may retain its numerator's power-of-five cache in b.
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
    if (e10 >= 0) big_set(&w->product, m * 2 + 1);
    else if (!big_mul_u64(&w->product, &w->b, m * 2 + 1)) return 0;
    cmp = big_cmp_scaled(&w->a, e10, &w->product, exponent);
    /* No binary64 boundary can lie strictly inside an 800-digit decimal
     * prefix bucket: every such boundary has <=768 significant digits.
     * A discarded nonzero suffix therefore matters exactly on equality.
     */
    if (!cmp && sticky) cmp = 1;
    *comparison = cmp;
    return 1;
}

static int decimal_prepare(axi_numeric_workspace *w, int e10)
{
    int i;
    big_set(&w->b, 1);
    if (e10 >= 0) {
        for (i = 0; i < e10; i++) if (!big_mul_add(&w->a, 5, 0)) return 0;
    } else {
        for (i = 0; i < -e10; i++) if (!big_mul_add(&w->b, 5, 0)) return 0;
    }
    return 1;
}

static int decimal_round(axi_numeric_workspace *w, int e10, int sticky,
                         uint64_t *bits)
{
    uint64_t lo = 0, hi = F64_INFINITY;
    if (!decimal_prepare(w, e10)) return AXI_DECIMAL_INVALID;
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

/* Exact short-decimal path. A uint64 coefficient times 10^e is dyadic if
 * all denominator fives cancel. With |e| <= 27 the remaining m * 2^e is
 * normal binary64; round m once to 53 bits using integer remainder bits.
 * If a factor cannot be represented/cancelled, the exact general path
 * remains authoritative. No floating-point "fast approximation" is used.
 */
static int short_dyadic(const char *digits, unsigned nd, int e10,
                        uint64_t *bits)
{
    uint64_t m = 0, scan, significand;
    unsigned i, width = 0;
    int exponent;
    if (nd > 20 || e10 < -27 || e10 > 27) return 0;
    for (i = 0; i < nd; i++) {
        unsigned digit = (unsigned)(digits[i] - '0');
        if (m > (UINT64_MAX - digit) / 10) return 0;
        m = m * 10 + digit;
    }
    if (e10 >= 0) {
        for (int j = 0; j < e10; j++) {
            if (m > UINT64_MAX / 5) return 0;
            m *= 5;
        }
    } else {
        for (int j = 0; j < -e10; j++) {
            if (m % 5) return 0;
            m /= 5;
        }
    }
    if (!m) return 0; /* zero is handled before this helper */
    for (scan = m; scan; scan >>= 1) width++;
    exponent = e10 + (int)width - 1;
    if (width <= 53) significand = m << (53 - width);
    else {
        unsigned shift = width - 53;
        uint64_t remainder = m & ((UINT64_C(1) << shift) - 1);
        uint64_t half = UINT64_C(1) << (shift - 1);
        significand = m >> shift;
        if (remainder > half || (remainder == half && (significand & 1))) significand++;
        if (significand == (F64_HIDDEN << 1)) { significand >>= 1; exponent++; }
    }
    *bits = ((uint64_t)(exponent + 1023) << 52) | (significand & F64_FRACTION);
    return 1;
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
    if (!sticky && short_dyadic(w->digits, kept, point - (int)kept, &bits)) {
        *out_bits = bits;
        return AXI_DECIMAL_OK;
    }
    big_set(&w->a, 0);
    for (i = 0; i < kept; i++)
        if (!big_mul_add(&w->a, 10, (uint32_t)(w->digits[i] - '0')))
            return AXI_DECIMAL_INVALID;
    status = decimal_round(w, point - (int)kept, sticky, &bits);
    if (status == AXI_DECIMAL_OK) *out_bits = bits;
    return status;
}

static uint32_t big_div_small(axi_numeric_big *a, uint32_t divisor)
{
    uint64_t remainder = 0;
    unsigned i = a->n;
    while (i) {
        uint64_t v;
        i--;
        v = (remainder << 32) | a->limb[i];
        a->limb[i] = (uint32_t)(v / divisor);
        remainder = v % divisor;
    }
    while (a->n && !a->limb[a->n - 1]) a->n--;
    return (uint32_t)remainder;
}

/* Does coefficient * 10^exponent round to `bits`? A formatter knows its
 * target, so the two exact boundaries suffice instead of another search.
 * This also handles the unequal gaps on either side of powers of two.
 */
static int decimal_matches(axi_numeric_workspace *w, uint64_t coefficient,
                            int exponent, uint64_t bits)
{
    int cmp;
    /* The formatter retains 5^abs(exponent) in b across both candidates
     * and updates it once between precisions. For positive exponents it
     * scales the numerator; for negative exponents it is the denominator.
     */
    if (exponent >= 0) {
        if (!big_mul_u64(&w->a, &w->b, coefficient)) return 0;
    } else big_set(&w->a, coefficient);
    if (!decimal_boundary(w, exponent, 0, bits - 1, &cmp)) return 0;
    if (cmp < 0 || (!cmp && (bits & 1))) return 0;
    if (!decimal_boundary(w, exponent, 0, bits, &cmp)) return 0;
    return cmp < 0 || (!cmp && !(bits & 1));
}

/* Convert the exact finite dyadic to significant decimal digits. Removing
 * factors of two first keeps integral values and simple fractions small.
 * All digits fit the same workspace used by the reader's retained prefix.
 */
static int exact_digits(axi_numeric_workspace *w, uint64_t bits,
                         unsigned *count, int *point)
{
    uint64_t m = bits & F64_FRACTION;
    unsigned field = (unsigned)(bits >> 52), n = 0, i;
    int e = -1074, factor;
    if (field) { m |= F64_HIDDEN; e = (int)field - 1075; }
    while (e < 0 && !(m & 1)) { m >>= 1; e++; }
    big_set(&w->a, m);
    factor = e < 0 ? -e : e;
    for (int j = 0; j < factor; j++)
        if (!big_mul_add(&w->a, e < 0 ? 5 : 2, 0)) return 0;
    while (w->a.n) {
        uint32_t chunk = big_div_small(&w->a, UINT32_C(1000000000));
        unsigned width = w->a.n ? 9 : 0;
        /* Extract nine decimal digits per full-width division. Nonleading
         * chunks retain their zero padding; only the most significant
         * chunk may be shorter. No extra array or approximate arithmetic.
         */
        do {
            if (n == AXI_NUMERIC_DIGITS) return 0;
            w->digits[n++] = (char)('0' + chunk % 10);
            chunk /= 10;
            if (width) width--;
        } while (chunk || width);
    }
    for (i = 0; i < n / 2; i++) {
        char c = w->digits[i];
        w->digits[i] = w->digits[n - i - 1];
        w->digits[n - i - 1] = c;
    }
    *point = (int)n + (e < 0 ? e : 0);
    while (n > 1 && w->digits[n - 1] == '0') n--;
    *count = n;
    return 1;
}

static int write_decimal(axi_numeric_workspace *w, uint64_t coefficient,
                          int exponent, int negative, size_t *len)
{
    unsigned nd = 0;
    size_t used = 0;
    int point, i;
    while (coefficient && coefficient % 10 == 0) { coefficient /= 10; exponent++; }
    do {
        if (nd == sizeof w->small) return 0;
        w->small[nd++] = (char)('0' + coefficient % 10);
        coefficient /= 10;
    } while (coefficient);
    point = (int)nd + exponent;
    /* The shortest binary64 representation needs <=17 significant digits
     * and a decimal point in [-323,309]. Leave explicit slack and check it
     * before writing, rather than relying on a caller's buffer estimate.
     */
    if (point < -323 || point > 309 || nd > 17) return 0;
    if (negative) w->text[used++] = '-';
    if (point <= 0) {
        w->text[used++] = '0'; w->text[used++] = '.';
        for (i = 0; i < -point; i++) w->text[used++] = '0';
        for (i = (int)nd - 1; i >= 0; i--) w->text[used++] = w->small[i];
    } else {
        for (i = 0; i < point; i++)
            w->text[used++] = (unsigned)i < nd ? w->small[nd - (unsigned)i - 1] : '0';
        w->text[used++] = '.';
        if ((unsigned)point >= nd) w->text[used++] = '0';
        else for (i = point; (unsigned)i < nd; i++)
            w->text[used++] = w->small[nd - (unsigned)i - 1];
    }
    if (used >= sizeof w->text) return 0;
    w->text[used] = '\0';
    *len = used;
    return 1;
}

int axi_f64_to_decimal(uint64_t bits, axi_numeric_workspace *w,
                       const char **text, size_t *len)
{
    uint64_t magnitude = bits & UINT64_C(0x7fffffffffffffff), prefix = 0;
    unsigned nd, precision;
    int point, negative = (int)(bits >> 63);
    size_t size;
    if (!w || !text || !len || magnitude >= F64_INFINITY) return AXI_DECIMAL_INVALID;
    if (!magnitude) {
        if (!write_decimal(w, 0, 0, negative, &size)) return AXI_DECIMAL_INVALID;
        *text = w->text; *len = size;
        return AXI_DECIMAL_OK;
    }
    if (!exact_digits(w, magnitude, &nd, &point)) return AXI_DECIMAL_INVALID;
    big_set(&w->b, 1);
    for (int j = 0, power = point > 0 ? point - 1 : 1 - point; j < power; j++)
        if (!big_mul_add(&w->b, 5, 0)) return AXI_DECIMAL_INVALID;
    for (precision = 1; precision <= 17; precision++) {
        uint64_t first, second;
        int up = 0, exponent = point - (int)precision;
        if (precision > 1) {
            if (exponent >= 0) {
                if (big_div_small(&w->b, 5)) return AXI_DECIMAL_INVALID;
            } else if (!big_mul_add(&w->b, 5, 0)) return AXI_DECIMAL_INVALID;
        }
        if (precision <= nd) prefix = prefix * 10 + (uint64_t)(w->digits[precision - 1] - '0');
        else prefix *= 10;
        if (precision < nd) {
            char next = w->digits[precision];
            up = next > '5';
            if (next == '5') {
                unsigned j;
                up = (int)(prefix & 1);
                for (j = precision + 1; j < nd && !up; j++) if (w->digits[j] != '0') up = 1;
            }
        }
        first = prefix + (unsigned)up;
        second = prefix + (unsigned)!up;
        /* An interval containing the exact value can contain a decimal on
         * this grid only if it contains one of its two adjacent candidates.
         * Try the closest first, resolving equal distance to even. The
         * other side matters at asymmetric binary rounding intervals.
         */
        if (decimal_matches(w, first, exponent, magnitude)) {
            if (!write_decimal(w, first, exponent, negative, &size)) return AXI_DECIMAL_INVALID;
            *text = w->text; *len = size;
            return AXI_DECIMAL_OK;
        }
        if (precision < nd && decimal_matches(w, second, exponent, magnitude)) {
            if (!write_decimal(w, second, exponent, negative, &size)) return AXI_DECIMAL_INVALID;
            *text = w->text; *len = size;
            return AXI_DECIMAL_OK;
        }
    }
    return AXI_DECIMAL_INVALID; /* 17 digits suffice for every finite binary64. */
}
