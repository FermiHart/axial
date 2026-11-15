/* Independent checked-arithmetic TEST oracle, not the Axial C VM.
 * Requires a compiler supporting signed __int128 (GCC/Clang).
 * Copyright (c) 2026 Fermi Hart <contact@fermihart.com>
 * SPDX-License-Identifier: LicenseRef-SPL-1.0 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#ifndef __SIZEOF_INT128__
#error "games numeric oracle requires __int128"
#endif
typedef __int128 wide;
static int parse(const char *s, wide *out) {
    size_t len = strlen(s), i = 0;
    int negative = 0;
    wide n = 0;
    if (!len || len > 20) return 0;
    if (s[i] == '-') { negative = 1; ++i; }
    if (i == len) return 0;
    if (s[i] == '0' && (negative || len - i != 1)) return 0;
    for (; i < len; ++i) {
        if (s[i] < '0' || s[i] > '9') return 0;
        n = n * 10 + (s[i] - '0');
    }
    if (negative) n = -n;
    if (n < (wide)INT64_MIN || n > (wide)INT64_MAX) return 0;
    *out = n;
    return 1;
}
static wide power(int scale) {
    wide n = 1;
    while (scale-- > 0) n *= 10;
    return n;
}
static void run(const char *op, const char *a, const char *b, const char *s, const char *t) {
    wide x, y, digits, target, result;
    int fixed = !strcmp(op, "fixedMul") || !strcmp(op, "fixedDiv");
    int rescale = !strcmp(op, "rescale");
    if (!parse(s, &digits) || !parse(t, &target)) { puts("ERR:AXN-INPUT"); return; }
    if ((fixed || rescale) && (digits < 0 || digits > 9 || (rescale && (target < 0 || target > 9)))) {
        puts("ERR:AXN-INPUT"); return;
    }
    if (!parse(a, &x) || !parse(b, &y)) { puts("ERR:AXN-INPUT"); return; }
    if (!strcmp(op, "add")) result = x + y;
    else if (!strcmp(op, "sub")) result = x - y;
    else if (!strcmp(op, "mul")) result = x * y;
    else if (!strcmp(op, "div") || !strcmp(op, "fixedDiv")) {
        if (y == 0) { puts("ERR:AXN-ZERO"); return; }
        result = (fixed ? x * power((int)digits) : x) / y;
    } else if (!strcmp(op, "fixedMul")) result = (x * y) / power((int)digits);
    else if (rescale) result = target >= digits ? x * power((int)(target - digits)) : x / power((int)(digits - target));
    else { puts("ERR:AXN-INPUT"); return; }
    if (result < (wide)INT64_MIN || result > (wide)INT64_MAX) puts("ERR:AXN-OVERFLOW");
    else printf("OK:%" PRId64 "\n", (int64_t)result);
}
int main(void) {
    char line[256], op[16], a[64], b[64], s[32], t[32], extra;
    while (fgets(line, sizeof line, stdin)) {
        if (!strchr(line, '\n') && !feof(stdin)) return 2;
        if (sscanf(line, "%15s %63s %63s %31s %31s %c", op, a, b, s, t, &extra) != 5) return 2;
        run(op, a, b, s, t);
    }
    return ferror(stdin) ? 2 : 0;
}
