#define _POSIX_C_SOURCE 200809L
#include "axi_numeric.h"
#include <fenv.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *s, size_t row) { fprintf(stderr, "probe row %zu: %s\n", row, s); exit(2); }
int main(void)
{
    static const int modes[] = {FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO};
    struct { unsigned char left[8]; axi_numeric_workspace w; unsigned char right[8]; } box;
    char *line = NULL, answer[AXI_F64_DECIMAL_CAP];
    size_t cap = 0, row = 0, format_count = 0, parse_count = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, stdin)) >= 0) {
        unsigned mode, j;
        uint64_t baseline_bits = 0;
        int baseline_status = -1;
        size_t answer_len = 0;
        row++;
        if (n < 3 || line[n-1] != '\n' || line[1] != ' ') die("protocol", row);
        line[--n] = 0;
        for (mode = 0; mode < sizeof modes / sizeof modes[0]; mode++) {
            uint64_t bits = UINT64_C(0xdeadbeef12345678);
            const char *out = "sentinel";
            size_t outlen = 8;
            int status, raised;
            memset(&box, 0xa5, sizeof box);
            if (fesetround(modes[mode]) || feclearexcept(FE_ALL_EXCEPT)
                || feraiseexcept(FE_INVALID | FE_DIVBYZERO | FE_OVERFLOW | FE_UNDERFLOW | FE_INEXACT)) die("fenv setup", row);
            raised = fetestexcept(FE_ALL_EXCEPT);
            if (line[0] == 'P') status = axi_f64_from_decimal(line + 2, (size_t)n - 2, &bits, &box.w);
            else if (line[0] == 'F') {
                bits = strtoull(line + 2, NULL, 16);
                status = axi_f64_to_decimal(bits, &box.w, &out, &outlen);
            } else die("unknown command", row);
            if (fegetround() != modes[mode] || fetestexcept(FE_ALL_EXCEPT) != raised) die("changed fenv", row);
            for (j = 0; j < 8; j++) if (box.left[j] != 0xa5 || box.right[j] != 0xa5) die("workspace overrun", row);
            if (line[0] == 'F') {
                if (outlen >= sizeof answer || strlen(out) != outlen) die("invalid output length", row);
                if (!mode) { memcpy(answer, out, outlen + 1); answer_len = outlen; }
                else if (answer_len != outlen || memcmp(answer, out, outlen + 1)) die("fenv-dependent spelling", row);
            }
            if (!mode) { baseline_status = status; baseline_bits = bits; }
            else if (status != baseline_status || bits != baseline_bits) die("fenv-dependent value", row);
        }
        if (line[0] == 'F') { printf("%d %s\n", baseline_status, answer); format_count++; }
        else { printf("%d %016" PRIx64 "\n", baseline_status, baseline_bits); parse_count++; }
    }
    free(line);
    if (ferror(stdin)) return 2;
    fprintf(stderr, "probe: %zu parses, %zu formats, four modes; workspace=%zu, canaries/fenv unchanged\n", parse_count, format_count, sizeof box.w);
    return 0;
}
