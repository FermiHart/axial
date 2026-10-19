/* Deterministic microbenchmark; correctness is gated by numeric.py first.
 * Compile both compared revisions with exactly the same compiler/flags.
 * This is not a speed threshold or an end-to-end compiler measurement.
 */
#include "axi_numeric.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *const READ_VALUES[] = {
    "0.0", "1.0", "0.5", "1.25", "42.0", "1048576.0",
    "9007199254740993.0", "18446744073709551615.0", "0.125", "0.0625",
    "10000000000000000000.0", "0.3", "0.7", "123.456", "0.0000001",
    "99999999999999999999999999999999999999999999999999.0"
};

int main(int argc, char **argv)
{
    axi_numeric_workspace workspace;
    unsigned long count = 4096, i;
    uint64_t checksum = UINT64_C(14695981039346656037);
    uint64_t state = UINT64_C(0xa806700012345678);
    int reader;
    clock_t start, end;
    if (argc < 2 || argc > 3) return 2;
    reader = strcmp(argv[1], "reader") == 0;
    if (!reader && strcmp(argv[1], "format") != 0) return 2;
    if (argc == 3) {
        char *tail;
        count = strtoul(argv[2], &tail, 10);
        if (*tail || !count || count > 10000000) return 2;
    }
    start = clock();
    for (i = 0; i < count; i++) {
        if (reader) {
            const char *source = READ_VALUES[i % (sizeof READ_VALUES / sizeof *READ_VALUES)];
            uint64_t bits;
            if (axi_f64_from_decimal(source, strlen(source), &bits, &workspace)) return 1;
            checksum = (checksum ^ bits) * UINT64_C(1099511628211);
        } else {
            const char *text;
            size_t len, j;
            uint64_t bits;
            state ^= state << 13; state ^= state >> 7; state ^= state << 17;
            bits = (state & UINT64_C(0x800fffffffffffff))
                 | ((uint64_t)(i % 2047) << 52);
            if (axi_f64_to_decimal(bits, &workspace, &text, &len)) return 1;
            for (j = 0; j < len; j++)
                checksum = (checksum ^ (unsigned char)text[j]) * UINT64_C(1099511628211);
        }
    }
    end = clock();
    if (start == (clock_t)-1 || end == (clock_t)-1) return 2;
    printf("{\"mode\":\"%s\",\"iterations\":%lu,\"cpu_seconds\":%.9f,"
           "\"checksum\":\"%016llx\",\"workspace_bytes\":%lu}\n", argv[1], count,
           (double)(end - start) / CLOCKS_PER_SEC, (unsigned long long)checksum,
           (unsigned long)AXI_NUMERIC_SCRATCH_BYTES);
    return 0;
}
