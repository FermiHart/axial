/* Standalone protocol for the independent exact-integer Python oracle. */
#include "axi_numeric.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    static char input[16384];
    axi_numeric_workspace workspace;
    while (fgets(input, sizeof input, stdin)) {
        size_t len = strlen(input);
        uint64_t bits = UINT64_C(0xdeadbeef12345678);
        int status;
        if (!len || input[len - 1] != '\n') return 2;
        input[--len] = '\0';
        status = axi_f64_from_decimal(input, len, &bits, &workspace);
        printf("%d %016llx\n", status, (unsigned long long)bits);
    }
    return ferror(stdin) ? 2 : 0;
}
