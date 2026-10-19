/* Standalone protocol for the independent exact-integer Python oracle. */
#include "axi_numeric.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef AXI_NUMERIC_TEST_LEXER
#include "axi.h"
static int read_decimal(const char *source, size_t len, uint64_t *bits,
                         axi_numeric_workspace *workspace)
{
    axi_lexer lexer;
    axi_diags diags;
    axi_token token;
    (void)workspace;
    axi_diags_init(&diags);
    axi_lex_init(&lexer, source, len, &diags);
    axi_lex_next(&lexer, &token);
    if (diags.n) {
        if (diags.n == 1 && strcmp(diags.d[0].code, "AXI-L006") == 0)
            return AXI_DECIMAL_OVERFLOW;
        return AXI_DECIMAL_INVALID;
    }
    if (token.kind != T_FLOAT || token.len != len) return AXI_DECIMAL_INVALID;
    memcpy(bits, &token.fval, sizeof *bits);
    return AXI_DECIMAL_OK;
}
#else
#define read_decimal axi_f64_from_decimal
#endif

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
        status = read_decimal(input, len, &bits, &workspace);
        printf("%d %016llx\n", status, (unsigned long long)bits);
    }
    return ferror(stdin) ? 2 : 0;
}
