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

int main(int argc, char **argv)
{
    static char input[16384];
    axi_numeric_workspace workspace;
    int format = argc == 2 && strcmp(argv[1], "format") == 0;
    if (argc != 1 && !format) return 2;
    while (fgets(input, sizeof input, stdin)) {
        size_t len = strlen(input);
        uint64_t bits = UINT64_C(0xdeadbeef12345678);
        int status;
        if (!len || input[len - 1] != '\n') return 2;
        input[--len] = '\0';
        if (format) {
            const char *text = "unchanged";
            size_t textlen = 9, i;
            if (len != 16) return 2;
            bits = 0;
            for (i = 0; i < len; i++) {
                unsigned digit;
                if (input[i] >= '0' && input[i] <= '9') digit = (unsigned)(input[i] - '0');
                else if (input[i] >= 'a' && input[i] <= 'f') digit = (unsigned)(input[i] - 'a') + 10;
                else return 2;
                bits = bits * 16 + digit;
            }
            status = axi_f64_to_decimal(bits, &workspace, &text, &textlen);
            if (textlen != strlen(text)) return 2;
            printf("%d %s\n", status, text);
        } else {
            status = read_decimal(input, len, &bits, &workspace);
            printf("%d %016llx\n", status, (unsigned long long)bits);
        }
    }
    return ferror(stdin) ? 2 : 0;
}
