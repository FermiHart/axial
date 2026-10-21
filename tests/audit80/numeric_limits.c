/* Deterministic environmental and long-input tests for the numeric contract. */
#include "axi_numeric.h"
#include "axi.h"
#include <assert.h>
#include <fenv.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { const char *text; uint64_t bits; } fixture;
static const fixture CASES[] = {
    { "0.0", UINT64_C(0) },
    { "0.1", UINT64_C(0x3fb999999999999a) },
    { "0.3", UINT64_C(0x3fd3333333333333) },
    { "0.7", UINT64_C(0x3fe6666666666666) },
    { "1.25", UINT64_C(0x3ff4000000000000) },
    { "9007199254740993.0", UINT64_C(0x4340000000000000) },
    { "9007199254740995.0", UINT64_C(0x4340000000000002) },
    { "18446744073709551615.0", UINT64_C(0x43f0000000000000) },
    { "1.00000000000000011102230246251565404236316680908203125", UINT64_C(0x3ff0000000000000) },
    { "1.000000000000000111022302462515654042363166809082031251", UINT64_C(0x3ff0000000000001) },
    { "1.00000000000000033306690738754696212708950042724609375", UINT64_C(0x3ff0000000000002) },
};

static void environment_cases(axi_numeric_workspace *workspace)
{
    static const int modes[] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
    static const char *const locales[] = { "C", "POSIX", "C.UTF-8", "de_DE.UTF-8", "fr_FR.UTF-8" };
    unsigned i, j, k, tested_modes = 0, tested_locales = 0, comma_locales = 0;
    int original = fegetround();
    for (j = 0; j < sizeof locales / sizeof *locales; j++) {
        if (!setlocale(LC_NUMERIC, locales[j])) continue;
        tested_locales++;
        if (strcmp(localeconv()->decimal_point, ".") != 0) comma_locales++;
        for (i = 0; i < sizeof modes / sizeof *modes; i++) {
            if (fesetround(modes[i])) continue;
            tested_modes++;
            for (k = 0; k < sizeof CASES / sizeof *CASES; k++) {
                uint64_t bits = UINT64_MAX, lex_bits;
                const char *text;
                char copy[AXI_F64_DECIMAL_CAP];
                size_t len;
                axi_lexer lexer;
                axi_diags diags;
                axi_token token;
                int exceptions;
                assert(feclearexcept(FE_ALL_EXCEPT) == 0);
                assert(feraiseexcept(FE_DIVBYZERO | FE_INEXACT) == 0);
                exceptions = fetestexcept(FE_ALL_EXCEPT);
                assert(axi_f64_from_decimal(CASES[k].text, strlen(CASES[k].text), &bits, workspace) == 0);
                assert(bits == CASES[k].bits);
                assert(axi_f64_to_decimal(bits, workspace, &text, &len) == 0);
                assert(len < sizeof copy);
                memcpy(copy, text, len);
                assert(axi_f64_from_decimal(copy, len, &bits, workspace) == 0);
                assert(bits == CASES[k].bits);
                axi_diags_init(&diags);
                axi_lex_init(&lexer, CASES[k].text, strlen(CASES[k].text), &diags);
                axi_lex_next(&lexer, &token);
                memcpy(&lex_bits, &token.fval, sizeof lex_bits);
                assert(!diags.n && token.kind == T_FLOAT && lex_bits == bits);
                assert(fegetround() == modes[i] && fetestexcept(FE_ALL_EXCEPT) == exceptions);
            }
        }
    }
    assert(tested_modes >= 4 && tested_locales >= 1);
    assert(fesetround(original) == 0);
    assert(feclearexcept(FE_ALL_EXCEPT) == 0);
    assert(setlocale(LC_NUMERIC, "C"));
    printf("numeric W68: PASS (%u locale names, %u with a non-dot separator, %u locale/rounding combinations; fenv preserved)\n",
           tested_locales, comma_locales, tested_modes);
}

static void long_cases(axi_numeric_workspace *workspace)
{
    static const char halfway[] = "1.00000000000000011102230246251565404236316680908203125";
    const size_t count = 1024u * 1024u;
    const size_t prefix = sizeof halfway - 1;
    char *source = (char *)malloc(count + prefix + 4);
    uint64_t bits = UINT64_MAX;
    assert(source);
    memcpy(source, halfway, prefix);
    memset(source + prefix, '0', count);
    assert(axi_f64_from_decimal(source, prefix + count, &bits, workspace) == 0);
    assert(bits == UINT64_C(0x3ff0000000000000));
    source[prefix + count] = '1';
    assert(axi_f64_from_decimal(source, prefix + count + 1, &bits, workspace) == 0);
    assert(bits == UINT64_C(0x3ff0000000000001));
    source[prefix - 1] = '4';
    memset(source + prefix, '9', count);
    assert(axi_f64_from_decimal(source, prefix + count, &bits, workspace) == 0);
    assert(bits == UINT64_C(0x3ff0000000000000));
    memset(source, '9', count); memcpy(source + count, ".0", 2);
    bits = UINT64_MAX;
    assert(axi_f64_from_decimal(source, count + 2, &bits, workspace) == AXI_DECIMAL_OVERFLOW);
    assert(bits == UINT64_MAX);
    memcpy(source, "0.", 2); memset(source + 2, '0', count); source[count + 2] = '1';
    assert(axi_f64_from_decimal(source, count + 3, &bits, workspace) == 0 && bits == 0);
    memset(source, '0', count); memcpy(source + count, "1.25", 4);
    assert(axi_f64_from_decimal(source, count + 4, &bits, workspace) == 0);
    assert(bits == UINT64_C(0x3ff4000000000000));
    bits = UINT64_MAX; source[count + 4] = 'x';
    assert(axi_f64_from_decimal(source, count + 5, &bits, workspace) == AXI_DECIMAL_INVALID);
    assert(bits == UINT64_MAX);
    free(source);
    puts("numeric W68: PASS (1 MiB midpoint tails, sticky rounding, long magnitudes, leading zeroes and refusal atomicity)");
}

int main(void)
{
    axi_numeric_workspace workspace;
    uint64_t bits = UINT64_MAX;
    const char *text = "sentinel";
    size_t len = 123;
    assert(AXI_NUMERIC_SCRATCH_BYTES == sizeof workspace);
    assert(axi_f64_from_decimal(NULL, 3, &bits, &workspace) == AXI_DECIMAL_INVALID);
    assert(axi_f64_from_decimal("1.0", 3, NULL, &workspace) == AXI_DECIMAL_INVALID);
    assert(axi_f64_from_decimal("1.0", 3, &bits, NULL) == AXI_DECIMAL_INVALID);
    assert(bits == UINT64_MAX);
    assert(axi_f64_to_decimal(0, NULL, &text, &len) == AXI_DECIMAL_INVALID);
    assert(axi_f64_to_decimal(0, &workspace, NULL, &len) == AXI_DECIMAL_INVALID);
    assert(axi_f64_to_decimal(0, &workspace, &text, NULL) == AXI_DECIMAL_INVALID);
    assert(axi_f64_to_decimal(UINT64_C(0x7ff0000000000000), &workspace, &text, &len) == AXI_DECIMAL_INVALID);
    assert(strcmp(text, "sentinel") == 0 && len == 123);
    environment_cases(&workspace);
    long_cases(&workspace);
    return 0;
}
