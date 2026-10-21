#include "axi.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    static const char source[] = "\"A\\n\\t\\0\\\\\\\"Z\"";
    static const unsigned char want[] = {'A', '\n', '\t', 0, '\\', '"', 'Z', 0};
    static const char *bad[] = {"", "x", "\"", "\"x", "x\"", "\"\\x\"",
                                "\"x\"y\"", "\"\\\"", "\"\r\"", "\"\n\""};
    uint32_t n = 123;
    char dst[32], before[32], overlap[] = "\"abc\"";
    assert(axi_str_decoded_length(source, sizeof source - 1, &n) == 0 && n == 7);
    memset(dst, 0x5a, sizeof dst);
    assert(axi_str_decode_into(source, sizeof source - 1, dst, sizeof dst, &n) == 0);
    assert(n == 7 && memcmp(dst, want, sizeof want) == 0);
    char *owned = axi_str_unescape(source, sizeof source - 1, &n);
    assert(owned && n == 7 && memcmp(owned, want, sizeof want) == 0);
    free(owned);
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        memset(dst, 0x5a, sizeof dst); memcpy(before, dst, sizeof dst); n = 123;
        assert(axi_str_decode_into(bad[i], strlen(bad[i]), dst, sizeof dst, &n) != 0);
        assert(n == 123 && memcmp(dst, before, sizeof dst) == 0);
        assert(axi_str_unescape(bad[i], strlen(bad[i]), &n) == NULL && n == 123);
    }
    memset(dst, 0x5a, sizeof dst); memcpy(before, dst, sizeof dst); n = 123;
    assert(axi_str_decode_into(source, sizeof source - 1, dst, 7, &n) != 0);
    assert(n == 123 && memcmp(dst, before, sizeof dst) == 0);
    assert(axi_str_decode_into(overlap, sizeof overlap - 1, overlap, sizeof overlap, &n) != 0);
    assert(n == 123 && strcmp(overlap, "\"abc\"") == 0);
    assert(axi_str_decoded_length(NULL, 0, &n) != 0 && n == 123);
    assert(axi_str_decoded_length("\"\"", 2, &n) == 0 && n == 0);
    puts("frontend W55: PASS (allocation-free decoding and refusal atomicity)");
    return 0;
}
