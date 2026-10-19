/* Audit40 W08: exact JSON bytes, Unicode handling, sink failures, batching. */
#include "axi_json.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    char *out;
    size_t len, cap, calls, fail_at;
} buffer;

static int sink(void *opaque, const char *bytes, size_t n)
{
    buffer *b = opaque;
    b->calls++;
    if (b->calls == b->fail_at || n > b->cap - b->len) return -1;
    if (b->out) memcpy(b->out + b->len, bytes, n);
    b->len += n;
    return 0;
}

static void exact(const char *input, size_t n, const char *wanted)
{
    char out[1024], document[1028];
    buffer b = {out, 0, sizeof out, 0, 0};
    assert(axi_json_escape(input, n, sink, &b) == 0);
    assert(b.len == strlen(wanted) && memcmp(out, wanted, b.len) == 0);
    document[0] = '"'; memcpy(document + 1, out, b.len); document[b.len + 1] = '"';
    assert(axi_json_validate(document, b.len + 2) == 0);
}

int main(int argc, char **argv)
{
    char *plain = malloc(65536);
    buffer b;
    clock_t start;
    unsigned repeat = argc > 1 ? (unsigned)strtoul(argv[1], NULL, 10) : 1;
    assert(plain && repeat > 0);
    memset(plain, 'a', 65536);
    exact("", 0, "");
    exact("a\"b\\c\n\t\r\b\f\0", 11, "a\\\"b\\\\c\\n\\t\\r\\b\\f\\u0000");
    exact("\xc2\xa2\xe2\x82\xac\xf0\x9f\x98\x80", 9,
          "\xc2\xa2\xe2\x82\xac\xf0\x9f\x98\x80");
    exact("\xc0\xaf\xed\xa0\x80\xf4\x90\x80\x80", 9,
          "\\u00c0\\u00af\\u00ed\\u00a0\\u0080\\u00f4\\u0090\\u0080\\u0080");
    b.out = NULL; b.len = 0; b.cap = (size_t)-1; b.calls = 0; b.fail_at = 2;
    assert(axi_json_escape("a\nb", 3, sink, &b) == -1 && b.calls == 2 && b.len == 1);
    b.len = 0; b.calls = 0; b.fail_at = 0;
    start = clock();
    for (unsigned i = 0; i < repeat; i++)
        assert(axi_json_escape(plain, 65536, sink, &b) == 0);
    printf("json_escape_bytes=%lu sink_calls=%lu cpu_seconds=%.6f\n",
           (unsigned long)b.len, (unsigned long)b.calls,
           (double)(clock() - start) / CLOCKS_PER_SEC);
    assert(b.len == (size_t)repeat * 65536);
    if (argc == 1) assert(b.calls == 1);
    free(plain);
    puts("frontend W08: PASS");
    return 0;
}
