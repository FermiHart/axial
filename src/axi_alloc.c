/* axial - internal allocation door and deterministic CA04 failpoints.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 * INV-309 / AXI-INV-096.
 */
#include "axi_alloc.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef AXI_ALLOC_FAILPOINT
#include <unistd.h>

static size_t fail_at;
static size_t seen;
static int configured;
static int suspended;
static const char *fail_kind;

static void configure(void)
{
    const char *s;
    size_t value = 0;
    if (configured) return;
    configured = 1;
    s = getenv("AXI_ALLOC_FAIL_AT");
    fail_kind = getenv("AXI_ALLOC_FAIL_KIND");
    if (!s || !*s) return;
    while (*s >= '0' && *s <= '9') {
        size_t digit = (size_t)(*s++ - '0');
        if (value > ((size_t)-1 - digit) / 10) return;
        value = value * 10 + digit;
    }
    if (*s == '\0' && value > 0) fail_at = value;
}

static int should_fail(const char *kind)
{
    static const char marker[] = "AXI-FP001 allocation failpoint reached\n";
    if (suspended) return 0;
    configure();
    if (fail_kind && *fail_kind && strcmp(fail_kind, kind) != 0) return 0;
    seen++;
    if (fail_at != 0 && seen == fail_at) {
        ssize_t wrote = write(2, marker, sizeof marker - 1);
        (void)wrote;
        return 1;
    }
    return 0;
}

void axi_alloc_failpoint_suspend(void) { suspended = 1; }
void axi_alloc_failpoint_resume(void)  { seen = 0; suspended = 0; }
#else
static int should_fail(const char *kind)
{
    (void)kind;
    return 0;
}

void axi_alloc_failpoint_suspend(void) {}
void axi_alloc_failpoint_resume(void)  {}
#endif

void *axi_malloc(size_t size)
{
    void *p;
    if (should_fail("malloc")) { errno = ENOMEM; return NULL; }
    p = malloc(size);
    if (!p) errno = ENOMEM;
    return p;
}

void *axi_calloc(size_t count, size_t size)
{
    void *p;
    if (count != 0 && size > (size_t)-1 / count) {
        errno = ENOMEM; return NULL;
    }
    if (should_fail("calloc")) { errno = ENOMEM; return NULL; }
    p = calloc(count, size);
    if (!p) errno = ENOMEM;
    return p;
}

void *axi_realloc(void *ptr, size_t size)
{
    void *p;
    if (should_fail("realloc")) { errno = ENOMEM; return NULL; }
    p = realloc(ptr, size);
    if (!p) errno = ENOMEM;
    return p;
}

char *axi_strdup(const char *s)
{
    size_t n;
    char *copy;
    if (!s) return NULL;
    if (should_fail("strdup")) { errno = ENOMEM; return NULL; }
    n = strlen(s) + 1;
    copy = malloc(n);
    if (!copy) errno = ENOMEM;
    if (copy) memcpy(copy, s, n);
    return copy;
}
