/* The optional provider is compiled out in its actual product object. */
#include "axi_local_authority_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr, "audit80-nohost:%d: %s\n", __LINE__, #x); return 1; \
} } while (0)

int main(void)
{
    char directory[] = "/tmp/axi-authority-nohost80.XXXXXX", file[128];
    uint8_t key[32] = {1};
    axi_local_authority_v1 *owner = NULL;
    axi_local_authority_v1_facts facts, sentinel;
    CHECK(mkdtemp(directory) != NULL);
    CHECK(axi_local_authority_v1_enable(directory, key) == 0);
    CHECK(axi_local_authority_v1_open(directory, &owner) == AXI_LOCAL_AUTHORITY_V1_UNSUPPORTED && owner == NULL);
    memset(&facts, 0xa5, sizeof facts); sentinel = facts;
    CHECK(axi_local_authority_host_sample(&facts) == AXI_LOCAL_AUTHORITY_V1_UNSUPPORTED);
    CHECK(!memcmp(&facts, &sentinel, sizeof facts));
    CHECK(snprintf(file, sizeof file, "%s/authority_v1", directory) > 0 && unlink(file) == 0);
    CHECK(snprintf(file, sizeof file, "%s/owner.lock", directory) > 0 && unlink(file) == 0);
    CHECK(rmdir(directory) == 0);
    printf("audit80 security no-host: %u checks PASS (provider disabled; no fallback)\n", checks);
    return 0;
}
