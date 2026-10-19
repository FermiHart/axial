/* Regression cases for audit40 W21--W30. No network or ambient authority. */
#include "axi_trust_v1.h"
#include "axi_hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); \
} } while (0)

static void w21(void)
{
    const uint8_t short_snapshot[] = {'T', 'R', 'S', '1', 0, 0, 0, 1};
    uint8_t root[32];
    size_t n;
    CHECK(axi_trust_v1_snapshot_root(NULL, 0, root) == -1);
    for (n = 0; n <= sizeof short_snapshot; n++)
        CHECK(axi_trust_v1_snapshot_root(short_snapshot, n, root) == -1);
    for (n = 1; n < sizeof short_snapshot; n++) {
        CHECK(axi_trust_v1_check_transition(short_snapshot, n,
                                          short_snapshot, n) == -1);
    }
}

int main(int argc, char **argv)
{
    if (argc == 1 || strcmp(argv[1], "W21") == 0) w21();
    printf("audit40 security: %u checks passed\n", checks);
    return 0;
}
