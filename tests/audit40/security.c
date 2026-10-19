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

static void be64(uint8_t *p, uint64_t n)
{
    unsigned i;
    for (i = 0; i < 8; i++) p[i] = (uint8_t)(n >> (56 - 8 * i));
}

/* A minimal, canonical TRS1 fixture, including an optional revocation. */
static size_t snapshot(uint8_t out[512], uint64_t sequence,
                       const uint8_t *predecessor, int revoked)
{
    size_t off = 139;
    memset(out, 0, 512);
    memcpy(out, "TRS1", 4); out[7] = 1;
    out[8] = 1; be64(out + 40, sequence);
    if (predecessor) { out[48] = 1; memcpy(out + 49, predecessor, 32); }
    out[81] = 2; be64(out + 121, 1000);
    out[130] = 1; out[132] = 1; out[134] = 1; out[136] = 1;
    out[138] = (uint8_t)revoked;
    out[off] = 3; off += 32; /* identity */
    out[off] = 4; out[off + 32] = 3;
    out[off + 64] = AXI_TRUST_V1_PURPOSE_APPROVE;
    out[off + 65] = 5; be64(out + off + 105, 1000); off += 113;
    out[off] = 3; out[off + 32] = AXI_TRUST_V1_ROLE_APPROVER;
    out[off + 33] = 6; be64(out + off + 73, 1000); off += 81;
    out[off] = 7; out[off + 32] = AXI_TRUST_V1_ROLE_APPROVER;
    out[off + 33] = 6; out[off + 65] = 1; off += 67;
    if (revoked) { out[off] = 4; be64(out + off + 32, 100); off += 40; }
    return off;
}

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

static void w22(void)
{
    uint8_t prev[512], next[512], root[32], changed[512];
    size_t pn = snapshot(prev, 1, NULL, 1), nn, n;
    CHECK(axi_trust_v1_snapshot_root(prev, pn, root) == 0);
    nn = snapshot(next, 2, root, 1);
    CHECK(axi_trust_v1_check_transition(prev, pn, next, nn) == 0);
    for (n = 0; n < pn; n++)
        CHECK(axi_trust_v1_snapshot_root(prev, n, root) == -1);
    CHECK(axi_trust_v1_snapshot_root(prev, pn, root) == 0);
    CHECK(axi_trust_v1_snapshot_root(prev, pn + 1, root) == -1);
    memcpy(changed, next, sizeof changed); changed[8] ^= 1;
    changed[9] = 1; /* remain nonzero while changing the organization */
    CHECK(axi_trust_v1_check_transition(prev, pn, changed, nn) == -1);
    memcpy(changed, next, sizeof changed); changed[81] ^= 1;
    CHECK(axi_trust_v1_check_transition(prev, pn, changed, nn) == -1);
    memcpy(changed, next, sizeof changed); be64(changed + 40, 3);
    CHECK(axi_trust_v1_check_transition(prev, pn, changed, nn) == -1);
    memcpy(changed, next, sizeof changed); be64(changed + nn - 8, 101);
    CHECK(axi_trust_v1_check_transition(prev, pn, changed, nn) == -1);
    nn = snapshot(changed, 2, root, 0);
    CHECK(axi_trust_v1_check_transition(prev, pn, changed, nn) == -1);
    pn = snapshot(prev, UINT64_MAX, NULL, 0);
    CHECK(axi_trust_v1_snapshot_root(prev, pn, root) == 0);
    nn = snapshot(next, 0, root, 0);
    CHECK(axi_trust_v1_check_transition(prev, pn, next, nn) == -1);
}

int main(int argc, char **argv)
{
    if (argc == 1 || strcmp(argv[1], "W21") == 0) w21();
    if (argc == 1 || strcmp(argv[1], "W22") == 0) w22();
    printf("audit40 security: %u checks passed\n", checks);
    return 0;
}
