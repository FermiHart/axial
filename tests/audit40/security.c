/* Regression cases for audit40 W21--W30. No network or ambient authority. */
#include "axi_trust_v1.h"
#include "axi_hash.h"
#include "axi_time_lease_v1.h"
#include "axi_aer1.h"
#include "axi_aer1_verify.h"
#include "axi_aer2_v1.h"
#include "axi_delegation_v1.h"
#include "axi_local_attempt_v1.h"
#include "axi_local_epoch_v1.h"
#include "axi_selective_disclosure_v1.h"
#include "axi_rf1_pin_v1.h"
#include "ed25519.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

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

static void w23(void)
{
    axi_lease1 l;
    axi_lease1_state s, bad, saved;
    uint8_t missing[32] = {99};
    unsigned i;
    memset(&l, 0, sizeof l);
    l.principal_root[0] = 1; l.issuer_root[0] = 2;
    l.trust_snapshot_root[0] = 3; l.lease_nonce[0] = 4;
    l.time_domain_id[0] = 5; l.scope_root[0] = 6;
    l.revocation_root[0] = 7; l.scope_kind = AXI_LEASE1_SCOPE_EXACT_OBJECT;
    l.not_after = 100; l.ncap = 1; strcpy(l.caps[0], "fs.Write");
    l.nquota = 2; l.quota_unit[0][0] = 10; l.quota_unit[1][0] = 20;
    l.quota_limit[0] = UINT64_MAX; l.quota_limit[1] = 12;
    CHECK(axi_lease1_state_init(&s, &l) == 0);
    CHECK(axi_lease1_reserve(&s, l.quota_unit[0], UINT64_MAX - 1) == 0);
    CHECK(axi_lease1_reserve(&s, l.quota_unit[0], 1) == 0);
    saved = s;
    CHECK(axi_lease1_reserve(&s, l.quota_unit[0], 1) == -1);
    CHECK(memcmp(&s, &saved, sizeof s) == 0);
    bad = s; bad.nquota = 255; saved = bad;
    CHECK(axi_lease1_reserve(&bad, missing, 1) == -1);
    CHECK(memcmp(&bad, &saved, sizeof bad) == 0);
    for (i = 0; i < 7; i++) {
        bad = s;
        switch (i) {
        case 0: bad.nquota = AXI_LEASE1_MAX_QUOTAS + 1; break;
        case 1: bad.nquota = 0; break;
        case 2: bad.quota_reserved[0] = 1; bad.quota_limit[0] = 0; break;
        case 3: memcpy(bad.quota_unit[0], bad.quota_unit[1], 32); break;
        case 4: bad.quota_unit[2][0] = 30; break;
        case 5: bad.quota_reserved[2] = 1; break;
        case 6: memset(bad.lease_root, 0, 32); break;
        }
        saved = bad;
        CHECK(axi_lease1_reserve(&bad, l.quota_unit[1], 1) == -1);
        CHECK(memcmp(&bad, &saved, sizeof bad) == 0);
    }
    CHECK(axi_lease1_reserve(&s, l.quota_unit[1], 12) == 0);
    CHECK(axi_lease1_reserve(&s, l.quota_unit[1], 1) == -1);
    CHECK(axi_lease1_reserve(&s, missing, 1) == -1);
    CHECK(axi_lease1_reserve(&s, l.quota_unit[1], 0) == -1);
}

static void sign_body(uint8_t *bytes, size_t body_len, const char *domain,
                       const uint8_t sk[64])
{
    uint8_t msg[160];
    size_t dom_len = strlen(domain) + 1;
    CHECK(dom_len + 32 <= sizeof msg);
    memcpy(msg, domain, dom_len);
    axi_sha256(bytes, body_len, msg + dom_len);
    CHECK(ed25519_sign(bytes + body_len + 40, msg,
                       (uint32_t)(dom_len + 32), sk) == 0);
}

static void delegation_fixture(axi_delegation_v1 *d)
{
    memset(d, 0, sizeof *d);
    d->parent_kind = AXI_DELEGATION_V1_PARENT_AG1;
    d->parent_root[0] = 1; d->delegator_root[0] = 2;
    d->delegatee_root[0] = 3; d->trust_snapshot_root[0] = 4;
    d->issuer_key_id[0] = 5; d->branch_nonce[0] = 6;
    d->depth = 1; d->remaining_depth = 31; d->not_after = 100;
    d->budget[0] = 100; d->ncap = 1; strcpy(d->caps[0], "fs.Write");
}

static void w24(void)
{
    axi_aer1 a1, got1, saved1;
    axi_aer2_v1 a2, got2, saved2;
    axi_delegation_v1 d, gotd, savedd;
    uint8_t b1[AXI_AER1_SIGNED_SIZE], b2[AXI_AER2_V1_SIGNED_SIZE];
    uint8_t bd[AXI_DELEGATION_V1_SIGNED_SIZE];
    uint8_t seed[32] = {1, 2, 3}, pk[32], sk[64];
    size_t n;
    ed25519_keypair_from_seed(seed, pk, sk);
    memset(&a1, 0, sizeof a1);
    a1.profile = AXI_AER1_PROFILE_DEV; a1.opacity = AXI_AER1_OPACITY_CLEAR;
    a1.maturity = AXI_AER1_MATURITY_DEV; a1.has_artifact_root = 1;
    a1.principal_root[0] = 1; a1.artifact_root[0] = 2;
    a1.action_root[0] = 3; a1.budget_root[0] = 4;
    CHECK(axi_aer1_encode_signed(&a1, seed, b1) == 0);
    CHECK(axi_aer1_decode_signed(&got1, b1, sizeof b1, pk) == 0);
    CHECK(axi_aer1_verify_signed(&got1, b1, sizeof b1, pk) == 0);
    CHECK(memcmp(&got1, &a1, sizeof a1) == 0);
    memset(&got1, 0xa5, sizeof got1); saved1 = got1;
    for (n = 0; n < sizeof b1; n++) {
        CHECK(axi_aer1_decode_signed(&got1, b1, n, pk) == -1);
        CHECK(memcmp(&got1, &saved1, sizeof got1) == 0);
    }
    b1[8] = 255; sign_body(b1, AXI_AER1_ENCODED_SIZE, AXI_AER1_SIG_DOMAIN, sk);
    CHECK(axi_aer1_decode_signed(&got1, b1, sizeof b1, pk) == -1);
    CHECK(memcmp(&got1, &saved1, sizeof got1) == 0);
    CHECK(axi_aer1_verify_signed(&got1, b1, sizeof b1, pk) == -1);
    CHECK(memcmp(&got1, &saved1, sizeof got1) == 0);
    memset(&a2, 0, sizeof a2);
    a2.profile = AXI_AER2_V1_PROFILE_DEV; a2.opacity = AXI_AER2_V1_OPACITY_CLEAR;
    a2.maturity = AXI_AER2_V1_MATURITY_DEV; a2.has_artifact_root = 1;
    a2.principal_root[0] = 1; a2.artifact_root[0] = 2;
    a2.action_root[0] = 3; a2.budget_root[0] = 4;
    CHECK(axi_aer2_v1_encode_signed(&a2, seed, b2) == 0);
    CHECK(axi_aer2_v1_decode_signed(&got2, b2, sizeof b2, pk) == 0);
    CHECK(axi_aer2_v1_verify_signed(&got2, b2, sizeof b2, pk) == 0);
    CHECK(memcmp(&got2, &a2, sizeof a2) == 0);
    memset(&got2, 0xa5, sizeof got2); saved2 = got2;
    b2[8] = 255; sign_body(b2, AXI_AER2_V1_BODY_SIZE, AXI_AER2_V1_SIG_DOMAIN, sk);
    CHECK(axi_aer2_v1_decode_signed(&got2, b2, sizeof b2, pk) == -1);
    CHECK(memcmp(&got2, &saved2, sizeof got2) == 0);
    CHECK(axi_aer2_v1_verify_signed(&got2, b2, sizeof b2, pk) == -1);
    CHECK(memcmp(&got2, &saved2, sizeof got2) == 0);
    delegation_fixture(&d);
    CHECK(axi_delegation_v1_encode_signed(&d, seed, bd) == 0);
    CHECK(axi_delegation_v1_decode_signed(&gotd, bd, sizeof bd, pk) == 0);
    CHECK(memcmp(&gotd, &d, sizeof d) == 0);
    memset(&gotd, 0xa5, sizeof gotd); savedd = gotd;
    bd[8] = 255; sign_body(bd, AXI_DELEGATION_V1_BODY_SIZE,
                           AXI_DELEGATION_V1_SIG_DOMAIN, sk);
    CHECK(axi_delegation_v1_decode_signed(&gotd, bd, sizeof bd, pk) == -1);
    CHECK(memcmp(&gotd, &savedd, sizeof gotd) == 0);
}

static void fixture_path(char out[256], const char *directory, const char *name)
{
    int n = snprintf(out, 256, "%s/%s", directory, name);
    CHECK(n > 0 && n < 256);
}

static void fixture_write(const char *path, const void *bytes, size_t n)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    CHECK(fd >= 0);
    CHECK(write(fd, bytes, n) == (ssize_t)n);
    CHECK(close(fd) == 0);
}

static void record_fixture(uint8_t out[168], uint8_t version, const uint8_t root[32])
{
    memset(out, 0, 168); memcpy(out, "AXA1", 4);
    out[4] = version; out[5] = AXI_LOCAL_ATTEMPT_V1_COMMITTED;
    memcpy(out + 8, root, 32); out[40] = 1; out[72] = 2; out[112] = 3;
}

static int visit_count(const axi_local_attempt_v1_record_view *view, void *ctx)
{
    unsigned *n = ctx;
    CHECK(view->state == AXI_LOCAL_ATTEMPT_V1_COMMITTED);
    (*n)++;
    return 0;
}

static void w25(void)
{
    char directory[] = "/tmp/axial-audit40-record-XXXXXX";
    char records[256], lock[256], name[65], file[256];
    uint8_t root[32] = {0xab}, raw[168];
    axi_local_attempt_v1_outcome out;
    unsigned n = 0;
    CHECK(mkdtemp(directory) != NULL);
    fixture_path(records, directory, "records"); CHECK(mkdir(records, 0700) == 0);
    fixture_path(lock, directory, "owner.lock"); fixture_write(lock, "", 0);
    axi_hash_hex(root, name); fixture_path(file, records, name);
    record_fixture(raw, 1, root); fixture_write(file, raw, 144);
    CHECK(axi_local_attempt_v1_status(directory, root, &out) == AXI_LOCAL_ATTEMPT_V1_OK);
    CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_COMMITTED);
    CHECK(axi_local_attempt_v1_scan(directory, visit_count, &n) == AXI_LOCAL_ATTEMPT_V1_OK);
    CHECK(n == 1);
    record_fixture(raw, 2, root); fixture_write(file, raw, 168);
    CHECK(axi_local_attempt_v1_status(directory, root, &out) == AXI_LOCAL_ATTEMPT_V1_OK);
    record_fixture(raw, 1, root); fixture_write(file, raw, 168);
    CHECK(axi_local_attempt_v1_status(directory, root, &out) == AXI_LOCAL_ATTEMPT_V1_CORRUPT);
    CHECK(axi_local_attempt_v1_scan(directory, visit_count, &n) == AXI_LOCAL_ATTEMPT_V1_CORRUPT);
    record_fixture(raw, 2, root); fixture_write(file, raw, 144);
    CHECK(axi_local_attempt_v1_status(directory, root, &out) == AXI_LOCAL_ATTEMPT_V1_CORRUPT);
    record_fixture(raw, 2, root); raw[8] ^= 1; fixture_write(file, raw, 168);
    n = 0;
    CHECK(axi_local_attempt_v1_scan(directory, visit_count, &n) == AXI_LOCAL_ATTEMPT_V1_CORRUPT);
    CHECK(n == 0);
    fixture_write(file, "", 0);
    CHECK(axi_local_attempt_v1_status(directory, root, &out) == AXI_LOCAL_ATTEMPT_V1_OK);
    CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED);
    CHECK(unlink(file) == 0); CHECK(unlink(lock) == 0);
    CHECK(rmdir(records) == 0); CHECK(rmdir(directory) == 0);
}

static void w26(void)
{
    char directory[] = "/tmp/axial-audit40-store-XXXXXX";
    char alias[256], records[256], lock[256], file[256], victim[256], temp[256];
    char name[65];
    uint8_t root[32] = {0xab}, raw[168], observed[168];
    axi_local_attempt_v1_outcome out;
    axi_local_epoch_v1 epoch;
    unsigned n = 0;
    int fd;
    CHECK(mkdtemp(directory) != NULL);
    fixture_path(alias, directory, "alias"); CHECK(symlink(directory, alias) == 0);
    CHECK(axi_local_attempt_v1_store_check(alias) == AXI_LOCAL_ATTEMPT_V1_REFUSED);
    CHECK(unlink(alias) == 0);
    fixture_path(records, directory, "records"); CHECK(mkdir(records, 0700) == 0);
    fixture_path(lock, directory, "owner.lock"); fixture_write(lock, "", 0);
    axi_hash_hex(root, name); fixture_path(file, records, name);
    fixture_path(victim, directory, "victim");
    record_fixture(raw, 2, root); fixture_write(victim, raw, sizeof raw);
    CHECK(symlink(victim, file) == 0);
    CHECK(axi_local_attempt_v1_status(directory, root, &out) == AXI_LOCAL_ATTEMPT_V1_CORRUPT);
    CHECK(unlink(file) == 0);
    CHECK(link(victim, file) == 0);
    CHECK(axi_local_attempt_v1_status(directory, root, &out) == AXI_LOCAL_ATTEMPT_V1_CORRUPT);
    CHECK(unlink(file) == 0);
    CHECK(mkfifo(file, 0600) == 0);
    alarm(3);
    CHECK(axi_local_attempt_v1_status(directory, root, &out) == AXI_LOCAL_ATTEMPT_V1_CORRUPT);
    alarm(0);
    CHECK(unlink(file) == 0);
    CHECK(unlink(lock) == 0); CHECK(mkfifo(lock, 0600) == 0);
    alarm(3);
    CHECK(axi_local_attempt_v1_scan(directory, visit_count, &n) == AXI_LOCAL_ATTEMPT_V1_CORRUPT);
    alarm(0);
    CHECK(n == 0); CHECK(unlink(lock) == 0);
    fixture_write(lock, "", 0);
    fixture_path(temp, directory, ".tmp.epoch"); CHECK(symlink(victim, temp) == 0);
    memset(&epoch, 1, sizeof epoch);
    CHECK(axi_local_epoch_v1_provision(directory, &epoch, NULL) == AXI_LOCAL_EPOCH_V1_REFUSED);
    fd = open(victim, O_RDONLY); CHECK(fd >= 0);
    CHECK(read(fd, observed, sizeof observed) == sizeof observed); CHECK(close(fd) == 0);
    CHECK(memcmp(raw, observed, sizeof raw) == 0);
    /* Refusal may clean only the temporary entry; it never follows it. */
    CHECK(unlink(temp) == 0 || errno == ENOENT);
    CHECK(axi_local_epoch_v1_provision(directory, &epoch, NULL) == AXI_LOCAL_EPOCH_V1_OK);
    CHECK(axi_local_epoch_v1_activate(directory, 1) == AXI_LOCAL_EPOCH_V1_OK);
    CHECK(axi_local_epoch_v1_current(directory, &epoch) == AXI_LOCAL_EPOCH_V1_OK);
    fixture_path(temp, directory, "epoch_active"); CHECK(unlink(temp) == 0);
    CHECK(unlink(victim) == 0); CHECK(unlink(lock) == 0);
    CHECK(rmdir(records) == 0); CHECK(rmdir(directory) == 0);
}

static void chain_fixture(axi_delegation_v1 chain[AXI_DELEGATION_V1_MAX_DEPTH],
                          axi_delegation_v1_authority *root,
                          axi_delegation_v1_authority *leaf)
{
    axi_delegation_v1_authority parent;
    size_t i;
    memset(root, 0, sizeof *root);
    root->root[0] = 1; root->principal_root[0] = 2;
    root->trust_snapshot_root[0] = 4; root->remaining_depth = AXI_DELEGATION_V1_MAX_DEPTH;
    root->not_after = 100; root->budget[0] = 100;
    root->ncap = 1; strcpy(root->caps[0], "fs.Write");
    parent = *root;
    for (i = 0; i < AXI_DELEGATION_V1_MAX_DEPTH; i++) {
        delegation_fixture(&chain[i]);
        chain[i].parent_kind = i ? AXI_DELEGATION_V1_PARENT_DELEGATION
                                 : AXI_DELEGATION_V1_PARENT_AG1;
        memcpy(chain[i].parent_root, parent.root, 32);
        memcpy(chain[i].delegator_root, parent.principal_root, 32);
        chain[i].delegatee_root[0] = (uint8_t)(3 + i);
        chain[i].branch_nonce[0] = (uint8_t)(i + 1);
        chain[i].depth = (uint32_t)i + 1;
        chain[i].remaining_depth = AXI_DELEGATION_V1_MAX_DEPTH - (uint32_t)i - 1;
        chain[i].budget[0] = 100 - i;
        CHECK(axi_delegation_v1_verify(&chain[i], &parent, leaf) == 0);
        parent = *leaf;
    }
}

static void w28(void)
{
    axi_sd1_leaf leaf, saved;
    uint8_t tag[32] = {1}, salt[32] = {2}, expected[32];
    axi_delegation_v1 chain[AXI_DELEGATION_V1_MAX_DEPTH];
    axi_delegation_v1_authority root, wanted, got, saved_authority;
    CHECK(axi_sd1_commit_field(AXI_SD1_PROTECTED, 1, tag, 7, salt,
                               (const uint8_t *)"secret", 6, expected) == 0);
    CHECK(axi_sd1_make_leaf(&leaf, AXI_SD1_PROTECTED, 1, tag, 7, salt,
                            (const uint8_t *)"secret", 6) == 0);
    CHECK(memcmp(leaf.commitment, expected, 32) == 0);
    CHECK(axi_sd1_verify_disclosure(&leaf, salt, (const uint8_t *)"secret", 6) == 0);
    CHECK(axi_sd1_make_leaf(&leaf, AXI_SD1_PROTECTED, 1, leaf.field_tag, 7, salt,
                            (const uint8_t *)"secret", 6) == 0);
    CHECK(memcmp(leaf.commitment, expected, 32) == 0);
    saved = leaf; memset(tag, 0, 32);
    CHECK(axi_sd1_make_leaf(&leaf, AXI_SD1_PROTECTED, 1, tag, 7, salt,
                            (const uint8_t *)"secret", 6) == -1);
    CHECK(memcmp(&leaf, &saved, sizeof leaf) == 0);
    chain_fixture(chain, &root, &wanted);
    CHECK(axi_delegation_v1_verify_chain(chain, AXI_DELEGATION_V1_MAX_DEPTH, &root, &got) == 0);
    CHECK(memcmp(&got, &wanted, sizeof got) == 0);
    saved_authority = got; chain[31].delegator_root[0] ^= 1;
    CHECK(axi_delegation_v1_verify_chain(chain, AXI_DELEGATION_V1_MAX_DEPTH, &root, &got) == -1);
    CHECK(memcmp(&got, &saved_authority, sizeof got) == 0);
}

static size_t rf_fixture(char *bytes, size_t capacity, unsigned records)
{
    size_t off = 6;
    unsigned i;
    memcpy(bytes, "RF1\t1\n", 6);
    for (i = 0; i < records; i++) {
        int n = snprintf(bytes + off, capacity - off, "root\t%06u\tv\n", records - i);
        CHECK(n > 0 && (size_t)n < capacity - off);
        off += (size_t)n;
    }
    return off;
}

static void w29(void)
{
    char bytes[AXI_RF1_PIN_V1_MAX_BYTES + 1];
    uint8_t image[sizeof("BEYOND-RF1") + AXI_RF1_PIN_V1_MAX_BYTES], expected[32];
    axi_rf1_pin_v1 out;
    const char *bad[] = {"RF1\t1\n", "RF1\t1\nroot\ta\tb", "RF1\t1\nroot\ta\tb\n\n",
                         "RF1\t1\nroot\t\tb\n", "RF1\t1\nwat\ta\tb\n",
                         "RF1\t1\nunknown\ta\tb\tc\nroot\ta\tb\n"};
    size_t n, i;
    unsigned trial;
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++)
        CHECK(axi_rf1_pin_v1_parse(bad[i], strlen(bad[i]), &out) == AXI_RF1_PIN_V1_REFUSED);
    for (trial = 1; trial <= 128; trial++) {
        n = rf_fixture(bytes, sizeof bytes, trial);
        CHECK(axi_rf1_pin_v1_parse(bytes, n, &out) == AXI_RF1_PIN_V1_OK);
        CHECK(out.records == trial && out.unknowns == 0);
        memcpy(image, "BEYOND-RF1", sizeof("BEYOND-RF1"));
        memcpy(image + sizeof("BEYOND-RF1"), bytes, n);
        axi_sha256(image, sizeof("BEYOND-RF1") + n, expected);
        CHECK(memcmp(expected, out.rf_root, 32) == 0);
        memcpy(bytes + n, bytes + 6, 14);
        CHECK(axi_rf1_pin_v1_parse(bytes, n + 14, &out) == AXI_RF1_PIN_V1_REFUSED);
    }
    n = rf_fixture(bytes, sizeof bytes, 4096);
    CHECK(axi_rf1_pin_v1_parse(bytes, n, &out) == AXI_RF1_PIN_V1_OK);
    CHECK(out.records == 4096);
    memcpy(bytes, "RF1\t1\nroot\tx\t", 13);
    memset(bytes + 13, 'x', AXI_RF1_PIN_V1_MAX_BYTES - 14);
    bytes[AXI_RF1_PIN_V1_MAX_BYTES - 1] = '\n';
    CHECK(axi_rf1_pin_v1_parse(bytes, AXI_RF1_PIN_V1_MAX_BYTES, &out) == AXI_RF1_PIN_V1_OK);
    CHECK(axi_rf1_pin_v1_parse(bytes, AXI_RF1_PIN_V1_MAX_BYTES + 1, &out) == AXI_RF1_PIN_V1_REFUSED);
    n = (size_t)snprintf(bytes, sizeof bytes, "RF1\t1\nunknown\ta\tb\tc\n");
    CHECK(axi_rf1_pin_v1_parse(bytes, n, &out) == AXI_RF1_PIN_V1_OK && out.unknowns == 1);
    bytes[8] = '\0';
    CHECK(axi_rf1_pin_v1_parse(bytes, n, &out) == AXI_RF1_PIN_V1_REFUSED);
}

int main(int argc, char **argv)
{
    if (argc == 1 || strcmp(argv[1], "W21") == 0) w21();
    if (argc == 1 || strcmp(argv[1], "W22") == 0) w22();
    if (argc == 1 || strcmp(argv[1], "W23") == 0) w23();
    if (argc == 1 || strcmp(argv[1], "W24") == 0) w24();
    if (argc == 1 || strcmp(argv[1], "W25") == 0) w25();
    if (argc == 1 || strcmp(argv[1], "W26") == 0) w26();
    if (argc == 1 || strcmp(argv[1], "W28") == 0) w28();
    if (argc == 1 || strcmp(argv[1], "W29") == 0) w29();
    printf("audit40 security: %u checks passed\n", checks);
    return 0;
}
