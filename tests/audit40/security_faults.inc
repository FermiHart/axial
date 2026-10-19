/* Compile through security_faults.sh: only the two store modules have their
 * I/O names redirected. Fault state never enters the product build. */
#define main security_normal_main
#include "security.c"
#undef main
#include "axi_ag1_v1.h"
#include <dirent.h>

enum { NO_FAULT, ZERO_WRITE, DIRECTORY_READ_ERROR, TRAILER_EINTR,
       READ_NOMEM, DIR_FSYNC_BEFORE_EFFECT, DIR_FSYNC_AFTER_RENAME };
static int fault;
static unsigned fault_hits;

ssize_t audit_fault_write(int fd, const void *bytes, size_t n)
{
    if (fault == ZERO_WRITE) { fault_hits++; return 0; }
    return write(fd, bytes, n);
}

ssize_t audit_fault_read(int fd, void *bytes, size_t n)
{
    if (fault == READ_NOMEM) { fault_hits++; errno = ENOMEM; return -1; }
    if (fault == TRAILER_EINTR && n == 1 && fault_hits == 0) {
        fault_hits++; errno = EINTR; return -1;
    }
    return read(fd, bytes, n);
}

struct dirent *audit_fault_readdir(DIR *d)
{
    if (fault == DIRECTORY_READ_ERROR) { fault_hits++; errno = EIO; return NULL; }
    return readdir(d);
}

int audit_fault_fsync(int fd)
{
    struct stat st, child;
    int exists;
    if ((fault == DIR_FSYNC_BEFORE_EFFECT || fault == DIR_FSYNC_AFTER_RENAME)
            && fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)
            && fstatat(fd, "records", &child, AT_SYMLINK_NOFOLLOW) == 0) {
        exists = fstatat(fd, "config", &child, AT_SYMLINK_NOFOLLOW) == 0;
        if ((fault == DIR_FSYNC_BEFORE_EFFECT && !exists)
                || (fault == DIR_FSYNC_AFTER_RENAME && exists)) {
            fault_hits++; errno = EIO; return -1;
        }
    }
    return fsync(fd);
}

static void set_fault(int f)
{
    fault = f; fault_hits = 0;
}

static void fault_reads(void)
{
    char directory[] = "/tmp/axial-audit40-faultread-XXXXXX";
    char records[256], lock[256], file[256], name[65];
    uint8_t root[32] = {0xab}, raw[168];
    axi_local_attempt_v1_outcome out;
    axi_local_epoch_v1 epoch;
    unsigned n = 0;
    CHECK(mkdtemp(directory) != NULL);
    fixture_path(records, directory, "records"); CHECK(mkdir(records, 0700) == 0);
    fixture_path(lock, directory, "owner.lock"); fixture_write(lock, "", 0);
    axi_hash_hex(root, name); fixture_path(file, records, name);
    record_fixture(raw, 2, root); fixture_write(file, raw, sizeof raw);
    set_fault(DIRECTORY_READ_ERROR);
    CHECK(axi_local_attempt_v1_scan(directory, visit_count, &n) == AXI_LOCAL_ATTEMPT_V1_REFUSED);
    CHECK(n == 0 && fault_hits == 1);
    set_fault(TRAILER_EINTR);
    CHECK(axi_local_attempt_v1_status(directory, root, &out) == AXI_LOCAL_ATTEMPT_V1_OK);
    CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_COMMITTED && fault_hits == 1);
    set_fault(READ_NOMEM);
    CHECK(axi_local_attempt_v1_status(directory, root, &out) == AXI_LOCAL_ATTEMPT_V1_REFUSED);
    set_fault(NO_FAULT);
    memset(&epoch, 1, sizeof epoch);
    CHECK(axi_local_epoch_v1_provision(directory, &epoch, NULL) == AXI_LOCAL_EPOCH_V1_OK);
    CHECK(axi_local_epoch_v1_activate(directory, 1) == AXI_LOCAL_EPOCH_V1_OK);
    set_fault(READ_NOMEM);
    CHECK(axi_local_epoch_v1_current(directory, &epoch) == AXI_LOCAL_EPOCH_V1_REFUSED);
    CHECK(fault_hits == 1);
    set_fault(NO_FAULT);
    CHECK(unlink(file) == 0); CHECK(unlink(lock) == 0);
    fixture_path(file, directory, "epoch_active"); CHECK(unlink(file) == 0);
    CHECK(rmdir(records) == 0); CHECK(rmdir(directory) == 0);
}

static void mint_fixture(const char *directory, uint8_t signed_grant[AXI_AG1_V1_SIGNED_SIZE],
                         uint8_t pk[32], uint8_t action_bytes[4096], size_t *action_len,
                         axi_local_admission_v1_pins *pins,
                         axi_local_admission_v1_observed *observed, uint8_t grant_root[32])
{
    axi_local_action_v1 a;
    axi_local_action_roots_v1 roots;
    axi_local_admission_v1_result adm;
    axi_ag1_v1 g;
    uint8_t seed[32] = {1, 2, 3}, sk[64];
    uint8_t key_message[sizeof("AXV2-KEY-ID-v1") + 32];
    struct stat st;
    int n;
    CHECK(stat(directory, &st) == 0);
    memset(&a, 0, sizeof a); memset(pins, 0, sizeof *pins);
    memset(observed, 0, sizeof *observed); memset(&g, 0, sizeof g);
    a.deployment[0] = 1; a.boot[0] = 2;
    a.uid = 1000; a.executor_uid = 1001;
    a.policy_binary[0] = 3; a.policy_module[0] = 4;
    a.policy_producer[0] = 5; a.policy_iface[0] = 6; a.trust_snapshot_root[0] = 7;
    a.resource_device = (uint64_t)st.st_dev; a.resource_inode = (uint64_t)st.st_ino;
    a.payload_size = 7; axi_sha256("payload", 7, a.payload_sha256);
    a.fuel = 100; a.workspace = 4096; a.ttl_ns = UINT64_C(1000000000);
    a.not_before = 10; a.not_after = a.not_before + a.ttl_ns;
    memcpy(pins->deployment, a.deployment, 16);
#define PIN(field) memcpy(pins->field, a.field, 32)
    PIN(policy_binary); PIN(policy_module); PIN(policy_producer); PIN(policy_iface);
    PIN(trust_snapshot_root);
#undef PIN
    observed->profile = AXI_LOCAL_ADMISSION_V1_PROD;
    observed->coverage_complete = 1; observed->clock_available = 1;
    observed->now_ns = 20; memcpy(observed->boot, a.boot, 16);
    n = axi_local_action_v1_encode(&a, action_bytes, 4096); CHECK(n > 0);
    *action_len = (size_t)n;
    CHECK(axi_local_action_v1_roots(&a, &roots) == 0);
    CHECK(axi_local_admission_v1_appraise(action_bytes, *action_len, pins, observed, &adm) == 0);
    memcpy(g.decision_aer_root, adm.context_root, 32);
    memcpy(g.principal_root, roots.principal, 32); memcpy(g.policy_root, roots.policy, 32);
    memcpy(g.action_root, roots.action, 32); memcpy(g.resource_root, roots.resource, 32);
    memcpy(g.budget_root, roots.budget, 32); memcpy(g.trust_snapshot_root, pins->trust_snapshot_root, 32);
    g.nonce[0] = 1; g.not_before = a.not_before; g.not_after = a.not_after;
    ed25519_keypair_from_seed(seed, pk, sk);
    memcpy(key_message, "AXV2-KEY-ID-v1", sizeof("AXV2-KEY-ID-v1"));
    memcpy(key_message + sizeof("AXV2-KEY-ID-v1"), pk, 32);
    axi_sha256(key_message, sizeof key_message, g.issuer_key_id);
    CHECK(axi_ag1_v1_encode_signed(&g, seed, signed_grant) == 0);
    axi_ag1_v1_root(&g, grant_root);
}

static void fault_commit(int injected)
{
    char directory[] = "/tmp/axial-audit40-faultcommit-XXXXXX";
    char records[256], file[256], name[65];
    uint8_t pk[32], root[32], bytes[4096], grant[AXI_AG1_V1_SIGNED_SIZE];
    axi_local_admission_v1_pins pins;
    axi_local_admission_v1_observed observed;
    axi_local_attempt_v1_outcome out, status;
    size_t len;
    struct stat st;
    int rc;
    CHECK(mkdtemp(directory) != NULL);
    mint_fixture(directory, grant, pk, bytes, &len, &pins, &observed, root);
    set_fault(injected); alarm(3);
    rc = axi_local_attempt_v1_commit(directory, grant, sizeof grant, pk, bytes, len,
                                    &pins, &observed, (const uint8_t *)"payload", 7, 20, &out);
    alarm(0);
    CHECK(fault_hits > 0); set_fault(NO_FAULT);
    CHECK(rc == AXI_LOCAL_ATTEMPT_V1_REFUSED);
    CHECK(axi_local_attempt_v1_status(directory, root, &status) == AXI_LOCAL_ATTEMPT_V1_OK);
    fixture_path(file, directory, "config");
    if (injected == DIR_FSYNC_AFTER_RENAME) {
        CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_UNKNOWN && out.effect_performed == 1);
        CHECK(status.state == AXI_LOCAL_ATTEMPT_V1_UNKNOWN);
        CHECK(stat(file, &st) == 0 && st.st_size == 7);
        CHECK(axi_local_attempt_v1_commit(directory, grant, sizeof grant, pk, bytes, len,
                     &pins, &observed, (const uint8_t *)"payload", 7, 20, &out) == AXI_LOCAL_ATTEMPT_V1_REFUSED);
        CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_UNKNOWN && out.effect_performed == 0);
        CHECK(unlink(file) == 0);
    } else {
        CHECK(out.effect_performed == 0);
        CHECK(stat(file, &st) == -1 && errno == ENOENT);
        CHECK(out.state == (injected == DIR_FSYNC_BEFORE_EFFECT
                           ? AXI_LOCAL_ATTEMPT_V1_UNKNOWN : AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED));
    }
    axi_hash_hex(root, name); fixture_path(records, directory, "records");
    fixture_path(file, records, name); CHECK(unlink(file) == 0 || errno == ENOENT);
    CHECK(rmdir(records) == 0);
    fixture_path(file, directory, "owner.lock"); CHECK(unlink(file) == 0);
    CHECK(rmdir(directory) == 0);
}

int main(int argc, char **argv)
{
    if (argc == 1 || strcmp(argv[1], "read") == 0) fault_reads();
    if (argc == 1 || strcmp(argv[1], "zero-write") == 0) fault_commit(ZERO_WRITE);
    if (argc == 1 || strcmp(argv[1], "dir-read") == 0) fault_commit(DIRECTORY_READ_ERROR);
    if (argc == 1 || strcmp(argv[1], "pre-effect") == 0) fault_commit(DIR_FSYNC_BEFORE_EFFECT);
    if (argc == 1 || strcmp(argv[1], "post-rename") == 0) fault_commit(DIR_FSYNC_AFTER_RENAME);
    printf("audit40 W27 fault injection: %u checks passed\n", checks);
    return 0;
}
