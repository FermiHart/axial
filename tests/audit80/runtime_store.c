#include "runtime_store.h"
#include "axi_hash.h"
#include "ed25519.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

const uint8_t runtime80_store_payload[] = "runtime80 replacement payload\n";
const size_t runtime80_store_payload_size = sizeof runtime80_store_payload - 1u;
static const uint8_t old_payload[] = "original configuration\n";

static int fixture_file(int dirfd, const char *name, const uint8_t *bytes, size_t n)
{
    int fd = openat(dirfd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    int ok;
    if (fd < 0) return -1;
    ok = write(fd, bytes, n) == (ssize_t)n && fsync(fd) == 0;
    if (close(fd) != 0) ok = 0;
    return ok ? 0 : -1;
}

int runtime80_store_init(runtime80_store *s)
{
    axi_local_action_v1 action;
    axi_local_action_roots_v1 roots;
    axi_local_admission_v1_result admission;
    axi_ag1_v1 grant;
    uint8_t seed[32] = {80, 76, 1}, sk[64];
    uint8_t key_message[sizeof("AXV2-KEY-ID-v1") + 32];
    struct stat st;
    int fd, n;
    memset(s, 0, sizeof *s);
    strcpy(s->directory, "/tmp/axial-audit80-runtime-store-XXXXXX");
    if (!mkdtemp(s->directory) || stat(s->directory, &st)) return -1;
    fd = open(s->directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (fixture_file(fd, "config", old_payload, sizeof old_payload - 1u) || fsync(fd)) {
        close(fd); return -1;
    }
    if (close(fd)) return -1;
    memset(&action, 0, sizeof action); memset(&grant, 0, sizeof grant);
    action.deployment[0] = 1; action.boot[0] = 2;
    action.uid = 1000; action.executor_uid = 1001;
    action.policy_binary[0] = 3; action.policy_module[0] = 4;
    action.policy_producer[0] = 5; action.policy_iface[0] = 6; action.trust_snapshot_root[0] = 7;
    action.resource_device = (uint64_t)st.st_dev; action.resource_inode = (uint64_t)st.st_ino;
    action.payload_size = runtime80_store_payload_size;
    axi_sha256(runtime80_store_payload, runtime80_store_payload_size, action.payload_sha256);
    action.fuel = 100; action.workspace = 4096; action.ttl_ns = UINT64_C(1000000000);
    action.not_before = 10; action.not_after = action.not_before + action.ttl_ns;
    memcpy(s->pins.deployment, action.deployment, 16);
#define PIN(field) memcpy(s->pins.field, action.field, 32)
    PIN(policy_binary); PIN(policy_module); PIN(policy_producer); PIN(policy_iface); PIN(trust_snapshot_root);
#undef PIN
    s->observed.profile = AXI_LOCAL_ADMISSION_V1_PROD;
    s->observed.coverage_complete = 1; s->observed.clock_available = 1;
    s->observed.now_ns = 20; memcpy(s->observed.boot, action.boot, 16);
    n = axi_local_action_v1_encode(&action, s->action_bytes, sizeof s->action_bytes);
    if (n <= 0 || axi_local_action_v1_roots(&action, &roots)) return -1;
    s->action_len = (size_t)n;
    if (axi_local_admission_v1_appraise(s->action_bytes, s->action_len,
                                       &s->pins, &s->observed, &admission)) return -1;
    memcpy(s->action_root, roots.action, 32); memcpy(s->context_root, admission.context_root, 32);
    memcpy(grant.decision_aer_root, admission.context_root, 32);
    memcpy(grant.principal_root, roots.principal, 32); memcpy(grant.policy_root, roots.policy, 32);
    memcpy(grant.action_root, roots.action, 32); memcpy(grant.resource_root, roots.resource, 32);
    memcpy(grant.budget_root, roots.budget, 32); memcpy(grant.trust_snapshot_root, s->pins.trust_snapshot_root, 32);
    grant.nonce[0] = 1; grant.not_before = action.not_before; grant.not_after = action.not_after;
    ed25519_keypair_from_seed(seed, s->pk, sk);
    memcpy(key_message, "AXV2-KEY-ID-v1", sizeof("AXV2-KEY-ID-v1"));
    memcpy(key_message + sizeof("AXV2-KEY-ID-v1"), s->pk, 32);
    axi_sha256(key_message, sizeof key_message, grant.issuer_key_id);
    if (axi_ag1_v1_encode_signed(&grant, seed, s->signed_grant)) return -1;
    axi_ag1_v1_root(&grant, s->root);
    memset(sk, 0, sizeof sk); /* public fixture seed; not a credential */
    return 0;
}

int runtime80_store_commit(runtime80_store *s, axi_local_attempt_v1_outcome *out)
{
    return axi_local_attempt_v1_commit(s->directory, s->signed_grant, sizeof s->signed_grant,
              s->pk, s->action_bytes, s->action_len, &s->pins, &s->observed,
              runtime80_store_payload, runtime80_store_payload_size, 20, out);
}

int runtime80_store_content(runtime80_store *s, int new_payload)
{
    const uint8_t *want = new_payload ? runtime80_store_payload : old_payload;
    size_t n = new_payload ? runtime80_store_payload_size : sizeof old_payload - 1u;
    uint8_t bytes[128];
    struct stat st;
    int dirfd = open(s->directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW), fd, ok;
    if (dirfd < 0) return -1;
    fd = openat(dirfd, "config", O_RDONLY | O_NOFOLLOW); close(dirfd);
    if (fd < 0) return -1;
    ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_nlink == 1
         && st.st_size == (off_t)n && read(fd, bytes, sizeof bytes) == (ssize_t)n
         && memcmp(bytes, want, n) == 0;
    if (close(fd)) ok = 0;
    return ok ? 0 : -1;
}

typedef struct {
    const runtime80_store *store;
    unsigned count, state;
    int failed;
} scan_expectation;

static int visit(const axi_local_attempt_v1_record_view *view, void *opaque)
{
    scan_expectation *e = opaque;
    uint8_t payload_hash[32];
    static const uint8_t no_epoch[16] = {0};
    axi_sha256(runtime80_store_payload, runtime80_store_payload_size, payload_hash);
    e->count++;
    if (view->state != e->state || memcmp(view->grant_root, e->store->root, 32)
            || memcmp(view->action_root, e->store->action_root, 32)
            || memcmp(view->context_root, e->store->context_root, 32)
            || memcmp(view->payload_sha, payload_hash, 32)
            /* v2 carries an epoch footer even in the inactive legacy store. */
            || view->has_epoch_link != 1 || view->epoch_generation != 0
            || memcmp(view->epoch_deployment, no_epoch, sizeof no_epoch)
            || view->payload_size != runtime80_store_payload_size) e->failed = 1;
    return 0;
}

int runtime80_store_scan(runtime80_store *s, unsigned count, unsigned state)
{
    scan_expectation e = {s, 0, state, 0};
    return axi_local_attempt_v1_scan(s->directory, visit, &e) == AXI_LOCAL_ATTEMPT_V1_OK
           && !e.failed && e.count == count ? 0 : -1;
}

int runtime80_store_destroy(runtime80_store *s)
{
    int fd = open(s->directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    int records, ok = 1;
    DIR *dir;
    struct dirent *entry;
    if (fd < 0) return -1;
    records = openat(fd, "records", O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (records >= 0) {
        dir = fdopendir(records);
        if (!dir) { close(records); close(fd); return -1; }
        errno = 0;
        while ((entry = readdir(dir)) != NULL) {
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
            if (unlinkat(records, entry->d_name, 0)) ok = 0;
            errno = 0;
        }
        if (errno) ok = 0;
        if (closedir(dir)) ok = 0;
        if (unlinkat(fd, "records", AT_REMOVEDIR)) ok = 0;
    } else if (errno != ENOENT) ok = 0;
    if (unlinkat(fd, "config", 0)) ok = 0;
    if (unlinkat(fd, "owner.lock", 0) && errno != ENOENT) ok = 0;
    if (unlinkat(fd, ".tmp.attempt", 0) && errno != ENOENT) ok = 0;
    if (close(fd)) ok = 0;
    if (rmdir(s->directory)) ok = 0;
    return ok ? 0 : -1;
}

