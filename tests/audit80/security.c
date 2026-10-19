#define _GNU_SOURCE
#include "axi_local_authority_v1.h"
#include "axi_local_epoch_v1.h"
#include "axi_ag1_v1.h"
#include "axi_hash.h"
#include "ed25519.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr, "audit80-security:%d: %s (errno=%d)\n", __LINE__, #x, errno); exit(1); \
} } while (0)

typedef struct {
    char dir[256];
    uint8_t seed[32], pk[32];
    axi_local_action_v1 action;
    axi_local_admission_v1_pins pins;
    axi_local_admission_v1_observed observed;
    uint8_t action_bytes[AXI_LOCAL_ACTION_V1_MAX_BYTES];
    size_t action_len;
    uint8_t grant[AXI_AG1_V1_SIGNED_SIZE], grant_root[32];
} fixture;

static void path_of(char out[512], const char *dir, const char *name)
{
    int n = snprintf(out, 512, "%s/%s", dir, name);
    CHECK(n > 0 && n < 512);
}

static void put_file(const char *path, const void *bytes, size_t len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    size_t n = 0;
    CHECK(fd >= 0);
    while (n < len) {
        ssize_t wrote = write(fd, (const uint8_t *)bytes + n, len - n);
        CHECK(wrote > 0); n += (size_t)wrote;
    }
    CHECK(close(fd) == 0);
}

static void rm_fixture(const char *directory)
{
    DIR *d = opendir(directory);
    struct dirent *e;
    CHECK(d != NULL);
    while ((e = readdir(d)) != NULL) {
        char p[512];
        struct stat st;
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        path_of(p, directory, e->d_name);
        CHECK(lstat(p, &st) == 0);
        if (S_ISDIR(st.st_mode)) rm_fixture(p);
        else CHECK(unlink(p) == 0);
    }
    CHECK(closedir(d) == 0 && rmdir(directory) == 0);
}

static int exists(const char *directory, const char *name)
{
    char path[512]; struct stat st;
    path_of(path, directory, name);
    if (lstat(path, &st) == 0) return 1;
    CHECK(errno == ENOENT); return 0;
}

static void new_fixture(fixture *f)
{
    uint8_t sk[64];
    struct stat st;
    memset(f, 0, sizeof *f);
    strcpy(f->dir, "/tmp/axi-authority80.XXXXXX");
    CHECK(mkdtemp(f->dir) != NULL && stat(f->dir, &st) == 0);
    f->seed[0] = 1; f->seed[1] = 2; f->seed[2] = 3;
    ed25519_keypair_from_seed(f->seed, f->pk, sk);
    f->action.deployment[0] = 1; f->action.boot[0] = 2;
    f->action.uid = 1000; f->action.executor_uid = 1001;
    f->action.policy_binary[0] = 3; f->action.policy_module[0] = 4;
    f->action.policy_producer[0] = 5; f->action.policy_iface[0] = 6;
    f->action.trust_snapshot_root[0] = 7;
    f->action.resource_device = (uint64_t)st.st_dev;
    f->action.resource_inode = (uint64_t)st.st_ino;
    f->action.payload_size = 7; axi_sha256("payload", 7, f->action.payload_sha256);
    f->action.fuel = 100; f->action.workspace = 4096;
    f->action.ttl_ns = UINT64_C(300000000000);
    f->action.not_before = 10; f->action.not_after = 10 + f->action.ttl_ns;
    memcpy(f->pins.deployment, f->action.deployment, 16);
#define PIN(field) memcpy(f->pins.field, f->action.field, 32)
    PIN(trust_snapshot_root); PIN(policy_binary); PIN(policy_module);
    PIN(policy_producer); PIN(policy_iface);
#undef PIN
    f->observed.profile = AXI_LOCAL_ADMISSION_V1_PROD;
    f->observed.coverage_complete = 1; f->observed.clock_available = 1;
    f->observed.now_ns = 20; memcpy(f->observed.boot, f->action.boot, 16);
}

static void mint(fixture *f, const axi_local_admission_v1_result *prepared)
{
    axi_local_action_roots_v1 roots;
    axi_local_admission_v1_result adm;
    axi_ag1_v1 g;
    uint8_t kid[sizeof("AXV2-KEY-ID-v1") + 32];
    int n = axi_local_action_v1_encode(&f->action, f->action_bytes, sizeof f->action_bytes);
    CHECK(n > 0); f->action_len = (size_t)n;
    CHECK(axi_local_action_v1_roots(&f->action, &roots) == 0);
    if (prepared) adm = *prepared;
    else CHECK(axi_local_admission_v1_appraise(f->action_bytes, f->action_len,
                                               &f->pins, &f->observed, &adm) == 0);
    memset(&g, 0, sizeof g);
    memcpy(g.decision_aer_root, adm.context_root, 32);
    memcpy(g.principal_root, roots.principal, 32); memcpy(g.policy_root, roots.policy, 32);
    memcpy(g.action_root, roots.action, 32); memcpy(g.resource_root, roots.resource, 32);
    memcpy(g.budget_root, roots.budget, 32); memcpy(g.trust_snapshot_root, f->pins.trust_snapshot_root, 32);
    g.nonce[0] = 1; g.not_before = f->action.not_before; g.not_after = f->action.not_after;
    memcpy(kid, "AXV2-KEY-ID-v1", sizeof("AXV2-KEY-ID-v1"));
    memcpy(kid + sizeof("AXV2-KEY-ID-v1"), f->pk, 32);
    axi_sha256(kid, sizeof kid, g.issuer_key_id);
    CHECK(axi_ag1_v1_encode_signed(&g, f->seed, f->grant) == 0);
    axi_ag1_v1_root(&g, f->grant_root);
}

static void provision(fixture *f)
{
    axi_local_epoch_v1 epoch;
    uint64_t generation = 0;
    memset(&epoch, 0, sizeof epoch);
    memcpy(epoch.deployment, f->pins.deployment, 16);
#define PIN(field) memcpy(epoch.field, f->pins.field, 32)
    PIN(trust_snapshot_root); PIN(policy_binary); PIN(policy_module);
    PIN(policy_producer); PIN(policy_iface);
#undef PIN
    CHECK(axi_local_epoch_v1_provision(f->dir, &epoch, &generation) == 0);
    CHECK(axi_local_epoch_v1_activate(f->dir, generation) == 0);
}

static void measured_action(fixture *f, axi_local_authority_v1 *owner)
{
    axi_local_authority_v1_facts facts;
    int n;
    CHECK(axi_local_authority_v1_observe(owner, &facts, 0) == 0);
    f->action.uid = facts.uid; f->action.executor_uid = facts.executor_uid;
    memcpy(f->action.boot, facts.boot, 16);
    f->action.resource_device = facts.resource_device; f->action.resource_inode = facts.resource_inode;
    f->action.has_previous = facts.has_previous; f->action.previous = facts.previous;
    f->action.not_before = facts.now_ns; f->action.not_after = facts.now_ns + f->action.ttl_ns;
    f->pins = facts.pins;
    memcpy(f->action.deployment, facts.pins.deployment, 16);
#define PIN(field) memcpy(f->action.field, facts.pins.field, 32)
    PIN(trust_snapshot_root); PIN(policy_binary); PIN(policy_module);
    PIN(policy_producer); PIN(policy_iface);
#undef PIN
    n = axi_local_action_v1_encode(&f->action, f->action_bytes, sizeof f->action_bytes);
    CHECK(n > 0); f->action_len = (size_t)n;
}

static void w41(void)
{
    fixture f, other;
    axi_local_authority_v1 *owner = NULL;
    axi_local_attempt_v1_outcome out;
    uint8_t wrong[32] = {1}, raw[64];
    char marker[512], relocated[512];
    uint64_t dev = 98, ino = 99;
    int fd;
    new_fixture(&f); new_fixture(&other); mint(&f, NULL);
    CHECK(axi_local_authority_v1_open(f.dir, &owner) != 0 && owner == NULL);
    CHECK(axi_local_authority_v1_enable(f.dir, f.pk) == 0);
    CHECK(axi_local_authority_v1_enable(f.dir, f.pk) == 0);
    CHECK(axi_local_authority_v1_enable(f.dir, wrong) != 0);
    CHECK(axi_local_authority_v1_open(f.dir, &owner) == 0 && owner != NULL);
    CHECK(axi_local_authority_v1_resource(owner, &dev, &ino) == 0);
    CHECK(dev == f.action.resource_device && ino == f.action.resource_inode);
    CHECK(axi_local_authority_v1_resource(owner, &dev, &dev) != 0);
    CHECK(axi_local_attempt_v1_commit(f.dir, f.grant, sizeof f.grant, f.pk,
            f.action_bytes, f.action_len, &f.pins, &f.observed,
            (const uint8_t *)"payload", 7, 20, &out) == AXI_LOCAL_ATTEMPT_V1_REFUSED);
    CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED && !out.effect_performed);
    CHECK(!exists(f.dir, "records") && !exists(f.dir, "config"));
    path_of(marker, f.dir, "authority_v1");
    fd = open(marker, O_RDONLY); CHECK(fd >= 0 && read(fd, raw, sizeof raw) == sizeof raw);
    CHECK(close(fd) == 0);
    CHECK(axi_local_authority_v1_enable(other.dir, other.pk) == 0);
    path_of(marker, other.dir, "authority_v1"); put_file(marker, raw, sizeof raw);
    {
        axi_local_authority_v1 *bad = NULL;
        CHECK(axi_local_authority_v1_open(other.dir, &bad) != 0 && bad == NULL);
    }
    CHECK(snprintf(relocated, sizeof relocated, "%s.moved", f.dir) > 0);
    CHECK(rename(f.dir, relocated) == 0 && mkdir(f.dir, 0700) == 0);
    CHECK(axi_local_authority_v1_resource(owner, &dev, &ino) == 0);
    CHECK(dev == f.action.resource_device && ino == f.action.resource_inode);
    axi_local_authority_v1_close(owner); owner = NULL;
    CHECK(axi_local_authority_v1_open(f.dir, &owner) != 0 && !owner);
    rm_fixture(f.dir); rm_fixture(relocated); rm_fixture(other.dir);
}

static void w42(void)
{
    fixture f;
    axi_local_authority_v1 *owner = NULL;
    axi_local_previous_v1 previous, saved;
    uint8_t present = 99, digest[32], bytes[4097];
    char config[512], linkname[512];
    struct stat st;
    new_fixture(&f);
    CHECK(axi_local_authority_v1_enable(f.dir, f.pk) == 0);
    CHECK(axi_local_authority_v1_open(f.dir, &owner) == 0);
    memset(&previous, 0x5a, sizeof previous);
    CHECK(axi_local_authority_v1_previous(owner, &previous, &present, 0) == 0 && !present);
    memset(&saved, 0, sizeof saved); CHECK(memcmp(&previous, &saved, sizeof saved) == 0);
    path_of(config, f.dir, "config"); path_of(linkname, f.dir, "alias");
    put_file(config, "before", 6); CHECK(stat(config, &st) == 0);
    CHECK(axi_local_authority_v1_previous(owner, &previous, &present, 0) == 0 && present);
    axi_sha256("before", 6, digest);
    CHECK(previous.device == (uint64_t)st.st_dev && previous.inode == (uint64_t)st.st_ino);
    CHECK(previous.size == 6 && !memcmp(previous.sha256, digest, 32));
    CHECK(previous.mtime_ns == (uint64_t)st.st_mtim.tv_sec * UINT64_C(1000000000)
                                  + (uint64_t)st.st_mtim.tv_nsec);
    memset(bytes, 7, sizeof bytes); put_file(config, bytes, 4096);
    CHECK(axi_local_authority_v1_previous(owner, &previous, &present, 0) == 0);
    CHECK(previous.size == 4096); saved = previous;
    put_file(config, bytes, 4097); present = 77;
    CHECK(axi_local_authority_v1_previous(owner, &previous, &present, 0) != 0);
    CHECK(!memcmp(&previous, &saved, sizeof saved) && present == 77);
    put_file(config, "", 0);
    CHECK(axi_local_authority_v1_previous(owner, &previous, &present, 0) == 0 && present);
    axi_sha256("", 0, digest); CHECK(previous.size == 0 && !memcmp(previous.sha256, digest, 32));
    CHECK(link(config, linkname) == 0);
    CHECK(axi_local_authority_v1_previous(owner, &previous, &present, 0) != 0);
    CHECK(unlink(linkname) == 0 && unlink(config) == 0);
    put_file(linkname, "victim", 6); CHECK(symlink("alias", config) == 0);
    CHECK(axi_local_authority_v1_previous(owner, &previous, &present, 0) != 0);
    CHECK(unlink(config) == 0 && mkfifo(config, 0600) == 0);
    alarm(2);
    CHECK(axi_local_authority_v1_previous(owner, &previous, &present, 0) != 0);
    alarm(0); CHECK(unlink(config) == 0);
    CHECK(mkdir(config, 0700) == 0);
    CHECK(axi_local_authority_v1_previous(owner, &previous, &present, 0) != 0);
    CHECK(rmdir(config) == 0);
    axi_local_authority_v1_close(owner); rm_fixture(f.dir);
}

static void w43(void)
{
    fixture f;
    axi_local_authority_v1 *owner = NULL;
    axi_local_authority_v1_facts facts, again, saved;
    pid_t child;
    int status;
    new_fixture(&f);
    provision(&f);
    CHECK(axi_local_authority_v1_enable(f.dir, f.pk) == 0);
    CHECK(axi_local_authority_v1_open(f.dir, &owner) == 0);
    CHECK(axi_local_authority_v1_observe(owner, &facts, 0) == 0);
    CHECK(facts.uid == getuid() && facts.executor_uid == geteuid() && facts.uid != facts.executor_uid);
    CHECK(facts.resource_device == f.action.resource_device && facts.resource_inode == f.action.resource_inode);
    CHECK(facts.now_ns > 0 && !facts.has_previous);
    CHECK(axi_local_authority_v1_observe(owner, &again, 0) == 0);
    CHECK(again.now_ns >= facts.now_ns && !memcmp(again.boot, facts.boot, 16));
    child = fork(); CHECK(child >= 0);
    if (child == 0) {
        /* A context cannot silently cross a process/credential boundary. */
        saved = facts;
        CHECK(axi_local_authority_v1_observe(owner, &facts, 0) != 0);
        CHECK(!memcmp(&facts, &saved, sizeof facts));
        CHECK(setreuid(geteuid(), geteuid()) == 0);
        {
            axi_local_authority_v1 *other = NULL;
            CHECK(axi_local_authority_v1_open(f.dir, &other) == AXI_LOCAL_AUTHORITY_V1_UNSUPPORTED);
            CHECK(other == NULL);
        }
        _exit(0);
    }
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(axi_local_authority_v1_observe(owner, &again, 0) == 0);
    axi_local_authority_v1_close(owner); rm_fixture(f.dir);
}

static void w44(void)
{
    fixture f;
    axi_local_authority_v1 *owner = NULL;
    axi_local_authority_v1_prepared *prepared = NULL;
    axi_local_admission_v1_result adm;
    axi_local_authority_v1_facts facts, sentinel;
    uint8_t payload[7] = {'p','a','y','l','o','a','d'};
    unsigned field;
    new_fixture(&f);
    CHECK(axi_local_authority_v1_enable(f.dir, f.pk) == 0);
    CHECK(axi_local_authority_v1_open(f.dir, &owner) == 0);
    memset(&facts, 0x5a, sizeof facts); sentinel = facts;
    CHECK(axi_local_authority_v1_observe(owner, &facts, 0) != 0);
    CHECK(!memcmp(&facts, &sentinel, sizeof facts));
    provision(&f); measured_action(&f, owner);
    for (field = 0; field < 8; field++) {
        axi_local_action_v1 saved = f.action;
        int n;
        switch (field) {
        case 0: f.action.uid++; if (f.action.uid == f.action.executor_uid) f.action.uid++; break;
        case 1: f.action.executor_uid += 2; break;
        case 2: f.action.resource_device ^= 1; break;
        case 3: f.action.resource_inode ^= 1; break;
        case 4: f.action.trust_snapshot_root[0] ^= 1; break;
        case 5: f.action.policy_binary[0] ^= 1; break;
        case 6: f.action.boot[0] ^= 1; break;
        default: f.action.has_previous = 1; break;
        }
        n = axi_local_action_v1_encode(&f.action, f.action_bytes, sizeof f.action_bytes);
        CHECK(n > 0);
        CHECK(axi_local_authority_v1_prepare(owner, f.action_bytes, (size_t)n, payload, sizeof payload,
                                             0, &prepared, &adm) != 0);
        CHECK(prepared == NULL && !adm.admitted);
        CHECK(!exists(f.dir, "records") && !exists(f.dir, "config"));
        f.action = saved;
    }
    measured_action(&f, owner);
    CHECK(axi_local_authority_v1_prepare(owner, f.action_bytes, f.action_len, payload, sizeof payload,
                                         0, &prepared, &adm) == 0 && prepared && adm.admitted);
    CHECK(axi_local_authority_v1_observe(owner, &facts, 0) == 0);
    CHECK(facts.epoch_generation == 1 && !memcmp(&facts.pins, &f.pins, sizeof f.pins));
    /* prepare owns all bytes and its fd after return. Commit tests in W45
     * prove that subsequent caller mutation cannot alter the signed effect. */
    memset(f.action_bytes, 0, sizeof f.action_bytes); memset(payload, 0, sizeof payload);
    axi_local_authority_v1_close(owner); owner = NULL;
    axi_local_authority_v1_prepared_close(prepared);
    CHECK(!exists(f.dir, "records") && !exists(f.dir, "config"));
    rm_fixture(f.dir);
}

int main(int argc, char **argv)
{
    if (geteuid() == 0) {
        /* Real kernel identities; no mocked authentication or ambient root. */
        CHECK(setgroups(0, NULL) == 0 && setgid(1001) == 0);
        CHECK(setreuid(1000, 1001) == 0);
    }
    if (getuid() == 0 || geteuid() == 0 || getuid() == geteuid()) {
        fprintf(stderr, "audit80 security: unsupported host; positive profile needs two real nonzero distinct UIDs\n");
        return 77;
    }
    if (argc > 2) return 2;
    if (argc == 1 || !strcmp(argv[1], "W41")) w41();
    if (argc == 1 || !strcmp(argv[1], "W42")) w42();
    if (argc == 1 || !strcmp(argv[1], "W43")) w43();
    if (argc == 1 || !strcmp(argv[1], "W44")) w44();
    if (argc == 2 && strcmp(argv[1], "W41") && strcmp(argv[1], "W42") && strcmp(argv[1], "W43") && strcmp(argv[1], "W44")) return 2;
    printf("audit80 security: %u checks PASS (ruid=%lu euid=%lu)\n", checks,
           (unsigned long)getuid(), (unsigned long)geteuid());
    return 0;
}
