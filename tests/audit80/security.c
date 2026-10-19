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
#include <sys/file.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
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

static axi_local_authority_v1_prepared *ready(fixture *f, axi_local_authority_v1 *owner)
{
    axi_local_authority_v1_prepared *prepared = NULL;
    axi_local_admission_v1_result adm;
    uint8_t payload[7] = {'p','a','y','l','o','a','d'};
    measured_action(f, owner);
    CHECK(axi_local_authority_v1_prepare(owner, f->action_bytes, f->action_len,
            payload, sizeof payload, 0, &prepared, &adm) == 0 && adm.admitted);
    memset(payload, 0xa5, sizeof payload); /* caller bytes no longer agree */
    mint(f, &adm);
    return prepared;
}

static void check_config(const char *dir, const void *bytes, size_t len)
{
    char path[512]; uint8_t got[4097]; int fd;
    path_of(path, dir, "config"); fd = open(path, O_RDONLY);
    CHECK(fd >= 0);
    CHECK(read(fd, got, sizeof got) == (ssize_t)len && !memcmp(got, bytes, len));
    CHECK(close(fd) == 0);
}

static void w45(void)
{
    unsigned scenario;
    for (scenario = 0; scenario < 6; scenario++) {
        fixture a, b;
        axi_local_authority_v1 *owner = NULL, *other = NULL;
        axi_local_authority_v1_prepared *prepared, *prepared_b;
        axi_local_attempt_v1_outcome out;
        char config[512], replacement[512], moved[512];
        new_fixture(&a); new_fixture(&b); provision(&a); provision(&b);
        CHECK(axi_local_authority_v1_enable(a.dir, a.pk) == 0);
        CHECK(axi_local_authority_v1_enable(b.dir, b.pk) == 0);
        CHECK(axi_local_authority_v1_open(a.dir, &owner) == 0);
        CHECK(axi_local_authority_v1_open(b.dir, &other) == 0);
        path_of(config, a.dir, "config"); path_of(replacement, a.dir, "replacement");
        if (scenario == 1 || scenario == 2) put_file(config, "before", 6);
        prepared = ready(&a, owner); prepared_b = ready(&b, other);
        /* A signed request for A cannot be consumed through B. */
        CHECK(axi_local_authority_v1_commit(prepared_b, a.grant, sizeof a.grant, 0, &out)
                == AXI_LOCAL_AUTHORITY_V1_REFUSED);
        CHECK(!out.effect_performed && !exists(b.dir, "records") && !exists(b.dir, "config"));
        if (scenario == 0) put_file(config, "unseen", 6);
        if (scenario == 1) put_file(config, "edited", 6);
        if (scenario == 2) {
            put_file(replacement, "before", 6);
            CHECK(rename(replacement, config) == 0);
        }
        if (scenario == 3) provision(&a); /* even identical pins advance epoch */
        if (scenario < 4) {
            CHECK(axi_local_authority_v1_commit(prepared, a.grant, sizeof a.grant, 0, &out)
                    == AXI_LOCAL_AUTHORITY_V1_REFUSED);
            CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED && !out.effect_performed);
            CHECK(!exists(a.dir, "records"));
            if (scenario < 3) check_config(a.dir, scenario == 0 ? "unseen" : scenario == 1 ? "edited" : "before", 6);
            else CHECK(!exists(a.dir, "config"));
        } else {
            if (scenario == 5) {
                CHECK(snprintf(moved, sizeof moved, "%s.moved", a.dir) > 0);
                CHECK(rename(a.dir, moved) == 0 && mkdir(a.dir, 0700) == 0);
            }
            /* Caller mutations and owner close cannot change copied input. */
            memset(a.action_bytes, 0, sizeof a.action_bytes);
            axi_local_authority_v1_close(owner); owner = NULL;
            CHECK(axi_local_authority_v1_commit(prepared, a.grant, sizeof a.grant, 0, &out) == 0);
            CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_COMMITTED && out.effect_performed == 1);
            check_config(scenario == 5 ? moved : a.dir, "payload", 7);
            CHECK(axi_local_authority_v1_commit(prepared, a.grant, sizeof a.grant, 0, &out)
                    == AXI_LOCAL_AUTHORITY_V1_REFUSED);
            CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_COMMITTED && !out.effect_performed);
            if (scenario == 5) {
                CHECK(!exists(a.dir, "config") && !exists(a.dir, "records"));
                rm_fixture(moved);
            }
        }
        axi_local_authority_v1_prepared_close(prepared);
        axi_local_authority_v1_prepared_close(prepared_b);
        axi_local_authority_v1_close(owner); axi_local_authority_v1_close(other);
        rm_fixture(a.dir); rm_fixture(b.dir);
    }
}

static void expire_pause(void)
{
    struct timespec pause = {1, 100000000L}, remaining;
    while (nanosleep(&pause, &remaining) != 0) {
        CHECK(errno == EINTR); pause = remaining;
    }
}

static void w46(void)
{
    unsigned scenario;
    for (scenario = 0; scenario < 4; scenario++) {
        fixture f;
        axi_local_authority_v1 *owner = NULL;
        axi_local_authority_v1_prepared *prepared;
        axi_local_attempt_v1_outcome out;
        char path[512];
        int lockfd = -1, status = 0, rc;
        pid_t child = -1;
        new_fixture(&f); provision(&f);
        CHECK(axi_local_authority_v1_enable(f.dir, f.pk) == 0);
        CHECK(axi_local_authority_v1_open(f.dir, &owner) == 0);
        if (scenario < 2) f.action.ttl_ns = UINT64_C(1000000000);
        prepared = ready(&f, owner);
        if (scenario == 2) {
            axi_ag1_v1 g;
            CHECK(axi_ag1_v1_decode_signed(&g, f.grant, sizeof f.grant, f.pk) == 0);
            g.not_after = g.not_before + UINT64_C(1000000000);
            CHECK(axi_ag1_v1_encode_signed(&g, f.seed, f.grant) == 0);
        }
        if (scenario == 0 || scenario == 2) expire_pause();
        if (scenario == 1 || scenario == 3) {
            path_of(path, f.dir, "owner.lock"); lockfd = open(path, O_RDONLY);
            CHECK(lockfd >= 0 && flock(lockfd, LOCK_EX) == 0);
            if (scenario == 1) {
                child = fork(); CHECK(child >= 0);
                if (child == 0) {
                    expire_pause(); CHECK(flock(lockfd, LOCK_UN) == 0 && close(lockfd) == 0);
                    _exit(0);
                }
            }
        }
        rc = axi_local_authority_v1_commit(prepared, f.grant, sizeof f.grant,
                scenario == 1 ? axi_local_attempt_v1_now_mono() + UINT64_C(3000000000) : 0, &out);
        CHECK(rc == (scenario == 3 ? AXI_LOCAL_AUTHORITY_V1_TIMEOUT : AXI_LOCAL_AUTHORITY_V1_REFUSED));
        CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED && !out.effect_performed);
        CHECK(!exists(f.dir, "records") && !exists(f.dir, "config"));
        if (lockfd >= 0) { CHECK(flock(lockfd, LOCK_UN) == 0 && close(lockfd) == 0); }
        if (child > 0) CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        axi_local_authority_v1_prepared_close(prepared); axi_local_authority_v1_close(owner);
        rm_fixture(f.dir);
    }
}

static void read_exact_pipe(int fd, void *bytes, size_t len)
{
    size_t n = 0;
    while (n < len) {
        ssize_t got = read(fd, (uint8_t *)bytes + n, len - n);
        if (got < 0 && errno == EINTR) continue;
        CHECK(got > 0); n += (size_t)got;
    }
}

typedef struct { int rc; axi_local_attempt_v1_outcome outcome; } worker_result;

static int record_counter(const axi_local_attempt_v1_record_view *view, void *ctx)
{
    unsigned *n = ctx;
    CHECK(view->state == AXI_LOCAL_ATTEMPT_V1_COMMITTED); (*n)++;
    return 0;
}

static void concurrent_prior(void)
{
    fixture f;
    int ready_pipe[2], go[2], report[2], status;
    pid_t children[2];
    worker_result results[2];
    unsigned i, effects = 0, spent = 0;
    char tokens[2];
    alarm(15); /* A failed child must not hang the pipe barrier forever. */
    new_fixture(&f); provision(&f);
    CHECK(axi_local_authority_v1_enable(f.dir, f.pk) == 0);
    CHECK(pipe(ready_pipe) == 0 && pipe(go) == 0 && pipe(report) == 0);
    for (i = 0; i < 2; i++) {
        children[i] = fork(); CHECK(children[i] >= 0);
        if (children[i] == 0) {
            axi_local_authority_v1 *owner = NULL;
            axi_local_authority_v1_prepared *prepared;
            axi_ag1_v1 grant;
            worker_result result;
            char token;
            close(ready_pipe[0]); close(go[1]); close(report[0]);
            CHECK(axi_local_authority_v1_open(f.dir, &owner) == 0);
            prepared = ready(&f, owner);
            CHECK(axi_ag1_v1_decode_signed(&grant, f.grant, sizeof f.grant, f.pk) == 0);
            grant.nonce[0] = (uint8_t)(i + 1);
            CHECK(axi_ag1_v1_encode_signed(&grant, f.seed, f.grant) == 0);
            CHECK(write(ready_pipe[1], "r", 1) == 1);
            read_exact_pipe(go[0], &token, 1);
            memset(&result, 0, sizeof result);
            result.rc = axi_local_authority_v1_commit(prepared, f.grant, sizeof f.grant,
                            axi_local_attempt_v1_now_mono() + UINT64_C(3000000000), &result.outcome);
            CHECK(write(report[1], &result, sizeof result) == sizeof result);
            axi_local_authority_v1_prepared_close(prepared); axi_local_authority_v1_close(owner);
            close(ready_pipe[1]); close(go[0]); close(report[1]);
            _exit(0);
        }
    }
    close(ready_pipe[1]); close(go[0]); close(report[1]);
    read_exact_pipe(ready_pipe[0], tokens, 2);
    CHECK(write(go[1], "gg", 2) == 2);
    read_exact_pipe(report[0], results, sizeof results);
    close(ready_pipe[0]); close(go[1]); close(report[0]);
    for (i = 0; i < 2; i++) {
        CHECK(waitpid(children[i], &status, 0) == children[i] && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        if (results[i].outcome.effect_performed) {
            effects++;
            CHECK(results[i].rc == 0 && results[i].outcome.state == AXI_LOCAL_ATTEMPT_V1_COMMITTED);
        } else CHECK(results[i].rc == AXI_LOCAL_AUTHORITY_V1_REFUSED
                       && results[i].outcome.state == AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED);
    }
    CHECK(effects == 1);
    CHECK(axi_local_attempt_v1_scan(f.dir, record_counter, &spent) == 0 && spent == 1);
    check_config(f.dir, "payload", 7);
    rm_fixture(f.dir);
    alarm(0);
}

static void w47(void)
{
    fixture f, legacy;
    axi_local_authority_v1 *owner = NULL;
    axi_local_authority_v1_prepared *prepared;
    axi_local_attempt_v1_outcome out;
    char path[512], saved[512];
    new_fixture(&f); provision(&f);
    CHECK(axi_local_authority_v1_enable(f.dir, f.pk) == 0);
    legacy = f; mint(&legacy, NULL);
    CHECK(axi_local_authority_v1_open(f.dir, &owner) == 0);
    prepared = ready(&f, owner);
    path_of(path, f.dir, "owner.lock"); path_of(saved, f.dir, "old.lock");
    CHECK(rename(path, saved) == 0); put_file(path, "", 0);
    CHECK(axi_local_authority_v1_commit(prepared, f.grant, sizeof f.grant, 0, &out) == AXI_LOCAL_AUTHORITY_V1_REFUSED);
    CHECK(!out.effect_performed && !exists(f.dir, "records") && !exists(f.dir, "config"));
    CHECK(unlink(path) == 0);
    CHECK(axi_local_authority_v1_enable(f.dir, f.pk) != 0 && !exists(f.dir, "owner.lock"));
    CHECK(axi_local_attempt_v1_commit(legacy.dir, legacy.grant, sizeof legacy.grant, legacy.pk,
        legacy.action_bytes, legacy.action_len, &legacy.pins, &legacy.observed,
        (const uint8_t *)"payload", 7, legacy.observed.now_ns, &out) != 0);
    CHECK(!exists(f.dir, "owner.lock") && !exists(f.dir, "records"));
    axi_local_authority_v1_prepared_close(prepared); axi_local_authority_v1_close(owner);
    rm_fixture(f.dir);
    concurrent_prior();
}

static void restarted_status(fixture *f, axi_local_authority_v1 *inherited, uint8_t state)
{
    pid_t child = fork();
    int status;
    CHECK(child >= 0);
    if (child == 0) {
        axi_local_authority_v1 *reopened = NULL;
        axi_local_attempt_v1_outcome out, sentinel;
        memset(&out, 0xa5, sizeof out); sentinel = out;
        CHECK(axi_local_authority_v1_status(inherited, f->grant_root, 0, &out)
                == AXI_LOCAL_AUTHORITY_V1_REFUSED);
        CHECK(!memcmp(&out, &sentinel, sizeof out));
        CHECK(axi_local_authority_v1_open(f->dir, &reopened) == 0);
        CHECK(axi_local_authority_v1_status(reopened, f->grant_root, 0, &out) == 0);
        CHECK(out.state == state && !out.effect_performed);
        axi_local_authority_v1_close(reopened);
        _exit(0);
    }
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void w48(void)
{
    fixture f;
    axi_local_authority_v1 *owner = NULL;
    axi_local_authority_v1_prepared *prepared;
    axi_local_authority_v1_facts facts, sentinel_facts;
    axi_local_attempt_v1_outcome out, sentinel;
    uint8_t missing[32] = {0x99}, zero[32] = {0};
    char original[256], relocated[256], path[512], recname[73];
    const char hex[] = "0123456789abcdef";
    int lockfd, n;
    unsigned i;
    new_fixture(&f); provision(&f);
    CHECK(axi_local_authority_v1_enable(f.dir, f.pk) == 0);
    CHECK(axi_local_authority_v1_open(f.dir, &owner) == 0);
    prepared = ready(&f, owner);
    CHECK(axi_local_authority_v1_commit(prepared, f.grant, sizeof f.grant, 0, &out) == 0);
    CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_COMMITTED && out.effect_performed);
    axi_local_authority_v1_prepared_close(prepared);
    CHECK(axi_local_authority_v1_status(owner, f.grant_root, 0, &out) == 0);
    CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_COMMITTED && !out.effect_performed);
    CHECK(axi_local_authority_v1_status(owner, missing, 0, &out) == 0);
    CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED && !out.effect_performed);
    memset(&out, 0xa5, sizeof out); sentinel = out;
    CHECK(axi_local_authority_v1_status(owner, zero, 0, &out) == AXI_LOCAL_AUTHORITY_V1_REFUSED);
    CHECK(!memcmp(&out, &sentinel, sizeof out));
    path_of(path, f.dir, "owner.lock"); lockfd = open(path, O_RDONLY);
    CHECK(lockfd >= 0 && flock(lockfd, LOCK_EX | LOCK_NB) == 0);
    CHECK(axi_local_authority_v1_status(owner, f.grant_root, 0, &out) == AXI_LOCAL_AUTHORITY_V1_TIMEOUT);
    CHECK(!memcmp(&out, &sentinel, sizeof out));
    CHECK(flock(lockfd, LOCK_UN) == 0 && close(lockfd) == 0);

    strcpy(original, f.dir);
    n = snprintf(relocated, sizeof relocated, "%s.held", f.dir);
    CHECK(n > 0 && (size_t)n < sizeof relocated);
    CHECK(rename(original, relocated) == 0 && mkdir(original, 0700) == 0);
    strcpy(f.dir, relocated);
    CHECK(axi_local_attempt_v1_status(original, f.grant_root, &out) == 0);
    CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED);
    CHECK(axi_local_authority_v1_status(owner, f.grant_root, 0, &out) == 0);
    CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_COMMITTED && !out.effect_performed);
    f.pins.trust_snapshot_root[0] ^= 1; provision(&f);
    CHECK(axi_local_authority_v1_status(owner, f.grant_root, 0, &out) == 0);
    CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_COMMITTED && !out.effect_performed);
    path_of(path, f.dir, "epoch_active"); CHECK(unlink(path) == 0);
    memset(&facts, 0xa5, sizeof facts); sentinel_facts = facts;
    CHECK(axi_local_authority_v1_observe(owner, &facts, 0) == AXI_LOCAL_AUTHORITY_V1_REFUSED);
    CHECK(!memcmp(&facts, &sentinel_facts, sizeof facts));
    CHECK(axi_local_authority_v1_status(owner, f.grant_root, 0, &out) == 0);
    CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_COMMITTED && !out.effect_performed);
    restarted_status(&f, owner, AXI_LOCAL_ATTEMPT_V1_COMMITTED);
    check_config(f.dir, "payload", 7);

    memcpy(recname, "records/", 8);
    for (i = 0; i < 32; i++) { recname[8 + i * 2] = hex[f.grant_root[i] >> 4]; recname[9 + i * 2] = hex[f.grant_root[i] & 15]; }
    recname[72] = 0; path_of(path, f.dir, recname); put_file(path, "x", 1);
    memset(&out, 0xa5, sizeof out); sentinel = out;
    CHECK(axi_local_authority_v1_status(owner, f.grant_root, 0, &out) == AXI_LOCAL_AUTHORITY_V1_CORRUPT);
    CHECK(!memcmp(&out, &sentinel, sizeof out));
    check_config(f.dir, "payload", 7);
    axi_local_authority_v1_close(owner);
    CHECK(rmdir(original) == 0); rm_fixture(f.dir);
}

static int setup_host(void)
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
    return 0;
}

int main(int argc, char **argv)
{
    int rc = setup_host();
    if (rc) return rc;
    if (argc > 2) return 2;
    if (argc == 1 || !strcmp(argv[1], "W41")) w41();
    if (argc == 1 || !strcmp(argv[1], "W42")) w42();
    if (argc == 1 || !strcmp(argv[1], "W43")) w43();
    if (argc == 1 || !strcmp(argv[1], "W44")) w44();
    if (argc == 1 || !strcmp(argv[1], "W45")) w45();
    if (argc == 1 || !strcmp(argv[1], "W46")) w46();
    if (argc == 1 || !strcmp(argv[1], "W47")) w47();
    if (argc == 1 || !strcmp(argv[1], "W48")) w48();
    if (argc == 2 && strcmp(argv[1], "W41") && strcmp(argv[1], "W42") && strcmp(argv[1], "W43") && strcmp(argv[1], "W44") && strcmp(argv[1], "W45") && strcmp(argv[1], "W46") && strcmp(argv[1], "W47") && strcmp(argv[1], "W48")) return 2;
    printf("audit80 security: %u checks PASS (ruid=%lu euid=%lu)\n", checks,
           (unsigned long)getuid(), (unsigned long)geteuid());
    return 0;
}
