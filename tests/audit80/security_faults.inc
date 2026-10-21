/* Product-only fsync redirection: real time advances, identities stay real. */
#define main audit80_ordinary_main
#include "security.c"
#undef main
#include "axi_alloc.h"
#include <stdarg.h>

static int delay_mode, delay_done;
enum {
    AF80_NONE, AF80_SHORT_READ, AF80_CONTROL_READ, AF80_CONFIG_READ, AF80_BOOT_READ,
    AF80_CLOCK_ERROR, AF80_CLOCK_NEGATIVE, AF80_CLOCK_NSEC, AF80_CLOCK_OVERFLOW,
    AF80_ALLOC, AF80_DUPFD, AF80_CONTROL_ZERO, AF80_CONTROL_PARTIAL, AF80_CONTROL_FSYNC,
    AF80_SPEND_UNLINK, AF80_SPEND_DIR_UNLINK, AF80_PARTIAL_UNLINK, AF80_CLEANUP_FSYNC
};
static int fault, fault_hits, cleanup_hits;

static int fd_path(int fd, char path[512])
{
    char link[64];
    ssize_t n;
    if (snprintf(link, sizeof link, "/proc/self/fd/%d", fd) <= 0) return 0;
    n = readlink(link, path, 511);
    if (n < 0 || n >= 511) return 0;
    path[n] = 0;
    return 1;
}

static int fd_suffix(int fd, const char *suffix)
{
    char path[512];
    size_t a, b = strlen(suffix);
    if (!fd_path(fd, path)) return 0;
    a = strlen(path);
    return a >= b && !strcmp(path + a - b, suffix);
}

static int spend_file(int fd)
{
    char path[512], *name;
    return fd_path(fd, path) && (name = strstr(path, "/records/")) != NULL
        && strlen(name + 9) == 64;
}

static unsigned descriptor_count(void)
{
    DIR *d = opendir("/proc/self/fd");
    struct dirent *e;
    unsigned n = 0;
    CHECK(d != NULL);
    while ((e = readdir(d)) != NULL)
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) n++;
    CHECK(closedir(d) == 0);
    return n;
}

static void set_fault(int value)
{
    fault = value; fault_hits = 0; cleanup_hits = 0;
}

ssize_t audit80_read(int fd, void *bytes, size_t len)
{
    if (fault == AF80_SHORT_READ) {
        if (fault_hits++ == 0) { errno = EINTR; return -1; }
        return read(fd, bytes, len > 1 ? 1 : len);
    }
    if ((fault == AF80_CONTROL_READ && fd_suffix(fd, "/authority_v1"))
            || (fault == AF80_CONFIG_READ && fd_suffix(fd, "/config"))
            || (fault == AF80_BOOT_READ && fd_suffix(fd, "/boot_id"))) {
        fault_hits++; errno = EIO; return -1;
    }
    return read(fd, bytes, len);
}

ssize_t audit80_write(int fd, const void *bytes, size_t len)
{
    if (fd_suffix(fd, "/authority_v1")) {
        if (fault == AF80_CONTROL_ZERO) { fault_hits++; return 0; }
        if (fault == AF80_CONTROL_PARTIAL) {
            if (fault_hits++ == 0) return write(fd, bytes, len > 7 ? 7 : len);
            return 0;
        }
    }
    if ((fault == AF80_PARTIAL_UNLINK || fault == AF80_CLEANUP_FSYNC) && spend_file(fd)) {
        if (fault_hits++ == 0) return write(fd, bytes, len > 7 ? 7 : len);
        return 0;
    }
    return write(fd, bytes, len);
}

int audit80_unlinkat(int dirfd, const char *name, int flags)
{
    if ((fault == AF80_SPEND_UNLINK || fault == AF80_SPEND_DIR_UNLINK || fault == AF80_PARTIAL_UNLINK)
            && strlen(name) == 64 && fd_suffix(dirfd, "/records")) {
        cleanup_hits++; errno = EACCES; return -1;
    }
    return unlinkat(dirfd, name, flags);
}

void *audit80_calloc(size_t count, size_t size)
{
    if (fault == AF80_ALLOC) { fault_hits++; errno = ENOMEM; return NULL; }
    return axi_calloc(count, size);
}

int audit80_fcntl(int fd, int command, ...)
{
    va_list ap;
    int value;
    va_start(ap, command); value = va_arg(ap, int); va_end(ap);
    if (fault == AF80_DUPFD && command == F_DUPFD_CLOEXEC) {
        fault_hits++; errno = EMFILE; return -1;
    }
    return fcntl(fd, command, value);
}

int audit80_clock_gettime(clockid_t clock_id, struct timespec *ts)
{
    if (clock_id == CLOCK_BOOTTIME) {
        if (fault == AF80_CLOCK_ERROR) { fault_hits++; errno = EIO; return -1; }
        if (fault >= AF80_CLOCK_NEGATIVE && fault <= AF80_CLOCK_OVERFLOW) {
            fault_hits++;
            if (fault == AF80_CLOCK_NEGATIVE) { ts->tv_sec = -1; ts->tv_nsec = 0; }
            if (fault == AF80_CLOCK_NSEC) { ts->tv_sec = 1; ts->tv_nsec = 1000000000L; }
            if (fault == AF80_CLOCK_OVERFLOW) {
                if (sizeof(time_t) < 8) { errno = EOVERFLOW; return -1; }
                ts->tv_sec = (time_t)(UINT64_MAX / UINT64_C(1000000000) + 1); ts->tv_nsec = 0;
            }
            return 0; /* Deliberately invalid provider output must refuse. */
        }
    }
    return clock_gettime(clock_id, ts);
}

int audit80_fsync(int fd)
{
    char link[64], path[512];
    ssize_t n;
    int rc, selected = 0;
    if (fault == AF80_CONTROL_FSYNC && fd_suffix(fd, "/authority_v1")) {
        fault_hits++; errno = EIO; return -1;
    }
    if ((fault == AF80_SPEND_UNLINK && spend_file(fd) && !fault_hits)
            || (fault == AF80_SPEND_DIR_UNLINK && fd_suffix(fd, "/records") && !fault_hits)) {
        CHECK(fsync(fd) == 0); fault_hits++; errno = EIO; return -1;
    }
    if (fault == AF80_CLEANUP_FSYNC && fd_suffix(fd, "/records")) {
        cleanup_hits++; errno = EIO; return -1;
    }
    rc = fsync(fd);
    if (rc != 0 || !delay_mode || delay_done) return rc;
    CHECK(snprintf(link, sizeof link, "/proc/self/fd/%d", fd) > 0);
    n = readlink(link, path, sizeof path - 1);
    CHECK(n >= 0 && (size_t)n < sizeof path - 1); path[n] = 0;
    if (delay_mode == 1 && strstr(path, "/records/") != NULL) selected = 1;
    if (delay_mode == 2 && strstr(path, "/.tmp.attempt") != NULL) selected = 1;
    if (selected) { delay_done = 1; expire_pause(); }
    return rc;
}

static void spend_cleanup(int injected)
{
    fixture f;
    axi_local_authority_v1 *owner = NULL;
    axi_local_authority_v1_prepared *prepared;
    axi_local_attempt_v1_outcome out;
    unsigned fds;
    new_fixture(&f); provision(&f);
    CHECK(axi_local_authority_v1_enable(f.dir, f.pk) == 0);
    CHECK(axi_local_authority_v1_open(f.dir, &owner) == 0);
    prepared = ready(&f, owner); fds = descriptor_count();
    set_fault(injected);
    CHECK(axi_local_authority_v1_commit(prepared, f.grant, sizeof f.grant, 0, &out)
            == AXI_LOCAL_AUTHORITY_V1_REFUSED);
    CHECK(fault_hits > 0 && cleanup_hits > 0);
    CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_UNKNOWN && !out.effect_performed);
    set_fault(AF80_NONE);
    CHECK(descriptor_count() == fds);
    CHECK(!exists(f.dir, "config") && !exists(f.dir, ".tmp.attempt"));
    if (injected == AF80_PARTIAL_UNLINK) {
        CHECK(axi_local_authority_v1_status(owner, f.grant_root, 0, &out) == AXI_LOCAL_AUTHORITY_V1_CORRUPT);
        CHECK(axi_local_authority_v1_commit(prepared, f.grant, sizeof f.grant, 0, &out) == AXI_LOCAL_AUTHORITY_V1_CORRUPT);
    } else {
        CHECK(axi_local_authority_v1_status(owner, f.grant_root, 0, &out) == 0);
        CHECK(out.state == (injected == AF80_CLEANUP_FSYNC ? AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED : AXI_LOCAL_ATTEMPT_V1_UNKNOWN));
        if (injected != AF80_CLEANUP_FSYNC) {
            CHECK(axi_local_authority_v1_commit(prepared, f.grant, sizeof f.grant, 0, &out) == AXI_LOCAL_AUTHORITY_V1_REFUSED);
            CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_UNKNOWN && !out.effect_performed);
        }
    }
    axi_local_authority_v1_prepared_close(prepared); axi_local_authority_v1_close(owner);
    rm_fixture(f.dir);
}

static void source_and_ownership_faults(void)
{
    fixture f;
    axi_local_authority_v1 *owner = NULL, *bad = NULL;
    axi_local_authority_v1_prepared *prepared = NULL;
    axi_local_admission_v1_result adm;
    axi_local_authority_v1_facts facts, sentinel;
    axi_local_attempt_v1_outcome out;
    char path[512];
    const int sources[] = {AF80_CONTROL_READ, AF80_CONFIG_READ, AF80_BOOT_READ,
                            AF80_CLOCK_ERROR, AF80_CLOCK_NEGATIVE, AF80_CLOCK_NSEC, AF80_CLOCK_OVERFLOW};
    unsigned i, fds;
    new_fixture(&f); provision(&f);
    CHECK(axi_local_authority_v1_enable(f.dir, f.pk) == 0);
    CHECK(axi_local_authority_v1_open(f.dir, &owner) == 0);
    path_of(path, f.dir, "config"); put_file(path, "before", 6);
    fds = descriptor_count();
    for (i = 0; i < sizeof sources / sizeof sources[0]; i++) {
        int rc;
        memset(&facts, 0xa5, sizeof facts); sentinel = facts;
        set_fault(sources[i]);
        rc = axi_local_authority_v1_observe(owner, &facts, 0);
        if (rc == 0 || !fault_hits)
            fprintf(stderr, "audit80 source fault=%d rc=%d hits=%d\n", sources[i], rc, fault_hits);
        CHECK(rc != 0 && fault_hits > 0);
        CHECK(!memcmp(&facts, &sentinel, sizeof facts));
        set_fault(AF80_NONE);
        CHECK(descriptor_count() == fds && !exists(f.dir, "records"));
        check_config(f.dir, "before", 6);
    }
    set_fault(AF80_SHORT_READ);
    CHECK(axi_local_authority_v1_observe(owner, &facts, 0) == 0 && fault_hits > 100);
    CHECK(facts.uid == (uint32_t)getuid() && facts.executor_uid == (uint32_t)geteuid());
    CHECK(facts.has_previous && facts.previous.size == 6);
    set_fault(AF80_NONE);
    set_fault(AF80_ALLOC);
    CHECK(axi_local_authority_v1_open(f.dir, &bad) == AXI_LOCAL_AUTHORITY_V1_REFUSED && bad == NULL && fault_hits == 1);
    set_fault(AF80_NONE);
    CHECK(descriptor_count() == fds);
    measured_action(&f, owner);
    for (i = 0; i < 2; i++) {
        set_fault(i == 0 ? AF80_ALLOC : AF80_DUPFD);
        CHECK(axi_local_authority_v1_prepare(owner, f.action_bytes, f.action_len,
                (const uint8_t *)"payload", 7, 0, &prepared, &adm) == AXI_LOCAL_AUTHORITY_V1_REFUSED);
        CHECK(prepared == NULL && !adm.admitted && adm.refusal != 0 && fault_hits == 1);
        set_fault(AF80_NONE);
        CHECK(descriptor_count() == fds && !exists(f.dir, "records"));
    }
    prepared = ready(&f, owner); fds = descriptor_count();
    set_fault(AF80_DUPFD);
    CHECK(axi_local_authority_v1_commit(prepared, f.grant, sizeof f.grant, 0, &out) == AXI_LOCAL_AUTHORITY_V1_REFUSED);
    CHECK(fault_hits == 1 && out.state == AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED && !out.effect_performed);
    set_fault(AF80_NONE);
    CHECK(descriptor_count() == fds && !exists(f.dir, "records"));
    check_config(f.dir, "before", 6);
    axi_local_authority_v1_prepared_close(prepared); axi_local_authority_v1_close(owner);
    rm_fixture(f.dir);
}

static void incomplete_activation(int injected)
{
    fixture f;
    axi_local_authority_v1 *owner = NULL;
    axi_local_attempt_v1_outcome out;
    unsigned fds;
    new_fixture(&f); mint(&f, NULL); fds = descriptor_count();
    set_fault(injected);
    CHECK(axi_local_authority_v1_enable(f.dir, f.pk) == AXI_LOCAL_AUTHORITY_V1_REFUSED && fault_hits > 0);
    set_fault(AF80_NONE);
    CHECK(descriptor_count() == fds && exists(f.dir, "authority_v1"));
    CHECK(axi_local_authority_v1_enable(f.dir, f.pk) == AXI_LOCAL_AUTHORITY_V1_REFUSED);
    CHECK(axi_local_authority_v1_open(f.dir, &owner) == AXI_LOCAL_AUTHORITY_V1_REFUSED && owner == NULL);
    CHECK(axi_local_attempt_v1_commit(f.dir, f.grant, sizeof f.grant, f.pk,
            f.action_bytes, f.action_len, &f.pins, &f.observed,
            (const uint8_t *)"payload", 7, f.observed.now_ns, &out) == AXI_LOCAL_AUTHORITY_V1_REFUSED);
    CHECK(!out.effect_performed && !exists(f.dir, "config") && !exists(f.dir, "records"));
    rm_fixture(f.dir);
}

static void activation_sync_retry(void)
{
    fixture f;
    axi_local_authority_v1 *owner = NULL;
    unsigned fds;
    new_fixture(&f); fds = descriptor_count();
    set_fault(AF80_CONTROL_FSYNC);
    CHECK(axi_local_authority_v1_enable(f.dir, f.pk) == AXI_LOCAL_AUTHORITY_V1_REFUSED && fault_hits == 1);
    CHECK(axi_local_authority_v1_enable(f.dir, f.pk) == AXI_LOCAL_AUTHORITY_V1_REFUSED && fault_hits == 2);
    set_fault(AF80_NONE);
    CHECK(descriptor_count() == fds);
    CHECK(axi_local_authority_v1_enable(f.dir, f.pk) == 0);
    CHECK(axi_local_authority_v1_open(f.dir, &owner) == 0);
    axi_local_authority_v1_close(owner);
    CHECK(descriptor_count() == fds && !exists(f.dir, "config") && !exists(f.dir, "records"));
    rm_fixture(f.dir);
}

static void delayed_expiry(int mode)
{
    fixture f;
    axi_local_authority_v1 *owner = NULL;
    axi_local_authority_v1_prepared *prepared;
    axi_local_attempt_v1_outcome out;
    new_fixture(&f); provision(&f);
    CHECK(axi_local_authority_v1_enable(f.dir, f.pk) == 0);
    CHECK(axi_local_authority_v1_open(f.dir, &owner) == 0);
    f.action.ttl_ns = UINT64_C(1000000000);
    prepared = ready(&f, owner);
    delay_mode = mode; delay_done = 0;
    CHECK(axi_local_authority_v1_commit(prepared, f.grant, sizeof f.grant, 0, &out)
            == AXI_LOCAL_AUTHORITY_V1_REFUSED);
    CHECK(delay_done == 1 && out.state == AXI_LOCAL_ATTEMPT_V1_UNKNOWN && !out.effect_performed);
    delay_mode = 0;
    CHECK(!exists(f.dir, "config") && !exists(f.dir, ".tmp.attempt"));
    CHECK(axi_local_attempt_v1_status(f.dir, f.grant_root, &out) == 0);
    CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_UNKNOWN && !out.effect_performed);
    CHECK(axi_local_authority_v1_status(owner, f.grant_root, 0, &out) == 0);
    CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_UNKNOWN && !out.effect_performed);
    restarted_status(&f, owner, AXI_LOCAL_ATTEMPT_V1_UNKNOWN);
    CHECK(axi_local_authority_v1_commit(prepared, f.grant, sizeof f.grant, 0, &out)
            == AXI_LOCAL_AUTHORITY_V1_REFUSED);
    CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_UNKNOWN && !out.effect_performed);
    axi_local_authority_v1_prepared_close(prepared); axi_local_authority_v1_close(owner);
    rm_fixture(f.dir);
}

int main(int argc, char **argv)
{
    int rc = setup_host();
    if (rc) return rc;
    if (argc > 2) return 2;
    if (argc == 1 || !strcmp(argv[1], "expiry")) { delayed_expiry(1); delayed_expiry(2); }
    if (argc == 1 || !strcmp(argv[1], "cleanup")) {
        spend_cleanup(AF80_SPEND_UNLINK); spend_cleanup(AF80_SPEND_DIR_UNLINK);
        spend_cleanup(AF80_PARTIAL_UNLINK); spend_cleanup(AF80_CLEANUP_FSYNC);
    }
    if (argc == 1 || !strcmp(argv[1], "sources")) {
        source_and_ownership_faults(); incomplete_activation(AF80_CONTROL_ZERO); incomplete_activation(AF80_CONTROL_PARTIAL);
        activation_sync_retry();
    }
    if (argc == 2 && strcmp(argv[1], "expiry") && strcmp(argv[1], "cleanup") && strcmp(argv[1], "sources")) return 2;
    printf("audit80 security faults: %u checks PASS (real host, injected failures)\n", checks);
    return 0;
}
