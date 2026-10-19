#include "axi_local_authority_internal.h"
#include "axi_local_store_v1.h"
#include "axi_alloc.h"
#include "axi_hash.h"
#include "axi_local_epoch_v1.h"
#include "axi_wipe.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int nonzero(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) if (p[i]) return 1;
    return 0;
}

static void put64(uint8_t *p, uint64_t n)
{
    unsigned i;
    for (i = 0; i < 8; i++) p[i] = (uint8_t)(n >> (8 * i));
}

static uint64_t get64(const uint8_t *p)
{
    uint64_t n = 0;
    unsigned i;
    for (i = 0; i < 8; i++) n |= (uint64_t)p[i] << (8 * i);
    return n;
}

static int control_read(int dirfd, uint8_t raw[AXI_LOCAL_AUTHORITY_CONTROL_SIZE])
{
    size_t n = 0;
    ssize_t got;
    uint8_t extra;
    int fd = axi_local_store_open_file_at(dirfd, AXI_LOCAL_AUTHORITY_CONTROL, O_RDONLY);
    if (fd < 0) return -1;
    while (n < AXI_LOCAL_AUTHORITY_CONTROL_SIZE) {
        got = read(fd, raw + n, AXI_LOCAL_AUTHORITY_CONTROL_SIZE - n);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { (void)close(fd); return -1; }
        n += (size_t)got;
    }
    do { got = read(fd, &extra, 1); } while (got < 0 && errno == EINTR);
    if (close(fd) != 0 || got != 0) return -1;
    return 0;
}

static int control_valid(int dirfd, const uint8_t raw[AXI_LOCAL_AUTHORITY_CONTROL_SIZE])
{
    struct stat st;
    if (axi_local_store_directory_fd(dirfd) != 0 || fstat(dirfd, &st) != 0
            || memcmp(raw, "AXLAUTH1", 8) != 0 || !nonzero(raw + 8, 32)
            || get64(raw + 40) != (uint64_t)st.st_dev
            || get64(raw + 48) != (uint64_t)st.st_ino
            || nonzero(raw + 56, 8)) return -1;
    return 0;
}

int axi_local_authority_v1_enable(const char *store_dir, const uint8_t issuer_pk[32])
{
    uint8_t raw[AXI_LOCAL_AUTHORITY_CONTROL_SIZE] = {0};
    struct stat st;
    int dirfd = -1, lockfd = -1, fd = -1, rc = AXI_LOCAL_AUTHORITY_V1_REFUSED;
    size_t n = 0;
    if (!issuer_pk || !nonzero(issuer_pk, 32)) return rc;
    dirfd = axi_local_store_open(store_dir);
    if (dirfd < 0) goto done;
    lockfd = axi_local_store_open_file_at(dirfd, "owner.lock", O_WRONLY | O_CREAT);
    if (lockfd < 0 || flock(lockfd, LOCK_EX) != 0 || fstat(dirfd, &st) != 0) goto done;
    fd = axi_local_store_open_file_at(dirfd, AXI_LOCAL_AUTHORITY_CONTROL,
                                      O_WRONLY | O_CREAT | O_EXCL);
    if (fd < 0) {
        if (errno != EEXIST || control_read(dirfd, raw) != 0
                || control_valid(dirfd, raw) != 0
                || memcmp(raw + 8, issuer_pk, 32) != 0) goto done;
        rc = fsync(dirfd) == 0 ? AXI_LOCAL_AUTHORITY_V1_OK : rc;
        goto done;
    }
    memcpy(raw, "AXLAUTH1", 8); memcpy(raw + 8, issuer_pk, 32);
    put64(raw + 40, (uint64_t)st.st_dev); put64(raw + 48, (uint64_t)st.st_ino);
    while (n < sizeof raw) {
        ssize_t wrote = write(fd, raw + n, sizeof raw - n);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) goto done;
        n += (size_t)wrote;
    }
    if (fsync(fd) != 0 || fsync(dirfd) != 0) goto done;
    rc = AXI_LOCAL_AUTHORITY_V1_OK;
done:
    if (fd >= 0 && close(fd) != 0) rc = AXI_LOCAL_AUTHORITY_V1_REFUSED;
    if (lockfd >= 0) { (void)flock(lockfd, LOCK_UN); (void)close(lockfd); }
    if (dirfd >= 0) (void)close(dirfd);
    return rc;
}

int axi_local_authority_v1_open(const char *store_dir, axi_local_authority_v1 **out)
{
    uint8_t raw[AXI_LOCAL_AUTHORITY_CONTROL_SIZE];
    axi_local_authority_v1_facts facts;
    axi_local_authority_v1 *owner = NULL;
    int dirfd = -1, lockfd = -1, rc = AXI_LOCAL_AUTHORITY_V1_REFUSED;
    if (!out) return rc;
    *out = NULL;
    rc = axi_local_authority_host_sample(&facts);
    if (rc != 0) return rc;
    rc = AXI_LOCAL_AUTHORITY_V1_REFUSED;
    dirfd = axi_local_store_open(store_dir);
    if (dirfd < 0) goto done;
    lockfd = axi_local_store_open_file_at(dirfd, "owner.lock", O_RDONLY);
    if (lockfd < 0 || flock(lockfd, LOCK_SH) != 0) goto done;
    if (control_read(dirfd, raw) != 0 || control_valid(dirfd, raw) != 0) goto done;
    owner = axi_calloc(1, sizeof *owner);
    if (!owner) goto done;
    owner->dirfd = dirfd;
    owner->device = get64(raw + 40); owner->inode = get64(raw + 48);
    memcpy(owner->issuer_pk, raw + 8, 32);
    owner->uid = facts.uid; owner->executor_uid = facts.executor_uid;
    owner->pid = getpid(); memcpy(owner->boot, facts.boot, 16);
    *out = owner;
    dirfd = -1;
    rc = AXI_LOCAL_AUTHORITY_V1_OK;
done:
    if (lockfd >= 0) { (void)flock(lockfd, LOCK_UN); (void)close(lockfd); }
    if (dirfd >= 0) (void)close(dirfd);
    return rc;
}

void axi_local_authority_v1_close(axi_local_authority_v1 *owner)
{
    if (!owner) return;
    (void)close(owner->dirfd);
    free(owner);
}

int axi_local_authority_v1_resource(const axi_local_authority_v1 *owner,
                                     uint64_t *device, uint64_t *inode)
{
    struct stat st;
    if (!owner || !device || !inode || device == inode
            || axi_local_store_directory_fd(owner->dirfd) != 0
            || fstat(owner->dirfd, &st) != 0
            || (uint64_t)st.st_dev != owner->device
            || (uint64_t)st.st_ino != owner->inode) return AXI_LOCAL_AUTHORITY_V1_REFUSED;
    *device = owner->device; *inode = owner->inode;
    return AXI_LOCAL_AUTHORITY_V1_OK;
}

int axi_local_authority_validate_locked(const axi_local_authority_v1 *owner)
{
    uint8_t raw[AXI_LOCAL_AUTHORITY_CONTROL_SIZE];
    if (!owner || owner->pid != getpid() || owner->uid != (uintmax_t)getuid()
            || owner->executor_uid != (uintmax_t)geteuid()
            || control_read(owner->dirfd, raw) != 0
            || control_valid(owner->dirfd, raw) != 0
            || memcmp(owner->issuer_pk, raw + 8, 32) != 0
            || get64(raw + 40) != owner->device
            || get64(raw + 48) != owner->inode) return AXI_LOCAL_AUTHORITY_V1_REFUSED;
    return AXI_LOCAL_AUTHORITY_V1_OK;
}

int axi_local_authority_lock(const axi_local_authority_v1 *owner,
                              int operation, uint64_t deadline, int *lockfd)
{
    int fd, rc = AXI_LOCAL_AUTHORITY_V1_REFUSED;
    if (!owner || !lockfd) return rc;
    *lockfd = -1;
    fd = axi_local_store_open_file_at(owner->dirfd, "owner.lock", O_RDONLY);
    if (fd < 0) return rc;
    for (;;) {
        uint64_t now, remaining;
        struct timespec nap;
        if (flock(fd, operation | LOCK_NB) == 0) {
            if (axi_local_authority_validate_locked(owner) == 0) {
                *lockfd = fd;
                return AXI_LOCAL_AUTHORITY_V1_OK;
            }
            (void)flock(fd, LOCK_UN);
            break;
        }
        if (errno == EINTR) continue;
        if (errno != EWOULDBLOCK && errno != EAGAIN) break;
        now = axi_local_attempt_v1_now_mono();
        if (!now) break;
        if (now >= deadline) { rc = AXI_LOCAL_AUTHORITY_V1_TIMEOUT; break; }
        remaining = deadline - now;
        nap.tv_sec = 0;
        nap.tv_nsec = (long)(remaining < UINT64_C(1000000) ? remaining : UINT64_C(1000000));
        if (nanosleep(&nap, NULL) != 0 && errno != EINTR) break;
    }
    (void)close(fd);
    return rc;
}

static int same_file(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino
        && a->st_size == b->st_size && a->st_uid == b->st_uid
        && a->st_mode == b->st_mode && a->st_nlink == b->st_nlink
        && a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec
        && a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

int axi_local_authority_previous_locked(const axi_local_authority_v1 *owner,
                                          axi_local_previous_v1 *previous,
                                          uint8_t *present)
{
    uint8_t bytes[AXI_LOCAL_ACTION_V1_MAX_BYTES], extra;
    axi_local_previous_v1 staged;
    struct stat before, after, named;
    size_t n = 0, length;
    ssize_t got;
    int fd, rc = AXI_LOCAL_AUTHORITY_V1_REFUSED;
    memset(&staged, 0, sizeof staged);
    fd = axi_local_store_open_file_at(owner->dirfd, AXI_LOCAL_ATTEMPT_V1_TARGET_NAME, O_RDONLY);
    if (fd < 0) {
        if (errno != ENOENT) return rc;
        if (fstatat(owner->dirfd, AXI_LOCAL_ATTEMPT_V1_TARGET_NAME,
                     &named, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) return rc;
        *previous = staged; *present = 0;
        return AXI_LOCAL_AUTHORITY_V1_OK;
    }
    if (fstat(fd, &before) != 0 || before.st_size < 0
            || (uintmax_t)before.st_size > sizeof bytes
            || before.st_mtim.tv_sec < 0 || before.st_mtim.tv_nsec < 0
            || before.st_mtim.tv_nsec >= 1000000000L
            || (uintmax_t)before.st_mtim.tv_sec >
                (UINT64_MAX - (uint64_t)before.st_mtim.tv_nsec) / UINT64_C(1000000000)) goto done;
    length = (size_t)before.st_size;
    while (n < length) {
        got = read(fd, bytes + n, length - n);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) goto done;
        n += (size_t)got;
    }
    do { got = read(fd, &extra, 1); } while (got < 0 && errno == EINTR);
    if (got != 0 || fstat(fd, &after) != 0 || !same_file(&before, &after)
            || fstatat(owner->dirfd, AXI_LOCAL_ATTEMPT_V1_TARGET_NAME,
                         &named, AT_SYMLINK_NOFOLLOW) != 0 || !same_file(&after, &named)) goto done;
    staged.device = (uint64_t)before.st_dev; staged.inode = (uint64_t)before.st_ino;
    staged.size = length;
    staged.mtime_ns = (uint64_t)before.st_mtim.tv_sec * UINT64_C(1000000000)
                     + (uint64_t)before.st_mtim.tv_nsec;
    axi_sha256(bytes, length, staged.sha256);
    rc = AXI_LOCAL_AUTHORITY_V1_OK;
done:
    if (close(fd) != 0) rc = AXI_LOCAL_AUTHORITY_V1_REFUSED;
    if (rc == 0) { *previous = staged; *present = 1; }
    return rc;
}

int axi_local_authority_v1_previous(const axi_local_authority_v1 *owner,
                                     axi_local_previous_v1 *previous,
                                     uint8_t *present, uint64_t deadline_mono_ns)
{
    int lockfd = -1, rc;
    if (!owner || !previous || !present) return AXI_LOCAL_AUTHORITY_V1_REFUSED;
    rc = axi_local_authority_lock(owner, LOCK_SH, deadline_mono_ns, &lockfd);
    if (rc != 0) return rc;
    rc = axi_local_authority_previous_locked(owner, previous, present);
    (void)flock(lockfd, LOCK_UN); (void)close(lockfd);
    return rc;
}

#if defined(__linux__) && defined(CLOCK_BOOTTIME) && !defined(AXI_LOCAL_AUTHORITY_NO_HOST)
static int boot_uuid(uint8_t out[16])
{
    char text[38];
    size_t n = 0, off = 0, i;
    int fd;
    uint8_t staged[16];
    fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return -1;
    while (n < sizeof text) {
        ssize_t got = read(fd, text + n, sizeof text - n);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) { (void)close(fd); return -1; }
        if (!got) break;
        n += (size_t)got;
    }
    if (close(fd) != 0 || n != 37 || text[36] != '\n') return -1;
    for (i = 0; i < 16; i++) {
        unsigned j, v = 0;
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            if (text[off++] != '-') return -1;
        }
        for (j = 0; j < 2; j++) {
            unsigned char ch = (unsigned char)text[off++];
            if (ch >= '0' && ch <= '9') v = v * 16 + ch - '0';
            else if (ch >= 'a' && ch <= 'f') v = v * 16 + ch - 'a' + 10;
            else return -1;
        }
        staged[i] = (uint8_t)v;
    }
    if (!nonzero(staged, sizeof staged)) return -1;
    memcpy(out, staged, sizeof staged);
    return 0;
}
#endif

int axi_local_authority_host_sample(axi_local_authority_v1_facts *facts)
{
#if defined(__linux__) && defined(CLOCK_BOOTTIME) && !defined(AXI_LOCAL_AUTHORITY_NO_HOST)
    axi_local_authority_v1_facts staged;
    struct timespec ts;
    uintmax_t uid = getuid(), executor = geteuid();
    if (!facts || uid == 0 || uid >= UINT32_MAX || executor == 0
            || executor >= UINT32_MAX || uid == executor) return AXI_LOCAL_AUTHORITY_V1_UNSUPPORTED;
    memset(&staged, 0, sizeof staged);
    if (boot_uuid(staged.boot) != 0 || clock_gettime(CLOCK_BOOTTIME, &ts) != 0
            || ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000L
            || (uintmax_t)ts.tv_sec > (UINT64_MAX - (uint64_t)ts.tv_nsec) / UINT64_C(1000000000))
        return AXI_LOCAL_AUTHORITY_V1_UNSUPPORTED;
    staged.now_ns = (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
    if (!staged.now_ns) return AXI_LOCAL_AUTHORITY_V1_UNSUPPORTED;
    staged.uid = (uint32_t)uid; staged.executor_uid = (uint32_t)executor;
    *facts = staged;
    return AXI_LOCAL_AUTHORITY_V1_OK;
#else
    (void)facts;
    return AXI_LOCAL_AUTHORITY_V1_UNSUPPORTED;
#endif
}

int axi_local_authority_observe_locked(const axi_local_authority_v1 *owner,
                                         axi_local_authority_v1_facts *facts)
{
    axi_local_authority_v1_facts staged;
    axi_local_epoch_v1 epoch;
    int present = 0;
    int rc = axi_local_authority_host_sample(&staged);
    if (rc != 0) return rc;
    if (owner->pid != getpid() || staged.uid != owner->uid
            || staged.executor_uid != owner->executor_uid || memcmp(staged.boot, owner->boot, 16)
            || axi_local_authority_v1_resource(owner, &staged.resource_device, &staged.resource_inode) != 0
            || axi_local_authority_previous_locked(owner, &staged.previous, &staged.has_previous) != 0)
        return AXI_LOCAL_AUTHORITY_V1_REFUSED;
    if (axi_local_epoch_v1_read_at(owner->dirfd, &epoch, &present) != 0 || !present)
        return AXI_LOCAL_AUTHORITY_V1_REFUSED;
    staged.epoch_generation = epoch.generation;
    memcpy(staged.pins.deployment, epoch.deployment, 16);
#define PIN(field) memcpy(staged.pins.field, epoch.field, 32)
    PIN(trust_snapshot_root); PIN(policy_binary); PIN(policy_module);
    PIN(policy_producer); PIN(policy_iface);
#undef PIN
    *facts = staged;
    return AXI_LOCAL_AUTHORITY_V1_OK;
}

int axi_local_authority_v1_observe(const axi_local_authority_v1 *owner,
                                    axi_local_authority_v1_facts *out,
                                    uint64_t deadline_mono_ns)
{
    int lockfd = -1, rc;
    if (!owner || !out) return AXI_LOCAL_AUTHORITY_V1_REFUSED;
    rc = axi_local_authority_lock(owner, LOCK_SH, deadline_mono_ns, &lockfd);
    if (rc != 0) return rc;
    rc = axi_local_authority_observe_locked(owner, out);
    (void)flock(lockfd, LOCK_UN); (void)close(lockfd);
    return rc;
}

int axi_local_authority_action_matches(const axi_local_action_v1 *action,
                                         const axi_local_authority_v1_facts *facts)
{
    if (action->uid != facts->uid || action->executor_uid != facts->executor_uid
            || action->resource_device != facts->resource_device
            || action->resource_inode != facts->resource_inode
            || action->has_previous != facts->has_previous) return 0;
    if (action->has_previous) {
        const axi_local_previous_v1 *a = &action->previous, *b = &facts->previous;
        if (a->device != b->device || a->inode != b->inode || a->size != b->size
                || a->mtime_ns != b->mtime_ns || memcmp(a->sha256, b->sha256, 32)) return 0;
    }
    return 1;
}

int axi_local_authority_v1_prepare(const axi_local_authority_v1 *owner,
                                    const void *action_bytes, size_t action_len,
                                    const uint8_t *payload, size_t payload_len,
                                    uint64_t deadline_mono_ns,
                                    axi_local_authority_v1_prepared **out,
                                    axi_local_admission_v1_result *admission)
{
    axi_local_authority_v1_prepared *prepared = NULL;
    axi_local_admission_v1_result result;
    uint8_t digest[32];
    int lockfd = -1, rc = AXI_LOCAL_AUTHORITY_V1_REFUSED, dupfd = -1;
    memset(&result, 0, sizeof result);
    result.refusal = AXI_LOCAL_ADMISSION_V1_REFUSE_INPUT;
    if (out) *out = NULL;
    if (admission) *admission = result;
    if (!owner || !out || !admission || !action_bytes || !action_len
            || action_len > AXI_LOCAL_ACTION_V1_MAX_BYTES
            || payload_len > AXI_LOCAL_ACTION_V1_MAX_BYTES || (!payload && payload_len)) return rc;
    prepared = axi_calloc(1, sizeof *prepared);
    if (!prepared) return rc;
    prepared->owner.dirfd = -1;
    prepared->action_len = action_len; prepared->payload_len = payload_len;
    memcpy(prepared->action_bytes, action_bytes, action_len);
    if (payload_len) memcpy(prepared->payload, payload, payload_len);
    if (axi_local_action_v1_decode(&prepared->action, prepared->action_bytes, action_len) != 0
            || prepared->action.payload_size != payload_len) goto done;
    axi_sha256(prepared->payload, payload_len, digest);
    if (memcmp(digest, prepared->action.payload_sha256, 32)) goto done;
    rc = axi_local_authority_lock(owner, LOCK_SH, deadline_mono_ns, &lockfd);
    if (rc != 0) goto done;
    rc = axi_local_authority_observe_locked(owner, &prepared->facts);
    if (rc != 0) goto done;
    rc = AXI_LOCAL_AUTHORITY_V1_REFUSED;
    if (!axi_local_authority_action_matches(&prepared->action, &prepared->facts)) {
        result.refusal = AXI_LOCAL_ADMISSION_V1_REFUSE_BINDING;
        goto done;
    }
    memcpy(prepared->observed.boot, prepared->facts.boot, 16);
    prepared->observed.now_ns = prepared->facts.now_ns;
    prepared->observed.clock_available = 1;
    prepared->observed.coverage_complete = 1;
    prepared->observed.profile = AXI_LOCAL_ADMISSION_V1_PROD;
    if (axi_local_admission_v1_appraise(prepared->action_bytes, action_len,
            &prepared->facts.pins, &prepared->observed, &result) != 0 || !result.admitted) goto done;
    dupfd = fcntl(owner->dirfd, F_DUPFD_CLOEXEC, 0);
    if (dupfd < 0) {
        result.admitted = 0; result.refusal = AXI_LOCAL_ADMISSION_V1_REFUSE_INPUT;
        memset(result.context_root, 0, sizeof result.context_root);
        goto done;
    }
    prepared->owner = *owner; prepared->owner.dirfd = dupfd; dupfd = -1;
    prepared->admission = result;
    *out = prepared; prepared = NULL;
    rc = AXI_LOCAL_AUTHORITY_V1_OK;
done:
    if (lockfd >= 0) { (void)flock(lockfd, LOCK_UN); (void)close(lockfd); }
    if (dupfd >= 0) (void)close(dupfd);
    if (prepared) { axi_private_wipe(prepared, sizeof *prepared); free(prepared); }
    *admission = result;
    return rc;
}

void axi_local_authority_v1_prepared_close(axi_local_authority_v1_prepared *prepared)
{
    if (!prepared) return;
    (void)close(prepared->owner.dirfd);
    axi_private_wipe(prepared, sizeof *prepared);
    free(prepared);
}

int axi_local_authority_v1_commit(const axi_local_authority_v1_prepared *prepared,
                                   const uint8_t *grant_signed, size_t grant_len,
                                   uint64_t deadline_mono_ns,
                                   axi_local_attempt_v1_outcome *out)
{
    return axi_local_attempt_authority_commit(prepared, grant_signed, grant_len,
                                               deadline_mono_ns, out);
}
