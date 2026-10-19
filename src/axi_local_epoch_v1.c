/* ADR-059 AXV2-12: explicit epoch lifecycle, fixture-only. See header. */
#include "axi_local_epoch_v1.h"

#include "axi_local_attempt_v1.h"
#include "axi_local_store_v1.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define EPOCH_MAGIC_0 'A'
#define EPOCH_MAGIC_1 'X'
#define EPOCH_MAGIC_2 'E'
#define EPOCH_MAGIC_3 '1'
#define EPOCH_VERSION 1u
#define EPOCH_RECORD_SIZE (4u + 4u + 8u + 16u + 5u * 32u)

static int nonzero(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (p[i]) {
            return 1;
        }
    }
    return 0;
}

/* AXI-INV-217 (S6-FINDING-01): resource exhaustion is transient,
 * never corruption. EMFILE/ENFILE/ENOMEM while reading trust config
 * must refuse (re-query), never report CORRUPT for an undamaged file.
 */
static int err_transient(void)
{
    return errno == EMFILE || errno == ENFILE || errno == ENOMEM;
}

static int pins_valid(const axi_local_epoch_v1 *e)
{
    return e && e->generation > 0
        && nonzero(e->deployment, 16)
        && nonzero(e->trust_snapshot_root, 32)
        && nonzero(e->policy_binary, 32)
        && nonzero(e->policy_module, 32)
        && nonzero(e->policy_producer, 32)
        && nonzero(e->policy_iface, 32);
}

static void epoch_pack(uint8_t out[EPOCH_RECORD_SIZE],
                       const axi_local_epoch_v1 *e)
{
    size_t i;
    memset(out, 0, EPOCH_RECORD_SIZE);
    out[0] = EPOCH_MAGIC_0;
    out[1] = EPOCH_MAGIC_1;
    out[2] = EPOCH_MAGIC_2;
    out[3] = EPOCH_MAGIC_3;
    out[4] = EPOCH_VERSION;
    for (i = 0; i < 8; i++) {
        out[8 + i] = (uint8_t)((e->generation >> (8 * i)) & 0xff);
    }
    memcpy(out + 16, e->deployment, 16);
    memcpy(out + 32, e->trust_snapshot_root, 32);
    memcpy(out + 64, e->policy_binary, 32);
    memcpy(out + 96, e->policy_module, 32);
    memcpy(out + 128, e->policy_producer, 32);
    memcpy(out + 160, e->policy_iface, 32);
}

static int epoch_unpack(const uint8_t in[EPOCH_RECORD_SIZE],
                        axi_local_epoch_v1 *e)
{
    size_t i;
    uint64_t gen = 0;
    if (in[0] != EPOCH_MAGIC_0 || in[1] != EPOCH_MAGIC_1 ||
        in[2] != EPOCH_MAGIC_2 || in[3] != EPOCH_MAGIC_3 ||
        in[4] != EPOCH_VERSION || in[5] != 0 || in[6] != 0 || in[7] != 0) {
        return -1;
    }
    for (i = 0; i < 8; i++) {
        gen = gen | ((uint64_t)in[8 + i] << (8 * i));
    }
    memset(e, 0, sizeof(*e));
    e->generation = gen;
    memcpy(e->deployment, in + 16, 16);
    memcpy(e->trust_snapshot_root, in + 32, 32);
    memcpy(e->policy_binary, in + 64, 32);
    memcpy(e->policy_module, in + 96, 32);
    memcpy(e->policy_producer, in + 128, 32);
    memcpy(e->policy_iface, in + 160, 32);
    return pins_valid(e) ? 0 : -1;
}

static int write_full_fsync_at(int dirfd, const char *name, const void *data,
                               size_t len)
{
    int fd = axi_local_store_open_file_at(dirfd, name, O_WRONLY | O_CREAT | O_TRUNC);
    size_t off = 0;
    if (fd < 0) {
        return -1;
    }
    while (off < len) {
        ssize_t w = write(fd, (const char *)data + off, len - off);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return -1;
        }
        off += (size_t)w;
    }
    if (fsync(fd) != 0) {
        close(fd);
        return -1;
    }
    return close(fd);
}

static int read_exact_at(int dirfd, const char *name,
                         uint8_t out[EPOCH_RECORD_SIZE], int *present)
{
    int fd = axi_local_store_open_file_at(dirfd, name, O_RDONLY);
    size_t off = 0;
    uint8_t extra;
    ssize_t r;
    *present = 0;
    if (fd < 0) {
        if (errno == ENOENT) {
            return 0;
        }
        return err_transient() ? -2 : -1;
    }
    while (off < EPOCH_RECORD_SIZE) {
        r = read(fd, out + off, EPOCH_RECORD_SIZE - off);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            {
                int t = err_transient();
                close(fd);
                return t ? -2 : -1;
            }
        }
        if (r == 0) {
            break;
        }
        off += (size_t)r;
    }
    if (off != EPOCH_RECORD_SIZE) {
        close(fd);
        return -1;
    }
    r = read(fd, &extra, 1);
    close(fd);
    if (r != 0) {
        return -1;
    }
    *present = 1;
    return 0;
}

int axi_local_epoch_v1_provision(const char *store_dir,
                                 const axi_local_epoch_v1 *pins,
                                 uint64_t *out_generation)
{
    int sdfd = -1, lockfd = -1, rec = -1;
    uint8_t raw[EPOCH_RECORD_SIZE];
    int present = 0;
    axi_local_epoch_v1 cur, staged;
    uint64_t gen;
    if (!pins || !nonzero(pins->deployment, 16)
            || !nonzero(pins->trust_snapshot_root, 32)
            || !nonzero(pins->policy_binary, 32)
            || !nonzero(pins->policy_module, 32)
            || !nonzero(pins->policy_producer, 32)
            || !nonzero(pins->policy_iface, 32)) {
        return AXI_LOCAL_EPOCH_V1_REFUSED;
    }
    if (axi_local_attempt_v1_store_check(store_dir) !=
        AXI_LOCAL_ATTEMPT_V1_OK) {
        return AXI_LOCAL_EPOCH_V1_REFUSED;
    }
    sdfd = axi_local_store_open(store_dir);
    if (sdfd < 0) {
        return AXI_LOCAL_EPOCH_V1_REFUSED;
    }
    lockfd = axi_local_store_open_file_at(sdfd, "owner.lock", O_WRONLY | O_CREAT);
    if (lockfd < 0 || flock(lockfd, LOCK_EX) != 0) {
        rec = AXI_LOCAL_EPOCH_V1_REFUSED;
        goto done;
    }
    if (read_exact_at(sdfd, "epoch_active", raw, &present) != 0
            || (present && epoch_unpack(raw, &cur) != 0)) {
        rec = AXI_LOCAL_EPOCH_V1_CORRUPT;
        goto done;
    }
    gen = present ? cur.generation + 1 : 1;
    if (gen == 0) {
        rec = AXI_LOCAL_EPOCH_V1_CORRUPT;
        goto done;
    }
    memset(&staged, 0, sizeof(staged));
    staged.generation = gen;
    memcpy(staged.deployment, pins->deployment, 16);
    memcpy(staged.trust_snapshot_root, pins->trust_snapshot_root, 32);
    memcpy(staged.policy_binary, pins->policy_binary, 32);
    memcpy(staged.policy_module, pins->policy_module, 32);
    memcpy(staged.policy_producer, pins->policy_producer, 32);
    memcpy(staged.policy_iface, pins->policy_iface, 32);
    epoch_pack(raw, &staged);
    if (write_full_fsync_at(sdfd, ".tmp.epoch", raw, sizeof(raw)) != 0
            || renameat(sdfd, ".tmp.epoch", sdfd, "epoch_pending") != 0
            || fsync(sdfd) != 0) {
        unlinkat(sdfd, ".tmp.epoch", 0);
        rec = AXI_LOCAL_EPOCH_V1_REFUSED;
        goto done;
    }
    if (out_generation) {
        *out_generation = gen;
    }
    rec = AXI_LOCAL_EPOCH_V1_OK;

done:
    if (lockfd >= 0) {
        flock(lockfd, LOCK_UN);
        close(lockfd);
    }
    if (sdfd >= 0) {
        close(sdfd);
    }
    return rec;
}

int axi_local_epoch_v1_activate(const char *store_dir, uint64_t generation)
{
    int sdfd = -1, lockfd = -1, rec = -1;
    uint8_t raw[EPOCH_RECORD_SIZE];
    int present = 0, active_present = 0;
    axi_local_epoch_v1 pend, cur;
    uint64_t want;
    if (generation == 0) {
        return AXI_LOCAL_EPOCH_V1_REFUSED;
    }
    if (axi_local_attempt_v1_store_check(store_dir) !=
        AXI_LOCAL_ATTEMPT_V1_OK) {
        return AXI_LOCAL_EPOCH_V1_REFUSED;
    }
    sdfd = axi_local_store_open(store_dir);
    if (sdfd < 0) {
        return AXI_LOCAL_EPOCH_V1_REFUSED;
    }
    lockfd = axi_local_store_open_file_at(sdfd, "owner.lock", O_WRONLY | O_CREAT);
    if (lockfd < 0 || flock(lockfd, LOCK_EX) != 0) {
        rec = AXI_LOCAL_EPOCH_V1_REFUSED;
        goto done;
    }
    if (read_exact_at(sdfd, "epoch_pending", raw, &present) != 0
            || !present || epoch_unpack(raw, &pend) != 0) {
        rec = AXI_LOCAL_EPOCH_V1_REFUSED;
        goto done;
    }
    if (read_exact_at(sdfd, "epoch_active", raw, &active_present) != 0
            || (active_present && epoch_unpack(raw, &cur) != 0)) {
        rec = AXI_LOCAL_EPOCH_V1_CORRUPT;
        goto done;
    }
    want = active_present ? cur.generation + 1 : 1;
    if (pend.generation != generation || pend.generation != want) {
        rec = AXI_LOCAL_EPOCH_V1_REFUSED;
        goto done;
    }
    if (renameat(sdfd, "epoch_pending", sdfd, "epoch_active") != 0
            || fsync(sdfd) != 0) {
        rec = AXI_LOCAL_EPOCH_V1_REFUSED;
        goto done;
    }
    rec = AXI_LOCAL_EPOCH_V1_OK;

done:
    if (lockfd >= 0) {
        flock(lockfd, LOCK_UN);
        close(lockfd);
    }
    if (sdfd >= 0) {
        close(sdfd);
    }
    return rec;
}

int axi_local_epoch_v1_current(const char *store_dir,
                               axi_local_epoch_v1 *out)
{
    int sdfd = -1;
    uint8_t raw[EPOCH_RECORD_SIZE];
    int present = 0;
    if (!out) {
        return AXI_LOCAL_EPOCH_V1_REFUSED;
    }
    memset(out, 0, sizeof(*out));
    if (axi_local_attempt_v1_store_check(store_dir) !=
        AXI_LOCAL_ATTEMPT_V1_OK) {
        return AXI_LOCAL_EPOCH_V1_REFUSED;
    }
    sdfd = axi_local_store_open(store_dir);
    if (sdfd < 0) {
        return AXI_LOCAL_ATTEMPT_V1_REFUSED;
    }
    if (read_exact_at(sdfd, "epoch_active", raw, &present) != 0) {
        close(sdfd);
        return AXI_LOCAL_EPOCH_V1_CORRUPT;
    }
    close(sdfd);
    if (!present) {
        return AXI_LOCAL_EPOCH_V1_REFUSED;
    }
    return epoch_unpack(raw, out) == 0 ? AXI_LOCAL_EPOCH_V1_OK
                                       : AXI_LOCAL_EPOCH_V1_CORRUPT;
}

int axi_local_epoch_v1_enforce(int dirfd,
                               const axi_local_admission_v1_pins *pins)
{
    uint8_t raw[EPOCH_RECORD_SIZE];
    int present = 0;
    axi_local_epoch_v1 cur;
    int rr;
    if (dirfd < 0 || !pins) {
        return -2;
    }
    rr = read_exact_at(dirfd, "epoch_active", raw, &present);
    if (rr == -2) {
        return -3;
    }
    if (rr != 0) {
        return -2;
    }
    if (!present) {
        return 0;
    }
    if (epoch_unpack(raw, &cur) != 0) {
        return -2;
    }
    if (memcmp(cur.deployment, pins->deployment, 16) != 0
            || memcmp(cur.trust_snapshot_root, pins->trust_snapshot_root,
                      32) != 0
            || memcmp(cur.policy_binary, pins->policy_binary, 32) != 0
            || memcmp(cur.policy_module, pins->policy_module, 32) != 0
            || memcmp(cur.policy_producer, pins->policy_producer, 32) != 0
            || memcmp(cur.policy_iface, pins->policy_iface, 32) != 0) {
        return -1;
    }
    return 0;
}

int axi_local_epoch_v1_read_at(int dirfd, axi_local_epoch_v1 *out,
                               int *present)
{
    uint8_t raw[EPOCH_RECORD_SIZE];
    int rr;
    if (!out || !present) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    *present = 0;
    if (dirfd < 0) {
        return -1;
    }
    rr = read_exact_at(dirfd, "epoch_active", raw, present);
    if (rr == -2) {
        return -2;
    }
    if (rr != 0) {
        return -1;
    }
    if (!*present) {
        return 0;
    }
    return epoch_unpack(raw, out) == 0 ? 0 : -1;
}
