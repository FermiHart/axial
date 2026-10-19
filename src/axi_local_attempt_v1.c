/* ADR-059 AXV2-07 / D04: durable AG1 attempt owner, narrow local profile.
 *
 * Fixture-only C implementation; no installed ABI promise, no production
 * runner, no Beyond wiring. See axi_local_attempt_v1.h for the contract.
 * Reuses the AG1 signed codec + matching, the 05 codec/roots, the 06
 * appraisal and the canonical SHA-256. Never touches the legacy
 * root-only consume_spent() ledger: the versioned record keyed by the
 * grant root is the sole spent authority for this profile.
 *
 * Pathname discipline: the store is opened once as a dirfd and every later
 * access uses openat/mkdirat/renameat with short relative names, so no
 * 4096-byte path buffers sit on the stack and no caller pathname is ever
 * re-resolved. Regular-file size is checked exactly, including the
 * trailing byte that must not exist.
 */
#include "axi_local_attempt_v1.h"

#include "axi_ag1_v1.h"
#include "axi_hash.h"
#include "axi_local_epoch_v1.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define ATTEMPT_MAGIC_0 'A'
#define ATTEMPT_MAGIC_1 'X'
#define ATTEMPT_MAGIC_2 'A'
#define ATTEMPT_MAGIC_3 '1'
#define ATTEMPT_VERSION 1u
#define ATTEMPT_RECORD_SIZE 144u
#define ATTEMPT_RECORD_V2_SIZE 168u
#define ATTEMPT_VERSION_2 2u

static void hex32(const uint8_t in[32], char out[65])
{
    static const char h[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < 32; i++) {
        out[i * 2] = h[in[i] >> 4];
        out[i * 2 + 1] = h[in[i] & 15];
    }
    out[64] = '\0';
}

static int root_zero(const uint8_t r[32])
{
    size_t i;
    for (i = 0; i < 32; i++) {
        if (r[i]) {
            return 0;
        }
    }
    return 1;
}

/* AXI-INV-217 (S6-FINDING-01): resource exhaustion is transient,
 * never corruption. EMFILE/ENFILE/ENOMEM while reading a record
 * must refuse (re-query), never report CORRUPT for an undamaged file.
 */
static int err_transient(void)
{
    return errno == EMFILE || errno == ENFILE || errno == ENOMEM;
}

/* issuer_key_id = SHA-256("AXV2-KEY-ID-v1" + NUL + pk32), ADR-059 section 7. */
static void issuer_key_id(const uint8_t pk[32], uint8_t out[32])
{
    static const char dom[] = "AXV2-KEY-ID-v1";
    uint8_t buf[sizeof(dom) + 32];
    memcpy(buf, dom, sizeof(dom));
    memcpy(buf + sizeof(dom), pk, 32);
    axi_sha256(buf, sizeof(buf), out);
}

static int fd_is_dir(int fd)
{
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISDIR(st.st_mode);
}

uint64_t axi_local_attempt_v1_now_mono(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

int axi_local_attempt_v1_store_check(const char *store_dir)
{
    struct stat st;
    if (!store_dir || !*store_dir) {
        return AXI_LOCAL_ATTEMPT_V1_REFUSED;
    }
    if (stat(store_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        return AXI_LOCAL_ATTEMPT_V1_REFUSED;
    }
    if (st.st_uid != geteuid() || (st.st_mode & 0777) != 0700) {
        return AXI_LOCAL_ATTEMPT_V1_REFUSED;
    }
    return AXI_LOCAL_ATTEMPT_V1_OK;
}

/* Acquire a lock op no later than deadline (monotonic ns).
 * Always tries once without waiting; then polls every 1ms. Returns 0
 * on acquisition, -1 on expiry (or flock error). */
static int acquire_timed_op(int lockfd, uint64_t deadline, int op)
{
    for (;;) {
        uint64_t now, remain;
        struct timespec nap;
        if (flock(lockfd, op | LOCK_NB) == 0) {
            return 0;
        }
        if (errno != EWOULDBLOCK) {
            return -1;
        }
        now = axi_local_attempt_v1_now_mono();
        if (now >= deadline) {
            return -1;
        }
        remain = deadline - now;
        nap.tv_sec = 0;
        nap.tv_nsec = (long)(remain < 1000000u ? remain : 1000000u);
        nanosleep(&nap, NULL);
    }
}

static int acquire_timed(int lockfd, uint64_t deadline)
{
    return acquire_timed_op(lockfd, deadline, LOCK_EX);
}

/* Write exactly len bytes then fsync. Returns 0 on success. */
static int write_full_fsync_at(int dirfd, const char *name, const void *data,
                               size_t len)
{
    int fd = openat(dirfd, name, O_WRONLY | O_CREAT | O_TRUNC, 0600);
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

/* Read a v1 (144) or v2 (168) record and prove no trailing byte
 * exists. Returns 0 with *present=1 and *out_len set, 0 with
 * *present=0 when the name does not exist or holds zero bytes, -2 on
 * transient resource exhaustion (EMFILE/ENFILE/ENOMEM: refuse and
 * re-query, AXI-INV-217), and -1 on any other I/O or shape anomaly
 * (nonzero wrong size counts as corrupt, not absent). Zero bytes prove
 * nothing was ever decided (AXI-INV-216, S3-FINDING-01:
 * crash between O_EXCL creat and the first byte), so absent is the
 * honest answer: the spend may proceed, status says NOT_ATTEMPTED
 * and scans skip the husk. */
static int read_record_at(int dirfd, const char *name,
                          uint8_t out[ATTEMPT_RECORD_V2_SIZE],
                          size_t *out_len, int *present)
{
    int fd = openat(dirfd, name, O_RDONLY);
    size_t off = 0;
    uint8_t extra;
    ssize_t r;
    *present = 0;
    *out_len = 0;
    if (fd < 0) {
        if (errno == ENOENT) {
            return 0;
        }
        return err_transient() ? -2 : -1;
    }
    while (off < ATTEMPT_RECORD_V2_SIZE) {
        r = read(fd, out + off, ATTEMPT_RECORD_V2_SIZE - off);
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
    if (off == 0) {
        /* AXI-INV-216 (S3-FINDING-01): zero-length husk, no decision recorded. */
        close(fd);
        return 0;
    }
    if (off != ATTEMPT_RECORD_SIZE && off != ATTEMPT_RECORD_V2_SIZE) {
        close(fd);
        return -1;
    }
    r = read(fd, &extra, 1);
    close(fd);
    if (r != 0) {
        return -1;
    }
    *present = 1;
    *out_len = off;
    return 0;
}

/* Pack the v2 record (168 bytes): v1 layout plus epoch generation
 * (LE u64 at 144) and epoch deployment (16 bytes at 152). New spends
 * always write v2; v1 stays readable forever. */
static void record_pack(uint8_t out[ATTEMPT_RECORD_V2_SIZE], uint8_t state,
                        const uint8_t grant_root[32],
                        const uint8_t action_root[32],
                        const uint8_t payload_sha[32], uint64_t payload_size,
                        const uint8_t context_root[32],
                        uint64_t epoch_generation,
                        const uint8_t epoch_deployment[16])
{
    size_t i;
    memset(out, 0, ATTEMPT_RECORD_V2_SIZE);
    out[0] = ATTEMPT_MAGIC_0;
    out[1] = ATTEMPT_MAGIC_1;
    out[2] = ATTEMPT_MAGIC_2;
    out[3] = ATTEMPT_MAGIC_3;
    out[4] = ATTEMPT_VERSION_2;
    out[5] = state;
    memcpy(out + 8, grant_root, 32);
    memcpy(out + 40, action_root, 32);
    memcpy(out + 72, payload_sha, 32);
    for (i = 0; i < 8; i++) {
        out[104 + i] = (uint8_t)((payload_size >> (8 * i)) & 0xff);
    }
    memcpy(out + 112, context_root, 32);
    for (i = 0; i < 8; i++) {
        out[144 + i] = (uint8_t)((epoch_generation >> (8 * i)) & 0xff);
    }
    memcpy(out + 152, epoch_deployment, 16);
}

static int version_ok(uint8_t v)
{
    return v == ATTEMPT_VERSION || v == ATTEMPT_VERSION_2;
}

static int record_unpack(const uint8_t *in, size_t len,
                         uint8_t *state, uint8_t grant_root[32])
{
    if (len != ATTEMPT_RECORD_SIZE && len != ATTEMPT_RECORD_V2_SIZE) {
        return -1;
    }
    if (in[0] != ATTEMPT_MAGIC_0 || in[1] != ATTEMPT_MAGIC_1 ||
        in[2] != ATTEMPT_MAGIC_2 || in[3] != ATTEMPT_MAGIC_3 ||
        !version_ok(in[4])) {
        return -1;
    }
    if (in[6] != 0 || in[7] != 0) {
        return -1;
    }
    if (state) {
        *state = in[5];
    }
    if (grant_root) {
        memcpy(grant_root, in + 8, 32);
    }
    switch (in[5]) {
    case AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED:
    case AXI_LOCAL_ATTEMPT_V1_ATTEMPTED:
    case AXI_LOCAL_ATTEMPT_V1_COMMITTED:
    case AXI_LOCAL_ATTEMPT_V1_UNKNOWN:
    case AXI_LOCAL_ATTEMPT_V1_FAILED:
        return 0;
    default:
        return -1;
    }
}

/* Full validated view. Deliberately separate from record_unpack (which
 * reports the RAW stored state for the commit/status paths): duplicating
 * ~20 lines of checks beats risking a behavior drift in the 07/08 gates. */
static int record_view_from_bytes(const uint8_t *in, size_t len,
                                  axi_local_attempt_v1_record_view *v)
{
    size_t i;
    uint64_t size = 0;
    if (len != ATTEMPT_RECORD_SIZE && len != ATTEMPT_RECORD_V2_SIZE) {
        return -1;
    }
    if (in[0] != ATTEMPT_MAGIC_0 || in[1] != ATTEMPT_MAGIC_1 ||
        in[2] != ATTEMPT_MAGIC_2 || in[3] != ATTEMPT_MAGIC_3 ||
        !version_ok(in[4])) {
        return -1;
    }
    if (in[6] != 0 || in[7] != 0) {
        return -1;
    }
    switch (in[5]) {
    case AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED:
    case AXI_LOCAL_ATTEMPT_V1_ATTEMPTED:
    case AXI_LOCAL_ATTEMPT_V1_COMMITTED:
    case AXI_LOCAL_ATTEMPT_V1_UNKNOWN:
    case AXI_LOCAL_ATTEMPT_V1_FAILED:
        break;
    default:
        return -1;
    }
    memset(v, 0, sizeof(*v));
    memcpy(v->grant_root, in + 8, 32);
    v->state = (in[5] == AXI_LOCAL_ATTEMPT_V1_ATTEMPTED)
        ? AXI_LOCAL_ATTEMPT_V1_UNKNOWN : in[5];
    memcpy(v->action_root, in + 40, 32);
    memcpy(v->payload_sha, in + 72, 32);
    for (i = 0; i < 8; i++) {
        size = size | ((uint64_t)in[104 + i] << (8 * i));
    }
    v->payload_size = size;
    memcpy(v->context_root, in + 112, 32);
    if (len == ATTEMPT_RECORD_V2_SIZE) {
        uint64_t gen = 0;
        v->has_epoch_link = 1;
        for (i = 0; i < 8; i++) {
            gen = gen | ((uint64_t)in[144 + i] << (8 * i));
        }
        v->epoch_generation = gen;
        memcpy(v->epoch_deployment, in + 152, 16);
    }
    return 0;
}

static int count_records(int recfd, unsigned *out)
{
    int dupfd = dup(recfd);
    DIR *d;
    struct dirent *e;
    unsigned n = 0;
    if (dupfd < 0) {
        return -1;
    }
    d = fdopendir(dupfd);
    if (!d) {
        close(dupfd);
        return -1;
    }
    while ((e = readdir(d)) != NULL) {
        size_t i, len = strlen(e->d_name);
        int hex = (len == 64);
        for (i = 0; hex && i < len; i++) {
            char c = e->d_name[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                hex = 0;
            }
        }
        if (hex) {
            n++;
        }
    }
    closedir(d);
    *out = n;
    return 0;
}

static void fill_out(axi_local_attempt_v1_outcome *out, uint8_t state,
                     uint8_t effect, const uint8_t grant_root[32])
{
    out->state = state;
    out->effect_performed = effect;
    if (grant_root) {
        memcpy(out->grant_root, grant_root, 32);
    } else {
        memset(out->grant_root, 0, 32);
    }
}

int axi_local_attempt_v1_status(const char *store_dir,
                                const uint8_t grant_root[32],
                                axi_local_attempt_v1_outcome *out)
{
    int sdfd, recfd, present = 0;
    uint8_t rec[ATTEMPT_RECORD_V2_SIZE];
    uint8_t state, stored_root[32];
    char hex[65];
    if (!out) {
        return AXI_LOCAL_ATTEMPT_V1_REFUSED;
    }
    memset(out, 0, sizeof(*out));
    if (!store_dir || !*store_dir || !grant_root || root_zero(grant_root)) {
        return AXI_LOCAL_ATTEMPT_V1_REFUSED;
    }
    if (axi_local_attempt_v1_store_check(store_dir) !=
        AXI_LOCAL_ATTEMPT_V1_OK) {
        return AXI_LOCAL_ATTEMPT_V1_REFUSED;
    }
    sdfd = open(store_dir, O_RDONLY | O_DIRECTORY);
    if (sdfd < 0) {
        return AXI_LOCAL_ATTEMPT_V1_REFUSED;
    }
    recfd = openat(sdfd, "records", O_RDONLY | O_DIRECTORY);
    close(sdfd);
    if (recfd < 0) {
        if (errno == ENOENT) {
            fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED, 0, grant_root);
            return AXI_LOCAL_ATTEMPT_V1_OK;
        }
        return AXI_LOCAL_ATTEMPT_V1_CORRUPT;
    }
    if (!fd_is_dir(recfd)) {
        close(recfd);
        return AXI_LOCAL_ATTEMPT_V1_CORRUPT;
    }
    hex32(grant_root, hex);
    {
        size_t reclen = 0;
        int rr = read_record_at(recfd, hex, rec, &reclen, &present);
        if (rr == -2) {
            /* AXI-INV-217: transient exhaustion, re-query. */
            close(recfd);
            return AXI_LOCAL_ATTEMPT_V1_REFUSED;
        }
        if (rr != 0) {
            close(recfd);
            return AXI_LOCAL_ATTEMPT_V1_CORRUPT;
        }
        close(recfd);
        if (!present) {
            fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED, 0, grant_root);
            return AXI_LOCAL_ATTEMPT_V1_OK;
        }
        if (record_unpack(rec, reclen, &state, stored_root) != 0 ||
            memcmp(stored_root, grant_root, 32) != 0) {
            return AXI_LOCAL_ATTEMPT_V1_CORRUPT;
        }
    }
    /* A durable ATTEMPTED record observed from outside is reported as
     * UNKNOWN: the previous holder either is still in-flight or crashed.
     * Either way this query performs no effect and writes nothing. */
    if (state == AXI_LOCAL_ATTEMPT_V1_ATTEMPTED) {
        fill_out(out, AXI_LOCAL_ATTEMPT_V1_UNKNOWN, 0, grant_root);
        return AXI_LOCAL_ATTEMPT_V1_OK;
    }
    fill_out(out, state, 0, grant_root);
    return AXI_LOCAL_ATTEMPT_V1_OK;
}

static int commit_impl(const char *store_dir,
                       const uint8_t *grant_signed, size_t grant_len,
                       const uint8_t trusted_pk[32],
                       const void *action_bytes, size_t action_len,
                       const axi_local_admission_v1_pins *pins,
                       const axi_local_admission_v1_observed *observed,
                       const uint8_t *payload, size_t payload_len,
                       uint64_t supplied_time, int timed,
                       uint64_t deadline_mono_ns,
                       axi_local_attempt_v1_outcome *out)
{
    axi_ag1_v1 grant;
    axi_ag1_v1_expectation expected;
    axi_local_action_v1 action;
    axi_local_action_roots_v1 roots;
    axi_local_admission_v1_result adm;
    uint8_t grant_root[32], kid[32], phash[32];
    uint8_t rec[ATTEMPT_RECORD_V2_SIZE];
    char hex[65];
    int sdfd = -1, recfd = -1, lockfd = -1, rc, present = 0;
    unsigned nrec = 0;
    size_t reclen = 0;
    uint64_t epoch_gen = 0;
    uint8_t epoch_dep[16] = {0};

    if (!out) {
        return AXI_LOCAL_ATTEMPT_V1_REFUSED;
    }
    memset(out, 0, sizeof(*out));
    if (!store_dir || !*store_dir ||
        !grant_signed || grant_len != AXI_AG1_V1_SIGNED_SIZE || !trusted_pk ||
        root_zero(trusted_pk) || !action_bytes || action_len == 0 ||
        action_len > AXI_LOCAL_ACTION_V1_MAX_BYTES || !pins || !observed ||
        (!payload && payload_len > 0) ||
        payload_len > AXI_LOCAL_ACTION_V1_MAX_BYTES) {
        return AXI_LOCAL_ATTEMPT_V1_REFUSED;
    }
    if (axi_local_attempt_v1_store_check(store_dir) !=
        AXI_LOCAL_ATTEMPT_V1_OK) {
        return AXI_LOCAL_ATTEMPT_V1_REFUSED;
    }

    /* 1. Signed grant under the owner-pinned issuer key. */
    if (axi_ag1_v1_decode_signed(&grant, grant_signed, grant_len,
                                 trusted_pk) != 0) {
        return AXI_LOCAL_ATTEMPT_V1_REFUSED;
    }
    if (grant.has_parent) {
        /* Narrow profile: no delegation, single-issuer grants only. */
        axi_ag1_v1_root(&grant, grant_root);
        fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED, 0, grant_root);
        return AXI_LOCAL_ATTEMPT_V1_REFUSED;
    }
    axi_ag1_v1_root(&grant, grant_root);
    issuer_key_id(trusted_pk, kid);
    if (memcmp(kid, grant.issuer_key_id, 32) != 0) {
        fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED, 0, grant_root);
        return AXI_LOCAL_ATTEMPT_V1_REFUSED;
    }

    /* 2. Canonical action identity (05). */
    if (axi_local_action_v1_decode(&action, action_bytes, action_len) != 0) {
        fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED, 0, grant_root);
        return AXI_LOCAL_ATTEMPT_V1_REFUSED;
    }
    if (axi_local_action_v1_roots(&action, &roots) != 0) {
        fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED, 0, grant_root);
        return AXI_LOCAL_ATTEMPT_V1_REFUSED;
    }

    /* 3. Common appraisal (06): admitted PROD with coverage, then bind the
     * single compared instant across grant, action and admission. */
    memset(&adm, 0, sizeof(adm));
    rc = axi_local_admission_v1_appraise(action_bytes, action_len, pins,
                                         observed, &adm);
    if (rc != 0 || !adm.admitted ||
        adm.profile != AXI_LOCAL_ADMISSION_V1_PROD ||
        observed->profile != AXI_LOCAL_ADMISSION_V1_PROD) {
        fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED, 0, grant_root);
        return AXI_LOCAL_ATTEMPT_V1_REFUSED;
    }
    if (supplied_time != observed->now_ns) {
        fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED, 0, grant_root);
        return AXI_LOCAL_ATTEMPT_V1_REFUSED;
    }

    /* 4. Exact payload bound by the descriptor. */
    if (payload_len != action.payload_size) {
        fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED, 0, grant_root);
        return AXI_LOCAL_ATTEMPT_V1_REFUSED;
    }
    axi_sha256(payload_len ? payload : (const uint8_t *)"", payload_len,
               phash);
    if (memcmp(phash, action.payload_sha256, 32) != 0) {
        fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED, 0, grant_root);
        return AXI_LOCAL_ATTEMPT_V1_REFUSED;
    }

    /* 5. Seven-root match plus grant time window at the bound instant. */
    memcpy(expected.decision_aer_root, adm.context_root, 32);
    memcpy(expected.principal_root, roots.principal, 32);
    memcpy(expected.policy_root, roots.policy, 32);
    memcpy(expected.action_root, roots.action, 32);
    memcpy(expected.resource_root, roots.resource, 32);
    memcpy(expected.budget_root, roots.budget, 32);
    memcpy(expected.trust_snapshot_root, pins->trust_snapshot_root, 32);
    if (!axi_ag1_v1_matches(&grant, &expected, supplied_time)) {
        fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED, 0, grant_root);
        return AXI_LOCAL_ATTEMPT_V1_REFUSED;
    }

    /* 6. Open the store once; every later access is *at() relative to a
     * dirfd, so caller pathnames are never re-resolved. */
    sdfd = open(store_dir, O_RDONLY | O_DIRECTORY);
    if (sdfd < 0) {
        fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED, 0, grant_root);
        rc = AXI_LOCAL_ATTEMPT_V1_REFUSED;
        goto done;
    }
    if (!fd_is_dir(sdfd)) {
        /* Unreachable through O_DIRECTORY barring a kernel surprise;
         * close anyway: no descriptor is ever leaked on refusal paths. */
        close(sdfd);
        sdfd = -1;
        fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED, 0, grant_root);
        rc = AXI_LOCAL_ATTEMPT_V1_REFUSED;
        goto done;
    }
    lockfd = openat(sdfd, "owner.lock", O_WRONLY | O_CREAT, 0600);
    if (lockfd < 0) {
        fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED, 0, grant_root);
        rc = AXI_LOCAL_ATTEMPT_V1_REFUSED;
        goto done;
    }
    if (timed) {
        if (acquire_timed(lockfd, deadline_mono_ns) != 0) {
            int src;
            /* Timeout: no write, no effect. Report the current lock-free
             * status so the caller learns the durable state, if any. */
            close(lockfd);
            lockfd = -1;
            close(sdfd);
            sdfd = -1;
            src = axi_local_attempt_v1_status(store_dir, grant_root, out);
            rc = (src == AXI_LOCAL_ATTEMPT_V1_OK)
                ? AXI_LOCAL_ATTEMPT_V1_TIMEOUT : src;
            goto done;
        }
    } else if (flock(lockfd, LOCK_EX) != 0) {
        fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED, 0, grant_root);
        rc = AXI_LOCAL_ATTEMPT_V1_REFUSED;
        goto done;
    }
    /* Epoch enforcement under the lock: a superseded epoch accepts no
     * new grant or mutation (old state stays recovery/status-only).
     * Legacy stores without an epoch file are grandfathered. enforce
     * -3 is transient exhaustion (AXI-INV-217): refuse, re-query. */
    {
        int er = axi_local_epoch_v1_enforce(sdfd, pins);
        if (er == -2) {
            rc = AXI_LOCAL_ATTEMPT_V1_CORRUPT;
            goto done;
        }
        if (er != 0) {
            fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED, 0, grant_root);
            rc = AXI_LOCAL_ATTEMPT_V1_REFUSED;
            goto done;
        }
    }
    /* Snapshot the active epoch for the v2 spend linkage. Absent file:
     * zeros (pre-epoch spend, staleness unknown, grandfathered).
     * Transient snapshot failure refuses (AXI-INV-217): no spend
     * without its linkage. */
    {
        axi_local_epoch_v1 active;
        int epresent = 0;
        int er;
        memset(&active, 0, sizeof(active));
        er = axi_local_epoch_v1_read_at(sdfd, &active, &epresent);
        if (er == -2) {
            fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED, 0,
                     grant_root);
            rc = AXI_LOCAL_ATTEMPT_V1_REFUSED;
            goto done;
        }
        if (er != 0) {
            rc = AXI_LOCAL_ATTEMPT_V1_CORRUPT;
            goto done;
        }
        if (epresent) {
            epoch_gen = active.generation;
            memcpy(epoch_dep, active.deployment, 16);
        }
    }
    if ((mkdirat(sdfd, "records", 0700) != 0 && errno != EEXIST)) {
        fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED, 0, grant_root);
        rc = AXI_LOCAL_ATTEMPT_V1_REFUSED;
        goto done;
    }
    recfd = openat(sdfd, "records", O_RDONLY | O_DIRECTORY);
    if (recfd < 0 || !fd_is_dir(recfd) ||
        count_records(recfd, &nrec) != 0) {
        fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED, 0, grant_root);
        rc = AXI_LOCAL_ATTEMPT_V1_REFUSED;
        goto done;
    }
    hex32(grant_root, hex);

    {
        int rr = read_record_at(recfd, hex, rec, &reclen, &present);
        if (rr == -2) {
            /* AXI-INV-217: transient exhaustion, re-query. */
            fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED, 0,
                     grant_root);
            rc = AXI_LOCAL_ATTEMPT_V1_REFUSED;
            goto done;
        }
        if (rr != 0) {
            rc = AXI_LOCAL_ATTEMPT_V1_CORRUPT;
            goto done;
        }
    }
    if (present) {
        uint8_t state, stored_root[32];
        if (record_unpack(rec, reclen, &state, stored_root) != 0 ||
            memcmp(stored_root, grant_root, 32) != 0) {
            rc = AXI_LOCAL_ATTEMPT_V1_CORRUPT;
            goto done;
        }
        if (state == AXI_LOCAL_ATTEMPT_V1_COMMITTED ||
            state == AXI_LOCAL_ATTEMPT_V1_FAILED) {
            /* Replay: terminal already recorded, never re-effect. */
            fill_out(out, state, 0, grant_root);
            rc = AXI_LOCAL_ATTEMPT_V1_REFUSED;
            goto done;
        }
        /* ATTEMPTED under the lock means the previous holder crashed
         * (a live holder would still own this lock). Report UNKNOWN,
         * write nothing, effect nothing, retry nothing. */
        fill_out(out, AXI_LOCAL_ATTEMPT_V1_UNKNOWN, 0, grant_root);
        rc = AXI_LOCAL_ATTEMPT_V1_REFUSED;
        goto done;
    }
    if (nrec >= AXI_LOCAL_ATTEMPT_V1_MAX_RECORDS) {
        fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED, 0, grant_root);
        rc = AXI_LOCAL_ATTEMPT_V1_STORE_FULL;
        goto done;
    }

    /* 7. Durable ATTEMPTED before any effect byte (O_EXCL + fsyncs).
     * New spends always write v2, linked to the active epoch (or zeros
     * when the store predates epochs). */
    {
        int fd;
        record_pack(rec, AXI_LOCAL_ATTEMPT_V1_ATTEMPTED, grant_root,
                    roots.action, phash, (uint64_t)payload_len,
                    adm.context_root, epoch_gen, epoch_dep);
        fd = openat(recfd, hex, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0) {
            /* Lost the race: re-read under the same lock. Any other
             * failure leaves a possibly-existing record unread: report
             * CORRUPT, never a NOT_ATTEMPTED this call cannot prove. */
            if (errno != EEXIST) {
                rc = AXI_LOCAL_ATTEMPT_V1_CORRUPT;
                goto done;
            }
            {
                int rr = read_record_at(recfd, hex, rec, &reclen,
                                        &present);
                if (rr == -2) {
                    /* AXI-INV-217: transient exhaustion, re-query. */
                    fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED,
                             0, grant_root);
                    rc = AXI_LOCAL_ATTEMPT_V1_REFUSED;
                    goto done;
                }
                if (rr != 0) {
                    /* EEXIST promised a record: unreadable now means
                     * the store is lying to us. */
                    rc = AXI_LOCAL_ATTEMPT_V1_CORRUPT;
                    goto done;
                }
            }
            if (!present) {
                /* AXI-INV-216 (S3-FINDING-01): the name exists but holds zero bytes
                 * (crash between creat and first write). Nothing was
                 * decided: remove the husk and spend once, under this
                 * same lock, with a single bounded retry. A
                 * concurrently completed record lands in the branch
                 * below; anything else absent here is a lie. */
                struct stat st;
                if (fstatat(recfd, hex, &st, 0) != 0
                    || st.st_size != 0
                    || unlinkat(recfd, hex, 0) != 0) {
                    rc = AXI_LOCAL_ATTEMPT_V1_CORRUPT;
                    goto done;
                }
                fd = openat(recfd, hex, O_WRONLY | O_CREAT | O_EXCL,
                            0600);
                if (fd < 0) {
                    rc = AXI_LOCAL_ATTEMPT_V1_CORRUPT;
                    goto done;
                }
            } else {
                uint8_t state, stored_root[32];
                if (record_unpack(rec, reclen, &state, stored_root) != 0
                        || memcmp(stored_root, grant_root, 32) != 0) {
                    rc = AXI_LOCAL_ATTEMPT_V1_CORRUPT;
                    goto done;
                }
                if (state == AXI_LOCAL_ATTEMPT_V1_COMMITTED ||
                    state == AXI_LOCAL_ATTEMPT_V1_FAILED) {
                    fill_out(out, state, 0, grant_root);
                    rc = AXI_LOCAL_ATTEMPT_V1_REFUSED;
                    goto done;
                }
                fill_out(out, AXI_LOCAL_ATTEMPT_V1_UNKNOWN, 0,
                         grant_root);
                rc = AXI_LOCAL_ATTEMPT_V1_REFUSED;
                goto done;
            }
        }
        {
            size_t off = 0;
            while (off < sizeof(rec)) {
                ssize_t w = write(fd, rec + off, sizeof(rec) - off);
                if (w < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    close(fd);
                    unlinkat(recfd, hex, 0);
                    fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED, 0,
                             grant_root);
                    rc = AXI_LOCAL_ATTEMPT_V1_REFUSED;
                    goto done;
                }
                off += (size_t)w;
            }
        }
        if (fsync(fd) != 0) {
            close(fd);
            unlinkat(recfd, hex, 0);
            fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED, 0, grant_root);
            rc = AXI_LOCAL_ATTEMPT_V1_REFUSED;
            goto done;
        }
        close(fd);
    }
    if (fsync(recfd) != 0) {
        unlinkat(recfd, hex, 0);
        fill_out(out, AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED, 0, grant_root);
        rc = AXI_LOCAL_ATTEMPT_V1_REFUSED;
        goto done;
    }

    /* 8. The one fixture effect: temp -> fsync -> rename -> dir fsync. */
    if (write_full_fsync_at(sdfd, ".tmp.attempt",
                            payload_len ? payload : (const uint8_t *)"",
                            payload_len) != 0 ||
        renameat(sdfd, ".tmp.attempt", sdfd,
                 AXI_LOCAL_ATTEMPT_V1_TARGET_NAME) != 0 ||
        fsync(sdfd) != 0) {
        unlinkat(sdfd, ".tmp.attempt", 0);
        /* Observed failure after spend: honest FAILED terminal. */
        record_pack(rec, AXI_LOCAL_ATTEMPT_V1_FAILED, grant_root,
                    roots.action, phash, (uint64_t)payload_len,
                    adm.context_root, epoch_gen, epoch_dep);
        if (write_full_fsync_at(recfd, ".tmp.rec", rec, sizeof(rec)) == 0 &&
            renameat(recfd, ".tmp.rec", recfd, hex) == 0 &&
            fsync(recfd) == 0) {
            fill_out(out, AXI_LOCAL_ATTEMPT_V1_FAILED, 0, grant_root);
            rc = AXI_LOCAL_ATTEMPT_V1_REFUSED;
            goto done;
        }
        /* Spend is durable, the effect observably failed, but the
         * terminal itself would not persist: UNKNOWN, never a
         * NOT_ATTEMPTED this call cannot prove. */
        unlinkat(recfd, ".tmp.rec", 0);
        fill_out(out, AXI_LOCAL_ATTEMPT_V1_UNKNOWN, 0, grant_root);
        rc = AXI_LOCAL_ATTEMPT_V1_REFUSED;
        goto done;
    }

    /* 9. COMMITTED terminal, same atomic discipline. */
    record_pack(rec, AXI_LOCAL_ATTEMPT_V1_COMMITTED, grant_root, roots.action,
                phash, (uint64_t)payload_len, adm.context_root, epoch_gen,
                epoch_dep);
    if (write_full_fsync_at(recfd, ".tmp.rec", rec, sizeof(rec)) != 0 ||
        renameat(recfd, ".tmp.rec", recfd, hex) != 0 ||
        fsync(recfd) != 0) {
        unlinkat(recfd, ".tmp.rec", 0);
        /* Effect is durable but terminal is not: report UNKNOWN, keep the
         * ATTEMPTED record so recovery cannot mistake it for success. */
        fill_out(out, AXI_LOCAL_ATTEMPT_V1_UNKNOWN, 1, grant_root);
        rc = AXI_LOCAL_ATTEMPT_V1_REFUSED;
        goto done;
    }
    fill_out(out, AXI_LOCAL_ATTEMPT_V1_COMMITTED, 1, grant_root);
    rc = AXI_LOCAL_ATTEMPT_V1_OK;

done:
    if (lockfd >= 0) {
        flock(lockfd, LOCK_UN);
        close(lockfd);
    }
    if (recfd >= 0) {
        close(recfd);
    }
    if (sdfd >= 0) {
        close(sdfd);
    }
    return rc;
}

int axi_local_attempt_v1_commit(const char *store_dir,
                                const uint8_t *grant_signed, size_t grant_len,
                                const uint8_t trusted_pk[32],
                                const void *action_bytes, size_t action_len,
                                const axi_local_admission_v1_pins *pins,
                                const axi_local_admission_v1_observed *observed,
                                const uint8_t *payload, size_t payload_len,
                                uint64_t supplied_time,
                                axi_local_attempt_v1_outcome *out)
{
    return commit_impl(store_dir, grant_signed, grant_len, trusted_pk,
                       action_bytes, action_len, pins, observed, payload,
                       payload_len, supplied_time, 0, 0, out);
}

int axi_local_attempt_v1_commit_deadline(
    const char *store_dir, const uint8_t *grant_signed, size_t grant_len,
    const uint8_t trusted_pk[32], const void *action_bytes, size_t action_len,
    const axi_local_admission_v1_pins *pins,
    const axi_local_admission_v1_observed *observed,
    const uint8_t *payload, size_t payload_len, uint64_t supplied_time,
    uint64_t deadline_mono_ns, axi_local_attempt_v1_outcome *out)
{
    return commit_impl(store_dir, grant_signed, grant_len, trusted_pk,
                       action_bytes, action_len, pins, observed, payload,
                       payload_len, supplied_time, 1, deadline_mono_ns, out);
}

static int name_is_record(const char *name)
{
    size_t i;
    if (strlen(name) != 64) {
        return 0;
    }
    for (i = 0; i < 64; i++) {
        char c = name[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static int scan_impl(const char *store_dir,
                     int (*visit)(const axi_local_attempt_v1_record_view *view,
                                  void *ctx),
                     void *ctx, int timed, uint64_t deadline)
{
    int sdfd = -1, lockfd = -1, recfd = -1, dupfd = -1, rc;
    DIR *d = NULL;
    struct dirent *e;
    uint8_t rec[ATTEMPT_RECORD_V2_SIZE];
    int present = 0;
    if (!visit) {
        return AXI_LOCAL_ATTEMPT_V1_REFUSED;
    }
    if (axi_local_attempt_v1_store_check(store_dir) !=
        AXI_LOCAL_ATTEMPT_V1_OK) {
        return AXI_LOCAL_ATTEMPT_V1_REFUSED;
    }
    sdfd = open(store_dir, O_RDONLY | O_DIRECTORY);
    if (sdfd < 0) {
        return AXI_LOCAL_ATTEMPT_V1_REFUSED;
    }
    rc = AXI_LOCAL_ATTEMPT_V1_OK;
    /* No O_CREAT: a scanner never materializes lock state. A store with
     * records but no lock file breaks the owner invariant -> CORRUPT.
     * A store with neither is fresh -> OK with zero visits. */
    lockfd = openat(sdfd, "owner.lock", O_RDONLY);
    if (lockfd < 0) {
        int rfd = openat(sdfd, "records", O_RDONLY | O_DIRECTORY);
        if (rfd < 0) {
            if (errno == ENOENT) {
                goto done;
            }
            rc = AXI_LOCAL_ATTEMPT_V1_CORRUPT;
            goto done;
        }
        close(rfd);
        rc = AXI_LOCAL_ATTEMPT_V1_CORRUPT;
        goto done;
    }
    if (timed) {
        if (acquire_timed_op(lockfd, deadline, LOCK_SH) != 0) {
            rc = AXI_LOCAL_ATTEMPT_V1_TIMEOUT;
            goto done;
        }
    } else if (flock(lockfd, LOCK_SH) != 0) {
        rc = AXI_LOCAL_ATTEMPT_V1_REFUSED;
        goto done;
    }
    recfd = openat(sdfd, "records", O_RDONLY | O_DIRECTORY);
    if (recfd < 0) {
        if (errno == ENOENT) {
            goto done;
        }
        rc = AXI_LOCAL_ATTEMPT_V1_CORRUPT;
        goto done;
    }
    if (!fd_is_dir(recfd)) {
        rc = AXI_LOCAL_ATTEMPT_V1_CORRUPT;
        goto done;
    }
    dupfd = dup(recfd);
    if (dupfd < 0) {
        rc = AXI_LOCAL_ATTEMPT_V1_CORRUPT;
        goto done;
    }
    d = fdopendir(dupfd);
    if (!d) {
        close(dupfd);
        dupfd = -1;
        rc = AXI_LOCAL_ATTEMPT_V1_CORRUPT;
        goto done;
    }
    dupfd = -1;
    while ((e = readdir(d)) != NULL) {
        axi_local_attempt_v1_record_view view;
        size_t reclen = 0;
        if (!name_is_record(e->d_name)) {
            /* Crash tmp debris (.tmp.rec) and friends: ignored. The gap
             * they hint at is already detectable through the stranded
             * ATTEMPTED record, which is never ignored. */
            continue;
        }
        {
            int rr = read_record_at(recfd, e->d_name, rec, &reclen,
                                    &present);
            if (rr == -2) {
                /* AXI-INV-217: transient exhaustion mid-walk, re-query. */
                rc = AXI_LOCAL_ATTEMPT_V1_REFUSED;
                break;
            }
            if (rr != 0) {
                rc = AXI_LOCAL_ATTEMPT_V1_CORRUPT;
                break;
            }
        }
        if (!present) {
            /* AXI-INV-216 (S3-FINDING-01): zero-length husk reads as absent (nothing
             * decided): skip like crash debris, never abort the walk. */
            continue;
        }
        if (record_view_from_bytes(rec, reclen, &view) != 0) {
            rc = AXI_LOCAL_ATTEMPT_V1_CORRUPT;
            break;
        }
        if (visit(&view, ctx) != 0) {
            rc = AXI_LOCAL_ATTEMPT_V1_REFUSED;
            break;
        }
    }

done:
    if (d) {
        closedir(d);
    }
    if (dupfd >= 0) {
        close(dupfd);
    }
    if (lockfd >= 0) {
        flock(lockfd, LOCK_UN);
        close(lockfd);
    }
    if (recfd >= 0) {
        close(recfd);
    }
    if (sdfd >= 0) {
        close(sdfd);
    }
    return rc;
}

int axi_local_attempt_v1_scan(const char *store_dir,
                              int (*visit)(const axi_local_attempt_v1_record_view *view,
                                           void *ctx),
                              void *ctx)
{
    return scan_impl(store_dir, visit, ctx, 0, 0);
}

int axi_local_attempt_v1_scan_timed(const char *store_dir,
                                     int (*visit)(const axi_local_attempt_v1_record_view *view,
                                                  void *ctx),
                                     void *ctx, uint64_t deadline_mono_ns)
{
    return scan_impl(store_dir, visit, ctx, 1, deadline_mono_ns);
}
