/* axial — POSIX platform shim for host effects and replay I/O. Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * This is the ONLY axial translation unit besides axi_osif.c that is allowed
 * to reach for POSIX/libc primitives. It exists so the gate can prove the
 * effect semantics on the host while the sovereign Beyond build (W23)
 * substitutes its own axi_platform_beyond.c, wired to the Single Door
 * (__bsys6) and GAIOLA envelopes.
 *
 * AXI-LAW-08 / AXI-LAW-11: no libc in the sovereign build. This file is
 * compiled by the host cc, never by bear. The effect plane (axi_effect.c)
 * does not know what a file, socket or process is.
 */
#include "axi_platform.h"
#include "axi_alloc.h"
#include "axi_effect.h"
#include "axi_replay.h"
#include "axi_hash.h"
#include "axi_osif.h"
#include "axi_u64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>

uint64_t axi_platform_monotonic_ns(void *opaque, int *ok)
{
    struct timespec value;
    (void)opaque;
    if (!ok) return 0;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0 || value.tv_sec < 0) {
        *ok = 0;
        return 0;
    }
    if ((uint64_t)value.tv_sec > UINT64_MAX / 1000000000u) {
        *ok = 0;
        return 0;
    }
    *ok = 1;
    return (uint64_t)value.tv_sec * 1000000000u + (uint64_t)value.tv_nsec;
}

/* Arrays above 1024 bytes enter the automatic-scratch manifest. proc.Spawn's
 * complete framing family is explicit even where one member is smaller. */
#define AXI_FS_PATH_CAP 4096u
#define AXI_PROC_CELL_CAP 256u
#define AXI_PROC_GRANTS_CAP 1024u
#define AXI_PROC_CHILD_ARGV_CAP 64

typedef char axi_fs_path_scratch[AXI_FS_PATH_CAP];
typedef char axi_proc_cell_scratch[AXI_PROC_CELL_CAP];
typedef char axi_proc_grants_scratch[AXI_PROC_GRANTS_CAP];
typedef char *axi_proc_child_argv_scratch[AXI_PROC_CHILD_ARGV_CAP];

static int scratch_add(size_t *total, size_t add)
{
    if (!total || add > (size_t)-1 - *total) return 0;
    *total += add;
    return 1;
}

int axi_host_eff_scratch_bytes(const char *name, size_t *bytes)
{
    if (!name || !bytes) return -1;
    *bytes = 0;
    if (strcmp(name, "fs.Read") == 0 || strcmp(name, "fs.Write") == 0) {
        *bytes = sizeof(axi_fs_path_scratch);
        return 0;
    }
    if (strcmp(name, "proc.Spawn") == 0) {
        return scratch_add(bytes, sizeof(axi_proc_cell_scratch))
            && scratch_add(bytes, sizeof(axi_proc_grants_scratch))
            && scratch_add(bytes, sizeof(axi_proc_child_argv_scratch)) ? 0 : -1;
    }
    return 0;
}

static int host_scratch_reserve(const axi_host_eff_ctx *ctx, size_t bytes)
{
    return !ctx || !ctx->account || axi_mem_reserve(ctx->account, bytes);
}

static int host_scratch_release(const axi_host_eff_ctx *ctx, size_t bytes)
{
    return !ctx || !ctx->account || axi_mem_release(ctx->account, bytes);
}

static int host_bytes_to_cstr(char *out, size_t capacity,
                              const void *bytes, size_t len)
{
    if (!out || !bytes || len == 0 || len >= capacity
            || memchr(bytes, '\0', len) != NULL) return 0;
    memcpy(out, bytes, len);
    out[len] = '\0';
    return 1;
}

static void host_record_actual(axi_host_eff_ctx *ctx,
                               const void *bytes, size_t len)
{
    if (!ctx || (len && !bytes)) return;
    axi_sha256(bytes, len, ctx->record_digest_storage);
    ctx->record_digest = ctx->record_digest_storage;
    ctx->record_nbytes = (uint64_t)len;
}

static void host_record_file_identity(axi_host_eff_ctx *ctx,
                                       const struct stat *st)
{
    static const char domain[] = "AXI-FS-IDENTITY-v1";
    uint8_t bytes[sizeof domain - 1 + 32 + 8 + 8 + 8];
    size_t off = 0;
    uint64_t fields[3];
    if (!ctx || !ctx->resources || !st) return;
    fields[0] = (uint64_t)st->st_dev;
    fields[1] = (uint64_t)st->st_ino;
    fields[2] = (uint64_t)st->st_mode;
    memcpy(bytes, domain, sizeof domain - 1);
    off += sizeof domain - 1;
    memcpy(bytes + off, ctx->resources->fs_root_identity, 32);
    off += 32;
    for (size_t field = 0; field < 3; field++)
        for (int shift = 56; shift >= 0; shift -= 8)
            bytes[off++] = (uint8_t)(fields[field] >> shift);
    axi_sha256(bytes, off, ctx->resource_identity_storage);
    ctx->resource_identity = ctx->resource_identity_storage;
}

static void fs_identity(const struct stat *st, uint8_t out[32])
{
    static const char domain[] = "AXI-FS-ROOT-v1";
    uint8_t bytes[sizeof domain - 1 + 24];
    size_t off = sizeof domain - 1;
    uint64_t fields[3] = {
        (uint64_t)st->st_dev, (uint64_t)st->st_ino, (uint64_t)st->st_mode
    };
    memcpy(bytes, domain, off);
    for (size_t field = 0; field < 3; field++)
        for (int shift = 56; shift >= 0; shift -= 8)
            bytes[off++] = (uint8_t)(fields[field] >> shift);
    axi_sha256(bytes, off, out);
}

int axi_platform_fs_root_adopt(axi_resource_envelope *resources, int fd)
{
    struct stat st;
    if (!resources || resources->fs_root_fd != 0 || fd < 0
            || fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode)) return -1;
    resources->fs_root_fd = (intptr_t)fd + 1;
    fs_identity(&st, resources->fs_root_identity);
    return 0;
}

int axi_platform_fs_root_open(axi_resource_envelope *resources, const char *path)
{
    int fd;
    if (!resources || !path || !*path || resources->fs_root_fd != 0) return -1;
    fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (axi_platform_fs_root_adopt(resources, fd) != 0) {
        close(fd);
        return -1;
    }
    return 0;
}

void axi_platform_fs_root_close(axi_resource_envelope *resources)
{
    if (!resources || resources->fs_root_fd == 0) return;
    close((int)(resources->fs_root_fd - 1));
    resources->fs_root_fd = 0;
    memset(resources->fs_root_identity, 0, sizeof resources->fs_root_identity);
}

static int host_wait_ready(const axi_host_eff_ctx *ctx, int fd, short events);

int axi_platform_blocking_call(const axi_host_eff_ctx *ctx,
                               axi_platform_blocking_fn call, void *opaque)
{
    int channel[2], status = 0, frame = 0, received = 0, killed = 0;
    pid_t child, waited;
    if (!ctx || !ctx->resources || !call
            || ctx->resources->reserved.children == 0)
        return -1;
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, channel) != 0) return -1;
    for (size_t i = 0; i < 2; i++) {
        int fd_flags = fcntl(channel[i], F_GETFD, 0);
        int status_flags = fcntl(channel[i], F_GETFL, 0);
        if (fd_flags < 0 || status_flags < 0
                || fcntl(channel[i], F_SETFD, fd_flags | FD_CLOEXEC) != 0
                || fcntl(channel[i], F_SETFL, status_flags | O_NONBLOCK) != 0) {
            close(channel[0]);
            close(channel[1]);
            return -1;
        }
    }
    child = fork();
    if (child < 0) {
        close(channel[0]);
        close(channel[1]);
        return -1;
    }
    if (child == 0) {
        close(channel[0]);
        frame = call(opaque) == 0 ? 1 : -1;
        (void)send(channel[1], &frame, sizeof frame, MSG_NOSIGNAL);
        close(channel[1]);
        _exit(frame == 1 ? 0 : 1);
    }
    close(channel[1]);
    if (host_wait_ready(ctx, channel[0], POLLIN)) {
        ssize_t n;
        do {
            n = recv(channel[0], &frame, sizeof frame, 0);
        } while (n < 0 && errno == EINTR);
        received = n == (ssize_t)sizeof frame && (frame == 1 || frame == -1);
    }
    close(channel[0]);
    do {
        waited = waitpid(child, &status, WNOHANG);
    } while (waited < 0 && errno == EINTR);
    if (waited == 0) {
        killed = kill(child, SIGKILL) == 0;
        do {
            waited = waitpid(child, &status, 0);
        } while (waited < 0 && errno == EINTR);
    }
    if (!received)
        (void)axi_resource_check_deadline(ctx->resources);
    /* AXI-INV-159: the worker is reaped before its reservation is released. */
    if (waited != child || !received) return -1;
    if (!killed && (!WIFEXITED(status)
                    || WEXITSTATUS(status) != (frame == 1 ? 0 : 1)))
        return -1;
    return frame == 1 ? 0 : -1;
}

typedef struct {
    int fd;
} host_fsync_call;

static int host_fsync(void *opaque)
{
    host_fsync_call *call = (host_fsync_call *)opaque;
    return call ? fsync(call->fd) : -1;
}

static int host_open_regular(char *path, int flags, mode_t mode,
                             axi_host_eff_ctx *ctx, struct stat *identity)
{
    char *component, *slash;
    int directory, fd = -1;
    if (!path || !*path || !identity || path[0] == '/' || !ctx
            || !ctx->resources || ctx->resources->fs_root_fd == 0)
        return -1;
    if (ctx->resources
            && axi_resource_check_deadline(ctx->resources) != AXI_RESOURCE_OK)
        return -1;
    directory = dup((int)(ctx->resources->fs_root_fd - 1));
    if (directory < 0) return -1;
    component = path;
    if (!*component) goto done;
    for (;;) {
        slash = strchr(component, '/');
        if (slash) *slash = '\0';
        if (!*component || strcmp(component, ".") == 0
                || strcmp(component, "..") == 0) goto done;
        if (!slash) {
            fd = openat(directory, component,
                        flags | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, mode);
            break;
        }
        int next = openat(directory, component,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) goto done;
        close(directory);
        directory = next;
        component = slash + 1;
        if (!*component) goto done;
    }
    if (ctx && ctx->resources
            && axi_resource_check_deadline(ctx->resources) != AXI_RESOURCE_OK) {
        if (fd >= 0) close(fd);
        fd = -1;
        goto done;
    }
    if (fd < 0 || fstat(fd, identity) != 0 || !S_ISREG(identity->st_mode)) {
        if (fd >= 0) close(fd);
        fd = -1;
        goto done;
    }
    host_record_file_identity(ctx, identity);
done:
    close(directory);
    return fd;
}

int axi_platform_random(void *buf, size_t len)
{
    FILE *f;
    size_t got;
    if (!buf || len == 0) return -1;
    f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    got = fread(buf, 1, len, f);
    if (fclose(f) != 0 || got != len) return -1;
    return 0;
}

/* ---- io.Write ------------------------------------------------------------ */
long axi_host_write(const axi_host_eff_ctx *ctx, const void *buf, size_t len)
{
    FILE *f = ctx && ctx->sink ? (FILE *)ctx->sink : AXI_OUT;
    if (len == 0) {
        host_record_actual((axi_host_eff_ctx *)ctx, buf, 0);
        return 0;
    }
    if (ctx && ctx->resources) {
        int fd = fileno(f);
        int flags;
        size_t w = 0;
        if (fd < 0 || (flags = fcntl(fd, F_GETFL, 0)) < 0
                || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
            return -1;
        while (w < len) {
            ssize_t wrote;
            if (!host_wait_ready(ctx, fd, POLLOUT)) break;
            wrote = write(fd, (const char *)buf + w, len - w);
            if (wrote < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            if (wrote <= 0) break;
            w += (size_t)wrote;
        }
        (void)fcntl(fd, F_SETFL, flags);
        host_record_actual((axi_host_eff_ctx *)ctx, buf, w);
        if (w != len) {
            if (w) ((axi_host_eff_ctx *)ctx)->attempt_state = AXI_EFFECT_PARTIAL;
            return -1;
        }
        return (long)w;
    }
    size_t w = fwrite(buf, 1, len, f);
    host_record_actual((axi_host_eff_ctx *)ctx, buf, w);
    if (w != len || fflush(f) != 0) return -1;
    return (long)w;
}

/* ---- fs.Read ------------------------------------------------------------ */
long axi_host_fs_read(const axi_host_eff_ctx *ctx, const void *buf, size_t len)
{
    axi_fs_path_scratch path;
    int fd = -1;
    long rc = -1;
    size_t scratch;
    struct stat identity;
    if (len == 0 || len >= AXI_FS_PATH_CAP) return -1;
    if (axi_host_eff_scratch_bytes("fs.Read", &scratch) != 0
            || !host_scratch_reserve(ctx, scratch)) return -1;
    if (!host_bytes_to_cstr(path, sizeof path, buf, len)) goto done;
    fd = host_open_regular(path, O_RDONLY, 0,
                           (axi_host_eff_ctx *)ctx, &identity);
    if (fd < 0 || identity.st_size < 0) goto done;
    uint64_t n64 = (uint64_t)identity.st_size;
    if (n64 > (uint64_t)SIZE_MAX) goto done;
    size_t n = (size_t)n64;
    char *data;
    if (n >= 65536u || !ctx || !ctx->resources || !ctx->account) goto done;
    if (ctx && ctx->replay && ctx->replay->mode == AXI_REPLAY_RECORD
            && n > sizeof ctx->replay->records[0].result) {
        goto done;
    }
    data = axi_resource_output_alloc(ctx->resources, ctx->account, n + 1u);
    if (!data) goto done;
    size_t r = 0;
    while (r < n) {
        if (ctx && ctx->resources
                && axi_resource_check_deadline(ctx->resources)
                   != AXI_RESOURCE_OK) goto done;
        ssize_t got = read(fd, data + r, n - r);
        if (got < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (got <= 0) {
            if (r) {
                host_record_actual((axi_host_eff_ctx *)ctx, data, r);
                ((axi_host_eff_ctx *)ctx)->attempt_state = AXI_EFFECT_PARTIAL;
            }
            goto done;
        }
        r += (size_t)got;
    }
    data[r] = '\0';
    ((axi_host_eff_ctx *)ctx)->result = data;
    ((axi_host_eff_ctx *)ctx)->result_len = r;
    ((axi_host_eff_ctx *)ctx)->has_result = 1;
    host_record_actual((axi_host_eff_ctx *)ctx, data, r);
    rc = (long)r;
done:
    if (fd >= 0 && close(fd) != 0) {
        if (ctx && rc >= 0)
            ((axi_host_eff_ctx *)ctx)->attempt_state = AXI_EFFECT_PARTIAL;
        rc = -1;
    }
    if (!host_scratch_release(ctx, scratch)) return -1;
    return rc;
}

/* ---- fs.Write ------------------------------------------------------------ */
long axi_host_fs_write(const axi_host_eff_ctx *ctx, const void *buf, size_t len)
{
    axi_fs_path_scratch path;
    int fd = -1;
    long rc = -1;
    size_t scratch;
    struct stat identity;
    host_fsync_call sync_call;
    const char *p = memchr(buf, '|', len);
    if (!p) return -1;
    size_t plen = (size_t)(p - (const char *)buf);
    if (plen == 0 || plen >= AXI_FS_PATH_CAP) return -1;
    if (axi_host_eff_scratch_bytes("fs.Write", &scratch) != 0
            || !host_scratch_reserve(ctx, scratch)) return -1;
    if (!host_bytes_to_cstr(path, sizeof path, buf, plen)) goto done;
    const void *content = p + 1;
    size_t clen = len - plen - 1;
    fd = host_open_regular(path, O_WRONLY | O_CREAT | O_TRUNC, 0666,
                           (axi_host_eff_ctx *)ctx, &identity);
    if (fd < 0) goto done;
    if (ctx) ((axi_host_eff_ctx *)ctx)->attempt_state = AXI_EFFECT_PARTIAL;
    size_t w = 0;
    while (w < clen) {
        if (ctx && ctx->resources
                && axi_resource_check_deadline(ctx->resources)
                   != AXI_RESOURCE_OK) break;
        ssize_t wrote = write(fd, (const char *)content + w, clen - w);
        if (wrote < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (wrote <= 0) break;
        w += (size_t)wrote;
    }
    host_record_actual((axi_host_eff_ctx *)ctx, content, w);
    sync_call.fd = fd;
    if (w == clen && axi_platform_blocking_call(ctx, host_fsync, &sync_call) == 0)
        rc = (long)w;
done:
    if (fd >= 0 && close(fd) != 0) rc = -1;
    if (!host_scratch_release(ctx, scratch)) return -1;
    return rc;
}

/* ---- crypto.Hash --------------------------------------------------------- */
long axi_host_crypto_hash(const axi_host_eff_ctx *ctx, const void *buf, size_t len)
{
    const char *p = memchr(buf, '|', len);
    if (!p) return -1;
    size_t alen = (size_t)(p - (const char *)buf);
    if (alen != 6 || memcmp(buf, "sha256", 6) != 0) return -1;
    const void *data = p + 1;
    size_t dlen = len - alen - 1;
    uint8_t digest[32];
    axi_sha256(data, dlen, digest);
    char *hex;
    if (!ctx || !ctx->resources || !ctx->account) return -1;
    hex = axi_resource_output_alloc(ctx->resources, ctx->account, 65u);
    if (!hex) return -1;
    static const char *d = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex[2*i]   = d[digest[i] >> 4];
        hex[2*i+1] = d[digest[i] & 15];
    }
    hex[64] = 0;
    ((axi_host_eff_ctx *)ctx)->result = hex;
    ((axi_host_eff_ctx *)ctx)->result_len = 64;
    ((axi_host_eff_ctx *)ctx)->has_result = 1;
    host_record_actual((axi_host_eff_ctx *)ctx, hex, 64);
    return 64;
}

/* ---- proc.Spawn ---------------------------------------------------------- */
long axi_host_proc_spawn(const axi_host_eff_ctx *ctx, const void *buf, size_t len)
{
    axi_proc_cell_scratch cell;
    axi_proc_grants_scratch grants_buf;
    size_t scratch;
    long rc = -1;
    if (!ctx || !ctx->m || !ctx->mod_path || !ctx->fuel_used || !ctx->fuel_exhausted)
        return -1;
    /* INV-295 / AXI-INV-090: argv framing is bytes, but NUL has no argv value. */
    if (memchr(buf, '\0', len)) return -1;

    const char *p = memchr(buf, '|', len);
    size_t cell_len = p ? (size_t)(p - (const char *)buf) : len;
    if (cell_len == 0 || cell_len >= AXI_PROC_CELL_CAP) return -1;

    /* Remaining fuel is what the child inherits */
    uint64_t remaining = ctx->fuel_budget - *ctx->fuel_used;
    if (remaining == 0) { *ctx->fuel_exhausted = 1; return -1; }

    if (axi_host_eff_scratch_bytes("proc.Spawn", &scratch) != 0
            || !host_scratch_reserve(ctx, scratch)) return -1;
    memcpy(cell, buf, cell_len);
    cell[cell_len] = '\0';

    /* Flatten grants for the platform layer without dropping authority. */
    memset(grants_buf, 0, sizeof grants_buf);
    if (ctx->grants && ctx->grants->n > 0) {
        size_t off = 0;
        for (int i = 0; i < ctx->grants->n; i++) {
            size_t glen = strlen(ctx->grants->name[i]);
            size_t need = glen + (i ? 1u : 0u);
            if (need >= sizeof grants_buf - off) goto done;
            if (i) grants_buf[off++] = '|';
            memcpy(grants_buf + off, ctx->grants->name[i], glen);
            off += glen;
        }
    }

    const char *args = p ? p + 1 : NULL;
    size_t args_len = p ? len - cell_len - 1 : 0;
    int nargs = args_len ? 1 : 0;
    for (size_t i = 0; i < args_len; i++) {
        if (args[i] != '|') continue;
        if (i == 0 || i + 1 == args_len || args[i - 1] == '|') goto done;
        if (++nargs > 16) goto done;
    }
    uint64_t child_used = 0;
    axi_resource_vector child_resources = {0};
    /* INV-289 / AXI-INV-084; INV-290 / AXI-INV-085. */
    rc = axi_platform_spawn(ctx->mod_path, ctx->m->root,
                            ctx->trusted_key_path, cell,
                            args, args_len, remaining,
                             grants_buf[0] ? grants_buf : NULL,
                             ctx->resources,
                             &child_used, &child_resources,
                             ctx->fuel_exhausted);
    if (ctx->resources
            && axi_resource_absorb_child(ctx->resources, &child_resources)
               != AXI_RESOURCE_OK)
        rc = -1;
    *ctx->fuel_used += child_used;
done:
    if (!host_scratch_release(ctx, scratch)) return -1;
    return rc;
}

/* ---- platform spawn primitive (POSIX) ----------------------------------- */
int axi_platform_spawn(const char *mod_path, const uint8_t mod_root[32],
                       const char *trusted_key_path,
                       const char *cell, const char *args, size_t args_len,
                       uint64_t fuel,
                       const char *grants,
                       const axi_resource_envelope *resources,
                       uint64_t *fuel_used_out,
                       axi_resource_vector *resources_used_out,
                       int *fuel_exhausted)
{
    if (!mod_path || !mod_root || !trusted_key_path || !*trusted_key_path
            || !cell || !fuel_used_out || !fuel_exhausted)
        return -1;
    *fuel_used_out = 0;
    if (resources_used_out) memset(resources_used_out, 0, sizeof *resources_used_out);
    *fuel_exhausted = 0;

    uint64_t calls_left = 0, input_left = 0, output_left = 0;
    uint64_t handles_left = 0, children_left = 0;
    int clock_ok = 0;
    if (resources) {
#define LEFT(field) (resources->ceiling.field - resources->spent.field \
                     - resources->reserved.field)
        if (!axi_resource_envelope_valid(resources)) return -1;
        calls_left = LEFT(calls);
        input_left = LEFT(input_bytes);
        output_left = LEFT(output_bytes);
        handles_left = LEFT(handles);
        children_left = LEFT(children);
#undef LEFT
        uint64_t now = resources->now(resources->clock_opaque, &clock_ok);
        if (!clock_ok || now >= resources->deadline_ns)
            return -1;
    }

    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }

    if (pid == 0) {
        close(pipefd[0]);
        char fuel_str[32];
        snprintf(fuel_str, sizeof fuel_str, "%llu", (unsigned long long)fuel);
        char fd_str[16];
        snprintf(fd_str, sizeof fd_str, "%d", pipefd[1]);
        char root_hex[65];
        static const char hex[] = "0123456789abcdef";
        for (int i = 0; i < 32; i++) {
            root_hex[i * 2] = hex[mod_root[i] >> 4];
            root_hex[i * 2 + 1] = hex[mod_root[i] & 15];
        }
        root_hex[64] = '\0';
        char calls_str[32], input_str[32], output_str[32];
        char handles_str[32], children_str[32], deadline_str[32];
        char root_fd_str[16];
        axi_proc_child_argv_scratch child_argv;
        int argc = 0;
        child_argv[argc++] = (char *)"axi";
        child_argv[argc++] = (char *)"run";
        child_argv[argc++] = (char *)mod_path;
        child_argv[argc++] = (char *)cell;
        /* INV-475 / AXI-INV-144: a signed-v7 child inherits the parent's
         * explicit trust anchor, never ambient trust and never a v5 fallback. */
        child_argv[argc++] = (char *)"--trusted-key";
        child_argv[argc++] = (char *)trusted_key_path;
        child_argv[argc++] = (char *)"--fuel";
        child_argv[argc++] = fuel_str;
        child_argv[argc++] = (char *)"--_fuel-report-fd";
        child_argv[argc++] = fd_str;
        child_argv[argc++] = (char *)"--_module-root";
        child_argv[argc++] = root_hex;
        if (resources) {
#define CHILD_LIMIT(option, value, storage) \
            snprintf(storage, sizeof storage, "%llu", (unsigned long long)(value)); \
            child_argv[argc++] = (char *)(option); \
            child_argv[argc++] = storage
            CHILD_LIMIT("--effect-calls", calls_left, calls_str);
            CHILD_LIMIT("--input-bytes", input_left, input_str);
            CHILD_LIMIT("--output-bytes", output_left, output_str);
            CHILD_LIMIT("--handles", handles_left, handles_str);
            CHILD_LIMIT("--children", children_left, children_str);
            CHILD_LIMIT("--_deadline-ns", resources->deadline_ns, deadline_str);
            if (resources->fs_root_fd != 0) {
                int root_fd = (int)(resources->fs_root_fd - 1);
                int fd_flags = fcntl(root_fd, F_GETFD, 0);
                if (fd_flags < 0
                        || fcntl(root_fd, F_SETFD, fd_flags & ~FD_CLOEXEC) != 0)
                    _exit(126);
                snprintf(root_fd_str, sizeof root_fd_str, "%d", root_fd);
                child_argv[argc++] = (char *)"--_fs-root-fd";
                child_argv[argc++] = root_fd_str;
            }
#undef CHILD_LIMIT
        }

        if (grants && *grants) {
            char *gcopy = axi_strdup(grants);
            if (!gcopy) _exit(126);
            char *tok = strtok(gcopy, "|");
            while (tok) {
                if (argc + 2 >= AXI_PROC_CHILD_ARGV_CAP) _exit(126);
                child_argv[argc++] = (char *)"--cap";
                child_argv[argc++] = tok;
                tok = strtok(NULL, "|");
            }
        }

        if (args_len > 0) {
            char *acopy = axi_malloc(args_len + 1);
            if (!acopy) _exit(126);
            memcpy(acopy, args, args_len);
            acopy[args_len] = '\0';
            char *tok = strtok(acopy, "|");
            /* Child data starts after the runner option boundary.
             * INV-284 / AXI-INV-079. */
            child_argv[argc++] = (char *)"--";
            while (tok) {
                if (argc + 1 >= AXI_PROC_CHILD_ARGV_CAP) _exit(126);
                child_argv[argc++] = tok;
                tok = strtok(NULL, "|");
            }
        }
        child_argv[argc] = NULL;

        execv("/proc/self/exe", child_argv);
        _exit(127);
    }

    close(pipefd[1]);
    int status = 0;
    /* INV-291 / AXI-INV-086: an unknown child status is never success. */
    for (;;) {
        pid_t waited = waitpid(pid, &status, resources ? WNOHANG : 0);
        if (waited == pid) break;
        if (waited < 0 && errno != EINTR) {
            close(pipefd[0]);
            return -1;
        }
        if (resources) {
            struct timespec pause = {0, 1000000};
            axi_resource_envelope *mutable_resources =
                (axi_resource_envelope *)resources;
            if (axi_resource_check_deadline(mutable_resources)
                    != AXI_RESOURCE_OK) {
                (void)kill(pid, SIGKILL);
                while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
                close(pipefd[0]);
                return -1;
            }
            (void)nanosleep(&pause, NULL);
        }
    }

    char fuel_buf[192];
    size_t report_len = 0;
    ssize_t n;
    do {
        n = read(pipefd[0], fuel_buf + report_len,
                 sizeof fuel_buf - report_len);
        if (n > 0) report_len += (size_t)n;
    } while ((n > 0 && report_len < sizeof fuel_buf) || (n < 0 && errno == EINTR));
    close(pipefd[0]);

    if (n == 0 && report_len > 0 && report_len < sizeof fuel_buf) {
        uint64_t fields[7];
        size_t off = 0;
        int valid = 1;
        /* INV-294 / AXI-INV-089: report framing is exact and mandatory on
         * child success; malformed accounting is not zero accounting. */
        for (size_t field = 0; field < 7; field++) {
            const char *start = fuel_buf + off;
            const char *space = field == 6 ? NULL
                : memchr(start, ' ', report_len - off);
            size_t field_len = space ? (size_t)(space - start) : report_len - off;
            if ((field != 6 && !space)
                    || axi_u64_parse(start, field_len, AXI_U64_ZERO_PERMITTED,
                                     &fields[field]) != AXI_U64_OK) {
                valid = 0;
                break;
            }
            off += field_len + (space != NULL);
        }
        if (!valid || off != report_len || fields[0] > fuel || fields[1] > 1)
            goto malformed_report;
        *fuel_used_out = fields[0];
        *fuel_exhausted = fields[1] != 0;
        if (resources_used_out) {
            resources_used_out->calls = fields[2];
            resources_used_out->input_bytes = fields[3];
            resources_used_out->output_bytes = fields[4];
            resources_used_out->handles = fields[5];
            resources_used_out->children = fields[6];
        }
    } else {
malformed_report:
        if (resources)
            ((axi_resource_envelope *)resources)->first_denial = AXI_RESOURCE_CORRUPT;
        return -1;
    }

    if (WIFEXITED(status)) {
        int rc = WEXITSTATUS(status);
        if (rc == 0) return 0;
        return -1;
    }
    return -1;
}

int axi_platform_report_fuel(int fd, uint64_t fuel_used, int fuel_exhausted,
                             const axi_resource_vector *resources_used)
{
    char buf[192];
    int n;
    if (fd < 0) return -1;
    /* Exit status 1 means refusal, not specifically fuel exhaustion.
     * INV-288 / AXI-INV-083. */
    n = snprintf(buf, sizeof buf, "%llu %d %llu %llu %llu %llu %llu",
                 (unsigned long long)fuel_used, fuel_exhausted ? 1 : 0,
                 (unsigned long long)(resources_used ? resources_used->calls : 0),
                 (unsigned long long)(resources_used ? resources_used->input_bytes : 0),
                 (unsigned long long)(resources_used ? resources_used->output_bytes : 0),
                 (unsigned long long)(resources_used ? resources_used->handles : 0),
                 (unsigned long long)(resources_used ? resources_used->children : 0));
    if (n <= 0 || (size_t)n >= sizeof buf) return -1;
    size_t off = 0;
    while (off < (size_t)n) {
        ssize_t wrote = write(fd, buf + off, (size_t)n - off);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) return -1;
        off += (size_t)wrote;
    }
    return 0;
}

/* ---- net effects (host shim) -------------------------------------------- */
static int net_sock_alloc(const axi_host_eff_ctx *ctx, int fd,
                          const uint8_t identity[32], uint64_t *handle)
{
    if (!ctx || !ctx->resources) return -1;
    return axi_handle_table_insert_identified(&ctx->resources->handles,
                                              (intptr_t)fd + 1,
                                              identity, handle);
}

static int net_sock_acquire(const axi_host_eff_ctx *ctx, uint64_t handle,
                            uint8_t identity[32])
{
    intptr_t value;
    if (!ctx || !ctx->resources
            || axi_handle_table_acquire_identified(&ctx->resources->handles,
                                                   handle, &value,
                                                   identity) != 0) return -1;
    return (int)(value - 1);
}

static void net_sock_release(const axi_host_eff_ctx *ctx, uint64_t handle)
{
    if (ctx && ctx->resources)
        (void)axi_handle_table_release(&ctx->resources->handles, handle);
}

static int host_wait_ready(const axi_host_eff_ctx *ctx, int fd, short events)
{
    struct pollfd item;
    if (!ctx || !ctx->resources) return 1;
    item.fd = fd;
    item.events = events;
    item.revents = 0;
    for (;;) {
        int clock_ok = 0;
        uint64_t now = ctx->resources->now(ctx->resources->clock_opaque,
                                           &clock_ok);
        uint64_t remaining, millis;
        int timeout, rc;
        if (!clock_ok || now >= ctx->resources->deadline_ns) return 0;
        remaining = ctx->resources->deadline_ns - now;
        millis = remaining / 1000000u + (remaining % 1000000u != 0);
        timeout = millis > (uint64_t)INT_MAX ? INT_MAX : (int)millis;
        rc = poll(&item, 1, timeout);
        if (rc > 0)
            return (item.revents & events) != 0
                && (item.revents & (POLLERR | POLLNVAL)) == 0;
        if (rc == 0) return 0;
        if (errno != EINTR) return 0;
    }
}

static int net_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

#define AXI_NET_ANSWER_MAX 16u

typedef struct {
    uint32_t family;
    uint32_t socktype;
    uint32_t protocol;
    uint32_t length;
    uint8_t address[sizeof(struct sockaddr_storage)];
} net_answer;

static int net_answer_compare(const void *left, const void *right)
{
    const net_answer *a = (const net_answer *)left;
    const net_answer *b = (const net_answer *)right;
    if (a->family != b->family) return a->family < b->family ? -1 : 1;
    if (a->socktype != b->socktype) return a->socktype < b->socktype ? -1 : 1;
    if (a->protocol != b->protocol) return a->protocol < b->protocol ? -1 : 1;
    if (a->length != b->length) return a->length < b->length ? -1 : 1;
    return memcmp(a->address, b->address, a->length);
}

static int net_connect_blocking(const char *host, const char *port,
                                uint8_t answer_root[32])
{
    struct addrinfo hints = {0}, *res = NULL, *rp;
    net_answer answers[AXI_NET_ANSWER_MAX];
    uint8_t canonical[4096];
    static const char domain[] = "AXI-DNS-ANSWER-SET-v1";
    size_t answer_count = 0, off = 0;
    int fd = -1;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (!answer_root || getaddrinfo(host, port, &hints, &res) != 0) return -1;
    for (rp = res; rp; rp = rp->ai_next) {
        net_answer *answer;
        if (answer_count == AXI_NET_ANSWER_MAX
                || rp->ai_addrlen > sizeof answer->address) {
            freeaddrinfo(res);
            return -1;
        }
        answer = &answers[answer_count++];
        memset(answer, 0, sizeof *answer);
        answer->family = (uint32_t)rp->ai_family;
        answer->socktype = (uint32_t)rp->ai_socktype;
        answer->protocol = (uint32_t)rp->ai_protocol;
        answer->length = (uint32_t)rp->ai_addrlen;
        memcpy(answer->address, rp->ai_addr, rp->ai_addrlen);
    }
    qsort(answers, answer_count, sizeof answers[0], net_answer_compare);
    memcpy(canonical + off, domain, sizeof domain - 1); off += sizeof domain - 1;
    size_t host_len = strlen(host), port_len = strlen(port);
    if (host_len > UINT16_MAX || port_len > UINT16_MAX) {
        freeaddrinfo(res);
        return -1;
    }
#define NET_PUT32(value) do { \
    uint32_t net_value = (uint32_t)(value); \
    canonical[off++] = (uint8_t)(net_value >> 24); \
    canonical[off++] = (uint8_t)(net_value >> 16); \
    canonical[off++] = (uint8_t)(net_value >> 8); \
    canonical[off++] = (uint8_t)net_value; \
} while (0)
    NET_PUT32(host_len);
    memcpy(canonical + off, host, host_len); off += host_len;
    NET_PUT32(port_len);
    memcpy(canonical + off, port, port_len); off += port_len;
    NET_PUT32(answer_count);
    for (size_t i = 0; i < answer_count; i++) {
        NET_PUT32(answers[i].family);
        NET_PUT32(answers[i].socktype);
        NET_PUT32(answers[i].protocol);
        NET_PUT32(answers[i].length);
        memcpy(canonical + off, answers[i].address, answers[i].length);
        off += answers[i].length;
    }
#undef NET_PUT32
    if (off > sizeof canonical) {
        freeaddrinfo(res);
        return -1;
    }
    axi_sha256(canonical, off, answer_root);
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int net_send_fd(int channel, int fd, const uint8_t answer_root[32])
{
    uint8_t payload[33];
    char control[CMSG_SPACE(sizeof fd)];
    struct iovec iov = {payload, sizeof payload};
    struct msghdr msg;
    struct cmsghdr *cmsg;
    memset(&msg, 0, sizeof msg);
    memset(control, 0, sizeof control);
    payload[0] = 'F';
    memcpy(payload + 1, answer_root, 32);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof control;
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof fd);
    memcpy(CMSG_DATA(cmsg), &fd, sizeof fd);
    return sendmsg(channel, &msg, 0) == (ssize_t)sizeof payload ? 0 : -1;
}

static int net_recv_fd(int channel, uint8_t answer_root[32])
{
    uint8_t payload[33];
    char control[CMSG_SPACE(sizeof(int))];
    struct iovec iov = {payload, sizeof payload};
    struct msghdr msg;
    struct cmsghdr *cmsg;
    int fd = -1;
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof control;
    if (!answer_root || recvmsg(channel, &msg, 0) != (ssize_t)sizeof payload
            || payload[0] != 'F') return -1;
    cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS
            || cmsg->cmsg_len != CMSG_LEN(sizeof fd)) return -1;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof fd);
    memcpy(answer_root, payload + 1, 32);
    return fd;
}

static int net_connect_bounded(const axi_host_eff_ctx *ctx,
                               const char *host, const char *port,
                               uint8_t answer_root[32])
{
    int channel[2], fd = -1, status = 0;
    pid_t child;
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, channel) != 0) return -1;
    child = fork();
    if (child < 0) {
        close(channel[0]);
        close(channel[1]);
        return -1;
    }
    if (child == 0) {
        close(channel[0]);
        uint8_t child_answer_root[32];
        fd = net_connect_blocking(host, port, child_answer_root);
        if (fd >= 0 && net_send_fd(channel[1], fd, child_answer_root) == 0) {
            close(fd);
            close(channel[1]);
            _exit(0);
        }
        if (fd >= 0) close(fd);
        close(channel[1]);
        _exit(1);
    }
    close(channel[1]);
    if (host_wait_ready(ctx, channel[0], POLLIN))
        fd = net_recv_fd(channel[0], answer_root);
    if (fd < 0) (void)kill(child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    close(channel[0]);
    if (fd < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    if (!net_nonblocking(fd)) {
        close(fd);
        return -1;
    }
    return fd;
}

static int net_peer_identity(int fd, uint8_t out[32])
{
    static const char domain[] = "AXI-NET-PEER-v1";
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof peer;
    char host[128], service[32];
    uint8_t bytes[sizeof domain - 1 + sizeof host + sizeof service + 1];
    size_t host_len, service_len, off = 0;
    if (!out || getpeername(fd, (struct sockaddr *)&peer, &peer_len) != 0
            || getnameinfo((struct sockaddr *)&peer, peer_len,
                           host, sizeof host, service, sizeof service,
                           NI_NUMERICHOST | NI_NUMERICSERV) != 0)
        return 0;
    host_len = strlen(host);
    service_len = strlen(service);
    if (host_len >= sizeof host || service_len >= sizeof service) return 0;
    memcpy(bytes + off, domain, sizeof domain - 1); off += sizeof domain - 1;
    memcpy(bytes + off, host, host_len); off += host_len;
    bytes[off++] = 0;
    memcpy(bytes + off, service, service_len); off += service_len;
    axi_sha256(bytes, off, out);
    return 1;
}

static int net_resource_identity(const uint8_t answer_root[32], int fd,
                                 uint8_t out[32])
{
    static const char domain[] = "AXI-NET-RESOURCE-v1";
    uint8_t bytes[sizeof domain - 1 + 64];
    uint8_t peer_root[32];
    if (!answer_root || !out || !net_peer_identity(fd, peer_root)) return 0;
    memcpy(bytes, domain, sizeof domain - 1);
    memcpy(bytes + sizeof domain - 1, answer_root, 32);
    memcpy(bytes + sizeof domain - 1 + 32, peer_root, 32);
    axi_sha256(bytes, sizeof bytes, out);
    return 1;
}

void axi_platform_handles_close(axi_resource_envelope *resources)
{
    intptr_t value;
    if (!resources) return;
    while (axi_handle_table_take(&resources->handles, &value) == 0) {
        (void)close((int)(value - 1));
        if (resources->live_handles)
            (void)axi_resource_handle_closed(resources);
    }
}

static void net_set_digest(axi_host_eff_ctx *ctx, const void *data, size_t len,
                           uint64_t nbytes)
{
    axi_sha256(data, len, ctx->record_digest_storage);
    ctx->record_digest = ctx->record_digest_storage;
    ctx->record_nbytes = nbytes;
}

long axi_host_net_connect(const axi_host_eff_ctx *ctx, const void *buf, size_t len)
{
    (void)ctx;
    if (len == 0 || len >= 256) return -1;
    char addr[256];
    if (!host_bytes_to_cstr(addr, sizeof addr, buf, len)) return -1;

    char *colon = strrchr(addr, ':');
    if (!colon) return -1;
    *colon = '\0';
    const char *host = addr;
    const char *port = colon + 1;

    uint8_t answer_root[32], resource_identity[32];
    int fd = ctx && ctx->resources
        ? net_connect_bounded(ctx, host, port, answer_root)
        : net_connect_blocking(host, port, answer_root);
    if (fd < 0) return -1;
    if (ctx && !net_resource_identity(answer_root, fd, resource_identity)) {
        close(fd);
        return -1;
    }
    if (ctx) {
        memcpy(((axi_host_eff_ctx *)ctx)->resource_identity_storage,
               resource_identity, 32);
        ((axi_host_eff_ctx *)ctx)->resource_identity =
            ((axi_host_eff_ctx *)ctx)->resource_identity_storage;
    }

    uint64_t handle;
    if (net_sock_alloc(ctx, fd, resource_identity, &handle) != 0) {
        close(fd);
        return -1;
    }
    if (handle > (uint64_t)LONG_MAX) {
        intptr_t ignored;
        (void)axi_handle_table_remove(&ctx->resources->handles, handle, &ignored);
        close(fd);
        return -1;
    }
    return (long)handle;
}

long axi_host_net_write(const axi_host_eff_ctx *ctx, const void *buf, size_t len)
{
    const char *p = memchr(buf, '|', len);
    if (!p) return -1;
    size_t hlen = (size_t)(p - (const char *)buf);
    if (hlen == 0 || hlen >= 32) return -1; /* INV-282 */
    uint64_t handle;
    /* INV-292 / AXI-INV-087: effect integers consume their complete field. */
    if (axi_u64_parse(buf, hlen, AXI_U64_ZERO_PERMITTED,
                      &handle) != AXI_U64_OK) return -1;
    const void *data = p + 1;
    size_t dlen = len - hlen - 1;
    uint8_t resource_identity[32];

    int fd = net_sock_acquire(ctx, handle, resource_identity);
    if (fd < 0) return -1;
    memcpy(((axi_host_eff_ctx *)ctx)->resource_identity_storage,
           resource_identity, 32);
    ((axi_host_eff_ctx *)ctx)->resource_identity =
        ((axi_host_eff_ctx *)ctx)->resource_identity_storage;

    size_t sent = 0;
    while (sent < dlen) {
        if (!host_wait_ready(ctx, fd, POLLOUT)) break;
        ssize_t w = send(fd, (const char *)data + sent, dlen - sent,
#ifdef MSG_NOSIGNAL
                         MSG_NOSIGNAL
#else
                         0
#endif
                         );
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) break;
        sent += (size_t)w;
    }
    net_set_digest((axi_host_eff_ctx *)ctx, data, sent, (uint64_t)sent);
    net_sock_release(ctx, handle);
    if (sent != dlen) {
        if (ctx && sent)
            ((axi_host_eff_ctx *)ctx)->attempt_state = AXI_EFFECT_PARTIAL;
        return -1;
    }
    return (long)sent;
}

long axi_host_net_read(const axi_host_eff_ctx *ctx, const void *buf, size_t len)
{
    const char *p = memchr(buf, '|', len);
    if (!p) return -1;
    size_t hlen = (size_t)(p - (const char *)buf);
    if (hlen == 0 || hlen >= 32) return -1; /* INV-282 */
    uint64_t handle, max64;
    if (axi_u64_parse(buf, hlen, AXI_U64_ZERO_PERMITTED,
                      &handle) != AXI_U64_OK) return -1;
    size_t mlen = len - hlen - 1;
    if (axi_u64_parse(p + 1, mlen, AXI_U64_POSITIVE_ONLY,
                      &max64) != AXI_U64_OK ||
        max64 > SIZE_MAX) return -1;
    size_t max = (size_t)max64;
    uint8_t resource_identity[32];
    if (ctx && ctx->replay && ctx->replay->mode == AXI_REPLAY_RECORD
            && max > sizeof ctx->replay->records[0].result) return -1;

    int fd = net_sock_acquire(ctx, handle, resource_identity);
    if (fd < 0) return -1;
    memcpy(((axi_host_eff_ctx *)ctx)->resource_identity_storage,
           resource_identity, 32);
    ((axi_host_eff_ctx *)ctx)->resource_identity =
        ((axi_host_eff_ctx *)ctx)->resource_identity_storage;

    char *rdbuf;
    if (!ctx || !ctx->resources || !ctx->account) {
        net_sock_release(ctx, handle);
        return -1;
    }
    if (max > 4096u) max = 4096u;
    rdbuf = axi_resource_output_alloc(ctx->resources, ctx->account,
                                      max ? max : 1u);
    if (!rdbuf) {
        net_sock_release(ctx, handle);
        return -1;
    }
    if (!host_wait_ready(ctx, fd, POLLIN)) {
        net_sock_release(ctx, handle);
        return -1;
    }
    ssize_t n = recv(fd, rdbuf, max, 0);
    if (n < 0) {
        net_sock_release(ctx, handle);
        return -1;
    }

    ((axi_host_eff_ctx *)ctx)->result = rdbuf;
    ((axi_host_eff_ctx *)ctx)->result_len = (size_t)n;
    ((axi_host_eff_ctx *)ctx)->has_result = 1;
    net_set_digest((axi_host_eff_ctx *)ctx, rdbuf, (size_t)n, (uint64_t)n);
    net_sock_release(ctx, handle);
    return (long)n;
}

long axi_host_net_close(const axi_host_eff_ctx *ctx, const void *buf, size_t len)
{
    uint64_t handle;
    intptr_t value;
    uint8_t resource_identity[32];
    if (!ctx || !ctx->resources
            || axi_u64_parse(buf, len, AXI_U64_ZERO_PERMITTED,
                             &handle) != AXI_U64_OK
            || axi_handle_table_acquire_identified(&ctx->resources->handles,
                                                   handle, &value,
                                                   resource_identity) != 0)
        return -1;
    memcpy(((axi_host_eff_ctx *)ctx)->resource_identity_storage,
           resource_identity, 32);
    ((axi_host_eff_ctx *)ctx)->resource_identity =
        ((axi_host_eff_ctx *)ctx)->resource_identity_storage;
    net_sock_release(ctx, handle);
    if (axi_handle_table_remove(&ctx->resources->handles, handle, &value) != 0)
        return -1;
    /* Ownership is relinquished even when close reports an interrupted or
     * delayed writeback error; the descriptor must never re-enter the table. */
    (void)close((int)(value - 1));
    return 0;
}

/* ---- replay persistence (host reference) -------------------------------- */
/* The replay core is stdio-agnostic; these helpers wire it to a FILE* on the
 * host and will be replaced by the Single Door file primitive in the sovereign
 * Beyond build. */

typedef struct {
    FILE *f;
} axi_platform_replay_file;

static size_t replay_file_write(const void *buf, size_t len, void *user)
{
    axi_platform_replay_file *rf = (axi_platform_replay_file *)user;
    return fwrite(buf, 1, len, rf->f);
}

static size_t replay_file_read(void *buf, size_t len, void *user)
{
    axi_platform_replay_file *rf = (axi_platform_replay_file *)user;
    return fread(buf, 1, len, rf->f);
}

int axi_platform_replay_save(const char *path, const axi_replay *R)
{
    if (!path || !R) return -1;
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    axi_platform_replay_file rf = { f };
    int rc = axi_replay_save_to(R, replay_file_write, &rf);
    if (fclose(f) != 0) rc = -1;
    return rc;
}

int axi_platform_replay_load(const char *path, axi_replay *R)
{
    if (!path || !R) return -1;
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    axi_platform_replay_file rf = { f };
    int rc = axi_replay_load_from(R, replay_file_read, &rf);
    fclose(f);
    return rc;
}
