/* axial — platform abstraction for host effects. Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * The effect plane (axi_effect.c) must not know what a file, socket or
 * process is. It knows fuel, grants and ledgers; the platform knows how to
 * touch the world and report back. This header is the only door between
 * those two worlds.
 *
 * Two implementations exist:
 *   axi_platform_posix.c  — host reference (libc/POSIX shim). Used by the
 *                           gate and by jash embedding today.
 *   axi_platform_beyond.c — sovereign build (W23). Will use the Beyond's
 *                           Single Door (__bsys6) and GAIOLA envelopes.
 *
 * AXI-LAW-08 / AXI-LAW-11: no libc in the sovereign build. The POSIX file is
 * compiled by the host cc, exactly like axi_osif.c, and for the same reason.
 */
#ifndef AXI_PLATFORM_H
#define AXI_PLATFORM_H

#include <stdint.h>
#include <stddef.h>

struct axi_host_eff_ctx;   /* defined in axi_effect.h */
struct axi_resource_envelope;
struct axi_resource_vector;

uint64_t axi_platform_monotonic_ns(void *opaque, int *ok);
typedef int (*axi_platform_blocking_fn)(void *opaque);
int axi_platform_blocking_call(const struct axi_host_eff_ctx *ctx,
                               axi_platform_blocking_fn call, void *opaque);
void axi_platform_handles_close(struct axi_resource_envelope *resources);
int axi_platform_fs_root_open(struct axi_resource_envelope *resources,
                              const char *path);
int axi_platform_fs_root_adopt(struct axi_resource_envelope *resources, int fd);
void axi_platform_fs_root_close(struct axi_resource_envelope *resources);

/* Spawn a child process that re-runs the current module with a given cell,
 * fuel budget and cap set. The child's fuel consumption is written back
 * through a platform channel and added to *fuel_used_out.
 *
 * Returns the child's exit code (0 = clean), or -1 on platform failure.
 * If the child died because it exhausted fuel, *fuel_exhausted is set to 1.
 *
 * mod_path: path to the .axb the child must load.
 * cell:     name of the cell to run.
 * args:     NUL-separated argument string ("arg1|arg2"), may be NULL.
 * fuel:     budget the child inherits (parent's remaining).
 * grants:   cap names to forward, as a "|"-joined string (may be NULL).
 * fuel_used_out:    child reports its spend here.
 * fuel_exhausted:   set to 1 if the child died on AXI-R008.
 */
int axi_platform_spawn(const char *mod_path, const uint8_t mod_root[32],
                       const char *trusted_key_path,
                       const char *cell, const char *args, size_t args_len,
                       uint64_t fuel,
                       const char *grants,
                       const struct axi_resource_envelope *resources,
                       uint64_t *fuel_used_out,
                       struct axi_resource_vector *resources_used_out,
                       int *fuel_exhausted);
int axi_platform_report_fuel(int fd, uint64_t fuel_used, int fuel_exhausted,
                             const struct axi_resource_vector *resources_used);

/* Host effect implementations (POSIX shim). In the sovereign Beyond build
 * these are replaced by axi_platform_beyond.c using the Single Door.
 * The signatures match axi_host_eff.fn in axi_effect.h. */
long axi_host_write(const struct axi_host_eff_ctx *ctx, const void *buf, size_t len);
long axi_host_fs_read(const struct axi_host_eff_ctx *ctx, const void *buf, size_t len);
long axi_host_fs_write(const struct axi_host_eff_ctx *ctx, const void *buf, size_t len);
long axi_host_crypto_hash(const struct axi_host_eff_ctx *ctx, const void *buf, size_t len);
long axi_host_proc_spawn(const struct axi_host_eff_ctx *ctx, const void *buf, size_t len);
long axi_host_net_connect(const struct axi_host_eff_ctx *ctx, const void *buf, size_t len);
long axi_host_net_read(const struct axi_host_eff_ctx *ctx, const void *buf, size_t len);
long axi_host_net_write(const struct axi_host_eff_ctx *ctx, const void *buf, size_t len);
long axi_host_net_close(const struct axi_host_eff_ctx *ctx, const void *buf, size_t len);

/* Replay persistence (MOAT-4). The host reference uses stdio; the sovereign
 * Beyond build substitutes the Single Door file primitive. */
struct axi_replay;
int axi_platform_replay_save(const char *path, const struct axi_replay *R);
int axi_platform_replay_load(const char *path, struct axi_replay *R);

/* Fill exactly len bytes from the host CSPRNG; partial entropy is refusal. */
int axi_platform_random(void *buf, size_t len);

#endif /* AXI_PLATFORM_H */
