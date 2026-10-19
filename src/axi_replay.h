/* axial — deterministic replay (W6.5 / AXI-P1 extension). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * The replay system enables bit-exact reproduction of I/O effects by:
 * 1. Recording all effect invocations with their payloads, results and fuel.
 * 2. Providing mock host implementations that return recorded results.
 *
 * This allows `axi replay <trace.axr>` to re-run a cell and produce
 * identical ledger + output without touching the real world.
 */
#ifndef AXI_REPLAY_H
#define AXI_REPLAY_H

#include <stdint.h>
#include <stddef.h>
#include "axi_mem_account.h"

#define AXI_CAPNAME 64

/* Exact automatic preimage used to bind one replay record. */
#define AXI_REPLAY_ENTRY_DIGEST_SCRATCH_BYTES 2306u

#define AXI_REPLAY_NONE   0
#define AXI_REPLAY_RECORD 1
#define AXI_REPLAY_REPLAY 2

/* ---- replay record (one effect invocation) ------------------------------- */

typedef struct {
    char     cap[AXI_CAPNAME];     /* effect name, e.g. "fs.Read" */
    char     cell[AXI_CAPNAME];    /* cell that invoked it */
    uint64_t nbytes;               /* payload size / bytes returned */
    uint8_t  digest[32];           /* SHA-256 of payload */
    uint8_t  result_digest[32];    /* SHA-256 of result (for verification) */
    uint64_t fuel_used;            /* fuel consumed by this effect (incl. child) */
    uint8_t  record_digest[32];    /* ledger digest supplied by host (net.*) */
    uint64_t record_nbytes;        /* ledger byte count supplied by host */
    uint8_t  has_record_digest;    /* 1 if record_digest/nbytes are valid */
    uint8_t  has_result_str;       /* 1 if result is bytes, 0 if result is the long return */
    uint8_t  payload[1024];        /* original payload (for mock to match) */
    size_t   payload_len;
    uint8_t  result[1024];         /* result bytes */
    size_t   result_len;
    uint8_t  entry_digest[32];     /* binds all serialized fields */
} axi_replay_entry;

struct axi_replay {
    axi_replay_entry *records;
    size_t n, cap;
    size_t cursor;              /* current record during replay */
    uint8_t mod_hash[32];       /* module hash for verification */
    int mode;                   /* NONE / RECORD / REPLAY */
    int oom;
    axi_mem_account *account;   /* optional, caller-owned allocation account */
};

typedef struct axi_replay axi_replay;

/* Initialize replay context with module hash (for verification). */
void axi_replay_init(axi_replay *R, const uint8_t mod_hash[32]);
/* The account must outlive the replay context. NULL preserves the legacy path. */
void axi_replay_init_accounted(axi_replay *R, const uint8_t mod_hash[32],
                               axi_mem_account *account);
void axi_replay_free(axi_replay *R);

/* Reserve one bounded record before touching the host. */
int axi_replay_prepare(axi_replay *R, size_t payload_len);

/* Allocate a new replay context. Returns NULL on OOM. */
axi_replay *axi_replay_new(const uint8_t mod_hash[32]);

/* Set/get mode. */
static inline void axi_replay_set_mode(axi_replay *R, int mode) { if (R) R->mode = mode; }
static inline int axi_replay_get_mode(const axi_replay *R) { return R ? R->mode : AXI_REPLAY_NONE; }

/* Recording phase: call from real host effect implementations to capture
 * the exact bytes that crossed the door and the result they produced. */
int axi_replay_record(axi_replay *R, const char *cap, const char *cell,
                      const void *payload, size_t plen,
                      const void *result, size_t rlen,
                      uint64_t fuel_used,
                      const uint8_t *record_digest, uint64_t record_nbytes,
                      int has_result_str);

/* Replay phase: mock host effects call this to get the recorded result.
 * Returns 0 on success, -1 if mismatch or no more records.
 * On success fills out_result (up to *out_len), out_len, *out_fuel_used,
 * and record digest fields. */
int axi_replay_next(axi_replay *R, const char *cap, const char *cell,
                    const void *payload, size_t plen,
                    void *out_result, size_t *out_len,
                    uint64_t *out_fuel_used,
                     uint8_t *out_record_digest, uint64_t *out_record_nbytes,
                     int *out_has_record_digest, int *out_has_result_str);
int axi_replay_peek(axi_replay *R, const char *cap, const char *cell,
                    const void *payload, size_t plen,
                    void *out_result, size_t *out_len,
                    uint64_t *out_fuel_used,
                    uint8_t *out_record_digest, uint64_t *out_record_nbytes,
                    int *out_has_record_digest, int *out_has_result_str);
int axi_replay_commit(axi_replay *R);

int axi_replay_at_end(const axi_replay *R);

/* Internal CA21 source API shared with replay-v4. NULL preserves the legacy
 * unaccounted path; caller-owned output changes only on success. */
int axi_replay_entry_digest_accounted(const axi_replay_entry *record,
                                      uint8_t out[32],
                                      axi_mem_account *account);

/* Streaming I/O callbacks for save/load. The caller supplies the file handle
 * (or other sink) through `user`; this keeps stdio out of the replay core.
 * Both return bytes transferred; short counts or 0 mean failure. */
typedef size_t (*axi_replay_write_fn)(const void *buf, size_t len, void *user);
typedef size_t (*axi_replay_read_fn)(void *buf, size_t len, void *user);

/* Save/load replay trace through the supplied callbacks. */
int axi_replay_save_to(const axi_replay *R, axi_replay_write_fn write_fn, void *user);
int axi_replay_load_from(axi_replay *R, axi_replay_read_fn read_fn, void *user);

#endif /* AXI_REPLAY_H */
