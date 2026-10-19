/* axial — deterministic replay (W6.5 / AXI-P1 extension).
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * The replay system enables bit-exact reproduction of I/O effects by:
 * 1. Recording all effect invocations with their payloads, results and fuel.
 * 2. Providing mock host implementations that return recorded results.
 *
 * This allows `axi replay <trace.axr>` to re-run a cell and produce
 * identical ledger + output without touching the real world.
 *
 * File I/O lives in the platform layer (axi_platform_*.c); this file only
 * knows byte buffers and callbacks, so the sovereign Beyond build can plug
 * the Single Door file primitive without changing replay semantics.
 */
#include "axi.h"
#include "axi_alloc.h"
#include "axi_replay.h"
#include "axi_hash.h"
#include <string.h>
#include <stdlib.h>

static int replay_array_bytes(size_t count, size_t element, size_t *bytes)
{
    if (!bytes || (count != 0 && element > (size_t)-1 / count)) return -1;
    *bytes = count * element;
    return 0;
}

static void replay_account_size_overflow(axi_mem_account *account)
{
    if (account) (void)axi_mem_alloc(account, (size_t)-1);
}

static void put_be32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24); out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);  out[3] = (uint8_t)value;
}

static void put_be64(uint8_t *out, uint64_t value)
{
    int i;
    for (i = 0; i < 8; i++) out[i] = (uint8_t)(value >> (56 - 8 * i));
}

static int canonical_result(const void **result, size_t *rlen,
                            uint8_t scalar[8], int has_result_str)
{
    long value;
    if (has_result_str || !result || !*result) return 1;
    if (!rlen || *rlen != sizeof value) return 0;
    memcpy(&value, *result, sizeof value);
    put_be64(scalar, (uint64_t)(int64_t)value);
    *result = scalar;
    *rlen = sizeof(uint64_t);
    return 1;
}

typedef char replay_digest_scratch_probe[
    sizeof(uint8_t[64 + 64 + 8 + 32 + 32 + 8 + 1 + 32 + 8 + 1
                   + 4 + 1024 + 4 + 1024])
        == AXI_REPLAY_ENTRY_DIGEST_SCRATCH_BYTES ? 1 : -1];

int axi_replay_entry_digest_accounted(const axi_replay_entry *rec,
                                      uint8_t out[32],
                                      axi_mem_account *account)
{
    uint8_t bytes[64 + 64 + 8 + 32 + 32 + 8 + 1 + 32 + 8 + 1
                   + 4 + 1024 + 4 + 1024];
    uint8_t digest[32];
    size_t offset = 0;
    if (!rec || !out) return 0;
    if (account && !axi_mem_reserve(account, sizeof bytes)) return 0;
#define APPEND(src, len) do { memcpy(bytes + offset, (src), (len)); offset += (len); } while (0)
    APPEND(rec->cap, AXI_CAPNAME);
    APPEND(rec->cell, AXI_CAPNAME);
    put_be64(bytes + offset, rec->nbytes); offset += 8;
    APPEND(rec->digest, 32);
    APPEND(rec->result_digest, 32);
    put_be64(bytes + offset, rec->fuel_used); offset += 8;
    bytes[offset++] = rec->has_record_digest;
    APPEND(rec->record_digest, 32);
    put_be64(bytes + offset, rec->record_nbytes); offset += 8;
    bytes[offset++] = rec->has_result_str;
    put_be32(bytes + offset, (uint32_t)rec->payload_len); offset += 4;
    APPEND(rec->payload, rec->payload_len);
    put_be32(bytes + offset, (uint32_t)rec->result_len); offset += 4;
    APPEND(rec->result, rec->result_len);
#undef APPEND
    axi_sha256(bytes, offset, digest);
    if (account && !axi_mem_release(account, sizeof bytes)) return 0;
    memcpy(out, digest, sizeof digest);
    return 1;
}

static int canonical_name(const char name[AXI_CAPNAME])
{
    const char *nul = memchr(name, '\0', AXI_CAPNAME);
    size_t i;
    if (!nul) return 0;
    for (i = (size_t)(nul - name) + 1; i < AXI_CAPNAME; i++)
        if (name[i] != '\0') return 0;
    return 1;
}

/* ---- init / free -------------------------------------------------------- */

void axi_replay_init(axi_replay *R, const uint8_t mod_hash[32])
{
    axi_replay_init_accounted(R, mod_hash, NULL);
}

void axi_replay_init_accounted(axi_replay *R, const uint8_t mod_hash[32],
                               axi_mem_account *account)
{
    R->records = NULL;
    R->n = R->cap = 0;
    R->cursor = 0;
    R->oom = 0;
    R->mode = AXI_REPLAY_NONE;
    R->account = account;
    if (mod_hash) memcpy(R->mod_hash, mod_hash, 32);
    else memset(R->mod_hash, 0, 32);
}

void axi_replay_free(axi_replay *R)
{
    if (!R) return;
    if (R->records) {
        if (R->account) {
            if (!axi_mem_free(R->account, R->records)) return;
        } else free(R->records);
    }
    R->records = NULL;
    R->n = R->cap = 0;
    R->cursor = 0;
}

axi_replay *axi_replay_new(const uint8_t mod_hash[32])
{
    axi_replay *R = axi_malloc(sizeof(axi_replay));
    if (!R) return NULL;
    axi_replay_init(R, mod_hash);
    return R;
}

int axi_replay_prepare(axi_replay *R, size_t payload_len)
{
    size_t bytes;
    if (!R || R->mode != AXI_REPLAY_RECORD) return 0;
    if (payload_len > sizeof R->records[0].payload) {
        R->oom = 1;
        return -1;
    }
    if (R->n >= R->cap) {
        size_t ncap;
        axi_replay_entry *records;
        if (R->cap && R->cap > (size_t)-1 / 2) {
            replay_account_size_overflow(R->account);
            R->oom = 1;
            return -1;
        }
        ncap = R->cap ? R->cap * 2 : 16;
        if (replay_array_bytes(ncap, sizeof *records, &bytes) != 0) {
            replay_account_size_overflow(R->account);
            R->oom = 1;
            return -1;
        }
        records = R->account
            ? axi_mem_realloc(R->account, R->records, bytes)
            : axi_realloc(R->records, bytes);
        if (!records) {
            R->oom = 1;
            return -1;
        }
        R->records = records;
        R->cap = ncap;
    }
    return 0;
}

/* ---- recording phase (used by real host effects) ------------------------ */

int axi_replay_record(axi_replay *R, const char *cap, const char *cell,
                      const void *payload, size_t plen,
                      const void *result, size_t rlen,
                      uint64_t fuel_used,
                      const uint8_t *record_digest, uint64_t record_nbytes,
                      int has_result_str)
{
    if (!R || R->mode != AXI_REPLAY_RECORD) return 0; /* no-op when not recording */
    if (plen > sizeof R->records[0].payload || rlen > sizeof R->records[0].result) {
        R->oom = 1;
        return -1;
    }
    if (axi_replay_prepare(R, plen) != 0) return -1;
    axi_replay_entry *rec = &R->records[R->n];
    uint8_t scalar[8];
    if (!canonical_result(&result, &rlen, scalar, has_result_str)) {
        R->oom = 1;
        return -1;
    }
    memset(rec, 0, sizeof *rec);
    strncpy(rec->cap, cap, AXI_CAPNAME - 1); rec->cap[AXI_CAPNAME - 1] = '\0';
    strncpy(rec->cell, cell, AXI_CAPNAME - 1); rec->cell[AXI_CAPNAME - 1] = '\0';
    rec->nbytes = plen;
    axi_sha256(payload, plen, rec->digest);
    if (has_result_str || result) axi_sha256(result, rlen, rec->result_digest);
    else memset(rec->result_digest, 0, 32);
    rec->fuel_used = fuel_used;
    rec->has_record_digest = record_digest ? 1 : 0;
    rec->record_nbytes = record_nbytes;
    if (record_digest) memcpy(rec->record_digest, record_digest, 32);
    else memset(rec->record_digest, 0, 32);
    rec->has_result_str = has_result_str;
    if (plen > 0) memcpy(rec->payload, payload, plen);
    rec->payload_len = plen;
    if (result && rlen > 0) memcpy(rec->result, result, rlen);
    rec->result_len = rlen;
    if (!axi_replay_entry_digest_accounted(
            rec, rec->entry_digest, R->account)) { /* AXI-INV-076 */
        R->oom = 1;
        return -1;
    }
    R->n++;
    return 0;
}

/* ---- replay phase (mock host effects) ----------------------------------- */

int axi_replay_peek(axi_replay *R, const char *cap, const char *cell,
                    const void *payload, size_t plen,
                    void *out_result, size_t *out_len,
                    uint64_t *out_fuel_used,
                    uint8_t *out_record_digest, uint64_t *out_record_nbytes,
                    int *out_has_record_digest, int *out_has_result_str)
{
    if (!R || R->mode != AXI_REPLAY_REPLAY) return -1;
    if (R->cursor >= R->n) return -1; /* no more records */
    axi_replay_entry *rec = &R->records[R->cursor];
    uint8_t entry_digest[32];
    if (!axi_replay_entry_digest_accounted(rec, entry_digest, R->account))
        return -1;
    if (memcmp(entry_digest, rec->entry_digest, 32) != 0) return -1;

    /* Verify this is the expected effect */
    if (strcmp(rec->cap, cap) != 0 || strcmp(rec->cell, cell) != 0) return -1;

    /* AXI-INV-076 / INV-281: verify all replay-controlled bytes before any
     * result, fuel or receipt field is delivered to the VM. */
    if (rec->nbytes != plen || rec->payload_len != plen
            || (plen > 0 && memcmp(rec->payload, payload, plen) != 0)) return -1;
    uint8_t d[32];
    axi_sha256(payload, plen, d);
    if (memcmp(d, rec->digest, 32) != 0) return -1;
    if (rec->has_result_str || rec->result_len > 0)
        axi_sha256(rec->result, rec->result_len, d);
    else memset(d, 0, sizeof d);
    if (memcmp(d, rec->result_digest, 32) != 0) return -1;

    /* Return recorded result */
    if (rec->result_len > *out_len) return -1;
    if (rec->result_len > 0 && out_result) memcpy(out_result, rec->result, rec->result_len);
    *out_len = rec->result_len;
    if (out_fuel_used) *out_fuel_used = rec->fuel_used;
    if (out_has_record_digest) *out_has_record_digest = rec->has_record_digest;
    if (out_record_nbytes) *out_record_nbytes = rec->record_nbytes;
    if (out_record_digest && rec->has_record_digest) memcpy(out_record_digest, rec->record_digest, 32);
    if (out_has_result_str) *out_has_result_str = rec->has_result_str;

    return 0;
}

int axi_replay_commit(axi_replay *R)
{
    if (!R || R->mode != AXI_REPLAY_REPLAY || R->cursor >= R->n) return -1;
    R->cursor++;
    return 0;
}

int axi_replay_next(axi_replay *R, const char *cap, const char *cell,
                    const void *payload, size_t plen,
                    void *out_result, size_t *out_len,
                    uint64_t *out_fuel_used,
                    uint8_t *out_record_digest, uint64_t *out_record_nbytes,
                    int *out_has_record_digest, int *out_has_result_str)
{
    return axi_replay_peek(R, cap, cell, payload, plen, out_result, out_len,
                           out_fuel_used, out_record_digest,
                           out_record_nbytes, out_has_record_digest,
                           out_has_result_str) == 0
        && axi_replay_commit(R) == 0 ? 0 : -1;
}

int axi_replay_at_end(const axi_replay *R) { return R->cursor >= R->n; }

/* ---- serialization helpers ---------------------------------------------- */

static int wr_be32(uint32_t v, axi_replay_write_fn w, void *user)
{
    uint8_t b[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16),
                     (uint8_t)(v >> 8),  (uint8_t)v };
    return w(b, 4, user) == 4 ? 0 : -1;
}

static int wr_be64(uint64_t v, axi_replay_write_fn w, void *user)
{
    uint8_t b[8];
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (56 - 8 * i));
    return w(b, 8, user) == 8 ? 0 : -1;
}

static int rd_be32(uint32_t *v, axi_replay_read_fn r, void *user)
{
    uint8_t b[4];
    if (r(b, 4, user) != 4) return -1;
    *v = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
         ((uint32_t)b[2] << 8)  |  (uint32_t)b[3];
    return 0;
}

static int rd_be64(uint64_t *v, axi_replay_read_fn r, void *user)
{
    uint8_t b[8];
    if (r(b, 8, user) != 8) return -1;
    *v = 0;
    for (int i = 0; i < 8; i++) *v = (*v << 8) | b[i];
    return 0;
}

/* ---- serialization ------------------------------------------------------ */

int axi_replay_save_to(const axi_replay *R, axi_replay_write_fn w, void *user)
{
    if (!R || !w) return -1;

    /* Magic + version */
    if (w("AXI-REPLAY-v3", 14, user) != 14) return -1;

    /* Module hash */
    if (w(R->mod_hash, 32, user) != 32) return -1;

    /* Record count */
    if (wr_be64((uint64_t)R->n, w, user) != 0) return -1;

    for (size_t i = 0; i < R->n; i++) {
        const axi_replay_entry *rec = &R->records[i];
        if (w(rec->cap, AXI_CAPNAME, user) != AXI_CAPNAME) return -1;
        if (w(rec->cell, AXI_CAPNAME, user) != AXI_CAPNAME) return -1;
        if (wr_be64(rec->nbytes, w, user) != 0) return -1;
        if (w(rec->digest, 32, user) != 32) return -1;
        if (w(rec->result_digest, 32, user) != 32) return -1;
        if (wr_be64(rec->fuel_used, w, user) != 0) return -1;
        if (w(&rec->has_record_digest, 1, user) != 1) return -1;
        if (w(rec->record_digest, 32, user) != 32) return -1;
        if (wr_be64(rec->record_nbytes, w, user) != 0) return -1;
        if (w(&rec->has_result_str, 1, user) != 1) return -1;
        if (wr_be32((uint32_t)rec->payload_len, w, user) != 0) return -1;
        if (rec->payload_len > 0 && w(rec->payload, rec->payload_len, user) != rec->payload_len) return -1;
        if (wr_be32((uint32_t)rec->result_len, w, user) != 0) return -1;
        if (rec->result_len > 0 && w(rec->result, rec->result_len, user) != rec->result_len) return -1;
        if (w(rec->entry_digest, 32, user) != 32) return -1;
    }

    return 0;
}

static int replay_load_empty(axi_replay *R, axi_replay_read_fn r, void *user)
{
    char magic[15] = {0};
    if (r(magic, 14, user) != 14) return -1;
    if (strcmp(magic, "AXI-REPLAY-v3") != 0) return -1;

    if (r(R->mod_hash, 32, user) != 32) return -1;

    uint64_t n;
    if (rd_be64(&n, r, user) != 0) return -1;

    if (n > 10000) return -1; /* sanity */

    size_t bytes;
    if (replay_array_bytes((size_t)n, sizeof(axi_replay_entry), &bytes) != 0) {
        replay_account_size_overflow(R->account);
        return -1;
    }
    (void)bytes;
    R->records = n ? (R->account
        ? axi_mem_calloc(R->account, (size_t)n, sizeof(axi_replay_entry))
        : axi_calloc((size_t)n, sizeof(axi_replay_entry))) : NULL;
    if (n && !R->records) return -1;
    R->cap = R->n = n;
    R->cursor = 0;
    R->oom = 0;

    for (size_t i = 0; i < n; i++) {
        axi_replay_entry *rec = &R->records[i];
        if (r(rec->cap, AXI_CAPNAME, user) != AXI_CAPNAME) return -1;
        if (r(rec->cell, AXI_CAPNAME, user) != AXI_CAPNAME) return -1;
        if (!canonical_name(rec->cap) || !canonical_name(rec->cell)) return -1;
        if (rd_be64(&rec->nbytes, r, user) != 0) return -1;
        if (r(rec->digest, 32, user) != 32) return -1;
        if (r(rec->result_digest, 32, user) != 32) return -1;
        if (rd_be64(&rec->fuel_used, r, user) != 0) return -1;
        if (r(&rec->has_record_digest, 1, user) != 1) return -1;
        if (rec->has_record_digest > 1) return -1;
        if (r(rec->record_digest, 32, user) != 32) return -1;
        if (rd_be64(&rec->record_nbytes, r, user) != 0) return -1;
        if (r(&rec->has_result_str, 1, user) != 1) return -1;
        if (rec->has_result_str > 1) return -1;
        uint32_t plen;
        if (rd_be32(&plen, r, user) != 0) return -1;
        if (plen > 1024) return -1;
        rec->payload_len = plen;
        if (plen > 0 && r(rec->payload, plen, user) != plen) return -1;
        uint32_t rlen;
        if (rd_be32(&rlen, r, user) != 0) return -1;
        if (rlen > 1024) return -1;
        rec->result_len = rlen;
        if (rlen > 0 && r(rec->result, rlen, user) != rlen) return -1;
        if (r(rec->entry_digest, 32, user) != 32) return -1;
        if (rec->nbytes != rec->payload_len) return -1;
        uint8_t digest[32];
        axi_sha256(rec->payload, rec->payload_len, digest);
        if (memcmp(digest, rec->digest, 32) != 0) return -1;
        if (rec->has_result_str || rec->result_len > 0)
            axi_sha256(rec->result, rec->result_len, digest);
        else memset(digest, 0, sizeof digest);
        if (memcmp(digest, rec->result_digest, 32) != 0) return -1;
        if (!axi_replay_entry_digest_accounted(rec, digest, R->account))
            return -1;
        if (memcmp(digest, rec->entry_digest, 32) != 0) return -1;
    }

    /* Exact framing: appended bytes are not an ignorable second truth. */
    uint8_t trailing;
    if (r(&trailing, 1, user) != 0) return -1;

    return 0;
}

int axi_replay_load_from(axi_replay *R, axi_replay_read_fn r, void *user)
{
    axi_replay loaded;
    axi_mem_failure_cause failure;
    axi_mem_failure_cause denied_failure;
    size_t failed_request, denied_request;
    if (!R || !r) return -1;

    axi_replay_init_accounted(&loaded, NULL, R->account);
    loaded.mode = R->mode;
    if (replay_load_empty(&loaded, r, user) != 0) {
        failure = R->account ? R->account->failure : AXI_MEM_FAILURE_NONE;
        failed_request = R->account ? R->account->failed_request : 0;
        denied_failure = R->account ? R->account->denied_failure
                                    : AXI_MEM_FAILURE_NONE;
        denied_request = R->account ? R->account->denied_request : 0;
        axi_replay_free(&loaded);
        if (R->account && failure != AXI_MEM_FAILURE_NONE) {
            R->account->failure = failure;
            R->account->failed_request = failed_request;
            R->account->denied_failure = denied_failure;
            R->account->denied_request = denied_request;
        }
        return -1;
    }

    axi_replay_free(R);
    if (R->records) {
        axi_replay_free(&loaded);
        return -1;
    }
    *R = loaded;
    return 0;
}
