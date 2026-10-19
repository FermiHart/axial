/* axial — the effect plane (W19). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * This file owns semantics, not mechanism: grants, ledger, and the table of
 * host effects. HOW an effect touches the world lives in the platform layer
 * (axi_platform_*.c). AXI-LAW-11: on the host these are POSIX shims; on the
 * Beyond sovereign build they become Single Door syscalls.
 */
#include "axi_effect.h"
#include "axi_alloc.h"
#include "axi_hash.h"
#include "axi_platform.h"
#include <limits.h>
#include <string.h>
#include <stdlib.h>

#define JOURNAL_SEED "AXI-EFFECT-JOURNAL-v2"

static int effect_array_bytes(size_t count, size_t element, size_t *bytes)
{
    if (!bytes || (count != 0 && element > (size_t)-1 / count)) return -1;
    *bytes = count * element;
    return 0;
}

static void effect_account_size_overflow(axi_mem_account *account)
{
    if (account) (void)axi_mem_alloc(account, (size_t)-1);
}

static size_t effect_name_len(const char *name)
{
    size_t n = 0;
    if (name) while (n < AXI_CAPNAME && name[n]) n++;
    return n;
}

static int effect_name_ok(const char *name)
{
    size_t n = effect_name_len(name);
    return n > 0 && n < AXI_CAPNAME;
}

static int journal_name_ok(const char name[AXI_CAPNAME])
{
    const char *nul = memchr(name, '\0', AXI_CAPNAME);
    if (!nul || nul == name) return 0;
    for (size_t i = (size_t)(nul - name) + 1; i < AXI_CAPNAME; i++)
        if (name[i] != '\0') return 0;
    return 1;
}

static void journal_seed(const uint8_t mod[32], uint8_t out[32])
{
    uint8_t seed[sizeof(JOURNAL_SEED) - 1 + 32];
    memcpy(seed, JOURNAL_SEED, sizeof(JOURNAL_SEED) - 1);
    memcpy(seed + sizeof(JOURNAL_SEED) - 1, mod, 32);
    axi_sha256(seed, sizeof seed, out);
}

static void journal_link(const uint8_t prev[32],
                         const axi_effect_journal_row *row, uint8_t out[32])
{
    uint8_t bytes[32 + 8 + 8 + 1 + AXI_CAPNAME + AXI_CAPNAME + 8 + 32 + 8
                  + 8 + 32 + 32 + 3];
    size_t off = 0;
    uint64_t outcome = (uint64_t)row->outcome;
    memcpy(bytes + off, prev, 32); off += 32;
    for (int i = 7; i >= 0; i--) bytes[off++] = (uint8_t)(row->seq >> (i * 8));
    for (int i = 7; i >= 0; i--) bytes[off++] = (uint8_t)(row->attempt >> (i * 8));
    bytes[off++] = row->state;
    memcpy(bytes + off, row->cap, AXI_CAPNAME); off += AXI_CAPNAME;
    memcpy(bytes + off, row->cell, AXI_CAPNAME); off += AXI_CAPNAME;
    for (int i = 7; i >= 0; i--) bytes[off++] = (uint8_t)(row->nbytes >> (i * 8));
    memcpy(bytes + off, row->digest, 32); off += 32;
    for (int i = 7; i >= 0; i--) bytes[off++] = (uint8_t)(outcome >> (i * 8));
    for (int i = 7; i >= 0; i--)
        bytes[off++] = (uint8_t)(row->actual_nbytes >> (i * 8));
    memcpy(bytes + off, row->actual_digest, 32); off += 32;
    memcpy(bytes + off, row->resource_identity, 32); off += 32;
    bytes[off++] = row->has_actual;
    bytes[off++] = row->has_resource_identity;
    bytes[off++] = row->evidence_failed;
    axi_sha256(bytes, off, out);
}

static int journal_reserve(axi_effect_journal *J, uint32_t need)
{
    uint32_t capacity;
    size_t bytes;
    axi_effect_journal_row *rows;
    if (!J || J->oom) return -1;
    if (J->n > J->cap || (J->cap && !J->row)) {
        J->oom = 1;
        return -1;
    }
    if (need > UINT32_MAX - J->n) {
        effect_account_size_overflow(J->account);
        J->oom = 1;
        return -1;
    }
    if (J->n + need <= J->cap) return 0;
    capacity = J->cap ? J->cap : 12;
    while (capacity < J->n + need) {
        if (capacity > UINT32_MAX / 2) {
            effect_account_size_overflow(J->account);
            J->oom = 1;
            return -1;
        }
        capacity *= 2;
    }
    if (effect_array_bytes((size_t)capacity, sizeof *rows, &bytes) != 0) {
        effect_account_size_overflow(J->account);
        J->oom = 1;
        return -1;
    }
    rows = J->account ? axi_mem_realloc(J->account, J->row, bytes)
                      : axi_realloc(J->row, bytes);
    if (!rows) { J->oom = 1; return -1; }
    J->row = rows;
    J->cap = capacity;
    return 0;
}

static void journal_append(axi_effect_journal *J, uint64_t attempt,
                            uint8_t state, int64_t outcome,
                            const axi_host_eff_ctx *ctx)
{
    axi_effect_journal_row *row = &J->row[J->n];
    const axi_effect_journal_row *first = state == AXI_JOURNAL_PREPARED
        ? NULL : &J->row[J->n - (J->open_state == AXI_JOURNAL_ATTEMPTED ? 2 : 1)];
    memset(row, 0, sizeof *row);
    row->seq = (uint64_t)J->n + 1;
    row->attempt = attempt;
    row->state = state;
    row->outcome = outcome;
    if (first) {
        memcpy(row->cap, first->cap, AXI_CAPNAME);
        memcpy(row->cell, first->cell, AXI_CAPNAME);
        row->nbytes = first->nbytes;
        memcpy(row->digest, first->digest, 32);
    }
    if (ctx && ctx->record_digest) {
        row->has_actual = 1;
        row->actual_nbytes = ctx->record_nbytes;
        memcpy(row->actual_digest, ctx->record_digest, 32);
    }
    if (ctx && ctx->resource_identity) {
        row->has_resource_identity = 1;
        memcpy(row->resource_identity, ctx->resource_identity, 32);
    }
    if (ctx && ctx->evidence_failed) row->evidence_failed = 1;
    journal_link(J->tip, row, row->tip);
    memcpy(J->tip, row->tip, 32);
    J->n++;
}

void axi_effect_journal_init(axi_effect_journal *J,
                             const uint8_t mod_hash[32])
{
    axi_effect_journal_init_accounted(J, mod_hash, NULL);
}

void axi_effect_journal_init_accounted(axi_effect_journal *J,
                                       const uint8_t mod_hash[32],
                                       axi_mem_account *account)
{
    if (!J) return;
    memset(J, 0, sizeof *J);
    J->account = account;
    if (mod_hash) memcpy(J->mod, mod_hash, 32);
    journal_seed(J->mod, J->tip);
}

void axi_effect_journal_free(axi_effect_journal *J)
{
    axi_mem_account *account;
    if (!J) return;
    account = J->account;
    if (J->row) {
        if (account) {
            if (!axi_mem_free(account, J->row)) return;
        } else free(J->row);
    }
    memset(J, 0, sizeof *J);
    J->account = account;
}

int axi_effect_journal_begin(axi_effect_journal *J, const char *cap,
                             const char *cell, const void *payload, size_t len,
                             uint64_t *attempt_out)
{
    axi_effect_journal_row *row;
    uint64_t attempt;
    if (!J || !attempt_out || J->open_attempt || !effect_name_ok(cap)
            || !effect_name_ok(cell) || (!payload && len)
            || J->next_attempt == UINT64_MAX || journal_reserve(J, 3) != 0)
        return -1;
    attempt = J->next_attempt + 1;
    row = &J->row[J->n];
    memset(row, 0, sizeof *row);
    row->seq = (uint64_t)J->n + 1;
    row->attempt = attempt;
    row->state = AXI_JOURNAL_PREPARED;
    memcpy(row->cap, cap, strlen(cap));
    memcpy(row->cell, cell, strlen(cell));
    row->nbytes = (uint64_t)len;
    axi_sha256(payload, len, row->digest);
    journal_link(J->tip, row, row->tip);
    memcpy(J->tip, row->tip, 32);
    J->n++;
    J->next_attempt = J->open_attempt = attempt;
    J->open_state = AXI_JOURNAL_PREPARED;
    *attempt_out = attempt;
    return 0;
}

int axi_effect_journal_attempt(axi_effect_journal *J, uint64_t attempt)
{
    if (!J || attempt == 0 || J->open_attempt != attempt
            || J->oom || !J->row || J->n == 0 || J->n >= J->cap
            || J->open_state != AXI_JOURNAL_PREPARED) return -1;
    journal_append(J, attempt, AXI_JOURNAL_ATTEMPTED, 0, NULL);
    J->open_state = AXI_JOURNAL_ATTEMPTED;
    return 0;
}

int axi_effect_journal_finish(axi_effect_journal *J, uint64_t attempt,
                               int committed, int64_t outcome)
{
    uint8_t state;
    if (!J || attempt == 0 || J->open_attempt != attempt
            || J->oom || !J->row || J->n == 0 || J->n >= J->cap
            || (J->open_state == AXI_JOURNAL_ATTEMPTED && J->n < 2)
            || (J->open_state != AXI_JOURNAL_PREPARED
                && J->open_state != AXI_JOURNAL_ATTEMPTED)
            || (committed != 0 && committed != 1)
            || (committed && (J->open_state != AXI_JOURNAL_ATTEMPTED
                              || outcome < 0))
            || (!committed && outcome >= 0)) return -1;
    state = committed ? AXI_JOURNAL_COMMITTED : AXI_JOURNAL_FAILED;
    journal_append(J, attempt, state, outcome, NULL);
    J->open_attempt = 0;
    J->open_state = 0;
    return 0;
}

int axi_effect_journal_finish_effect(axi_effect_journal *J, uint64_t attempt,
                                     const axi_host_eff_ctx *ctx)
{
    uint8_t state;
    int64_t outcome;
    if (!J || attempt == 0 || J->open_attempt != attempt
            || J->oom || !J->row || J->n == 0 || J->n >= J->cap
            || (J->open_state == AXI_JOURNAL_ATTEMPTED && J->n < 2)
            || !ctx || (J->open_state != AXI_JOURNAL_PREPARED
                && J->open_state != AXI_JOURNAL_ATTEMPTED)) return -1;
    outcome = ctx->host_outcome;
    if (outcome >= 0) {
        if (J->open_state != AXI_JOURNAL_ATTEMPTED) return -1;
        state = AXI_JOURNAL_COMMITTED;
    } else if (ctx && ctx->attempt_state == AXI_EFFECT_PARTIAL) {
        if (J->open_state != AXI_JOURNAL_ATTEMPTED) return -1;
        state = AXI_JOURNAL_PARTIAL;
    } else {
        state = AXI_JOURNAL_FAILED;
    }
    journal_append(J, attempt, state, outcome, ctx);
    J->open_attempt = 0;
    J->open_state = 0;
    return 0;
}

int axi_effect_journal_verify(const axi_effect_journal *J)
{
    uint8_t tip[32], linked[32];
    uint64_t open = 0, last_attempt = 0;
    uint8_t state = 0;
    const axi_effect_journal_row *first = NULL;
    if (!J || (J->n && !J->row) || J->n > J->cap) return -1;
    journal_seed(J->mod, tip);
    for (uint32_t i = 0; i < J->n; i++) {
        const axi_effect_journal_row *row = &J->row[i];
        if (row->seq != (uint64_t)i + 1 || !journal_name_ok(row->cap)
                || !journal_name_ok(row->cell)
                || row->has_actual > 1 || row->has_resource_identity > 1
                || row->evidence_failed > 1
                || (!row->has_actual
                    && (row->actual_nbytes != 0
                        || memcmp(row->actual_digest, (uint8_t[32]){0}, 32) != 0))
                || (!row->has_resource_identity
                    && memcmp(row->resource_identity,
                              (uint8_t[32]){0}, 32) != 0)) return -1;
        if (row->state == AXI_JOURNAL_PREPARED) {
            if (open || row->attempt != last_attempt + 1 || row->outcome != 0)
                return -1;
            open = row->attempt; state = row->state; first = row;
            last_attempt = row->attempt;
        } else {
            if (!open || row->attempt != open || !first
                    || memcmp(row->cap, first->cap, AXI_CAPNAME) != 0
                    || memcmp(row->cell, first->cell, AXI_CAPNAME) != 0
                    || row->nbytes != first->nbytes
                    || memcmp(row->digest, first->digest, 32) != 0) return -1;
            if (row->state == AXI_JOURNAL_ATTEMPTED) {
                if (state != AXI_JOURNAL_PREPARED || row->outcome != 0
                        || row->has_actual || row->has_resource_identity
                        || row->evidence_failed) return -1;
                state = row->state;
            } else if (row->state == AXI_JOURNAL_PARTIAL) {
                if (state != AXI_JOURNAL_ATTEMPTED || row->outcome >= 0)
                    return -1;
                open = 0; state = 0; first = NULL;
            } else if (row->state == AXI_JOURNAL_COMMITTED) {
                if (state != AXI_JOURNAL_ATTEMPTED || row->outcome < 0) return -1;
                open = 0; state = 0; first = NULL;
            } else if (row->state == AXI_JOURNAL_FAILED) {
                if ((state != AXI_JOURNAL_PREPARED
                        && state != AXI_JOURNAL_ATTEMPTED) || row->outcome >= 0)
                    return -1;
                open = 0; state = 0; first = NULL;
            } else return -1;
        }
        journal_link(tip, row, linked);
        if (memcmp(linked, row->tip, 32) != 0) return -1;
        memcpy(tip, linked, 32);
    }
    if (memcmp(tip, J->tip, 32) != 0 || open != J->open_attempt
            || state != J->open_state || last_attempt != J->next_attempt)
        return -1;
    return 0;
}

static void journal_hex(FILE *out, const void *bytes, size_t len)
{
    static const char hex[] = "0123456789abcdef";
    const uint8_t *p = bytes;
    for (size_t i = 0; i < len; i++) {
        fputc(hex[p[i] >> 4], out);
        fputc(hex[p[i] & 15], out);
    }
}

static const char *journal_state_name(uint8_t state)
{
    switch (state) {
    case AXI_JOURNAL_PREPARED: return "PREPARED";
    case AXI_JOURNAL_ATTEMPTED: return "ATTEMPTED";
    case AXI_JOURNAL_PARTIAL: return "PARTIAL";
    case AXI_JOURNAL_COMMITTED: return "COMMITTED";
    case AXI_JOURNAL_FAILED: return "FAILED";
    default: return NULL;
    }
}

int axi_effect_journal_fprint(const axi_effect_journal *J, FILE *out)
{
    if (!out || axi_effect_journal_verify(J) != 0) return 1;
    fputs("journal v2\nmodule ", out);
    journal_hex(out, J->mod, sizeof J->mod);
    fprintf(out, "\nrows %u\n", J->n);
    for (uint32_t i = 0; i < J->n; i++) {
        const axi_effect_journal_row *row = &J->row[i];
        const char *state = journal_state_name(row->state);
        const char *cap_end = memchr(row->cap, '\0', AXI_CAPNAME);
        const char *cell_end = memchr(row->cell, '\0', AXI_CAPNAME);
        if (!state || !cap_end || !cell_end) return 1;
        fprintf(out, "row %llu\nattempt %llu\nstate %s\ncap ",
                (unsigned long long)row->seq,
                (unsigned long long)row->attempt, state);
        journal_hex(out, row->cap, (size_t)(cap_end - row->cap));
        fputs("\ncell ", out);
        journal_hex(out, row->cell, (size_t)(cell_end - row->cell));
        fprintf(out, "\nbytes %llu\ndigest ",
                (unsigned long long)row->nbytes);
        journal_hex(out, row->digest, sizeof row->digest);
        fprintf(out, "\noutcome %lld\nactual-bytes %llu\nactual-digest ",
                (long long)row->outcome,
                (unsigned long long)row->actual_nbytes);
        journal_hex(out, row->actual_digest, sizeof row->actual_digest);
        fputs("\nresource-identity ", out);
        journal_hex(out, row->resource_identity, sizeof row->resource_identity);
        fprintf(out, "\nhas-actual %u\nhas-resource-identity %u\n"
                     "evidence-failed %u\ntip ",
                row->has_actual, row->has_resource_identity,
                row->evidence_failed);
        journal_hex(out, row->tip, sizeof row->tip);
        fputc('\n', out);
    }
    fputs("tip ", out);
    journal_hex(out, J->tip, sizeof J->tip);
    fputc('\n', out);
    return ferror(out) ? 1 : 0;
}

/* ---- grants ------------------------------------------------------------- */

void axi_grants_init(axi_grants *g)
{
    if (!g) return;
    memset(g, 0, sizeof *g);
}

int axi_grants_add(axi_grants *g, const char *name)
{
    size_t l = effect_name_len(name);
    if (axi_grants_verify(g) != 0) return -1;
    if (l == 0 || l >= AXI_CAPNAME) return -2;
    if (g->n >= AXI_CAP_MAX)        return -1;
    for (int i = 0; i < g->n; i++)
        if (strcmp(g->name[i], name) == 0) return -3;
    memcpy(g->name[g->n], name, l + 1);
    g->n++;
    return 0;
}

int axi_grants_has(const axi_grants *g, const char *name)
{
    if (!effect_name_ok(name) || axi_grants_verify(g) != 0) return 0;
    for (int i = 0; i < g->n; i++)
        if (strcmp(g->name[i], name) == 0) return 1;
    return 0;
}

int axi_grants_verify(const axi_grants *g)
{
    int i, j;
    if (!g || g->n < 0 || g->n > AXI_CAP_MAX) return -1;
    for (i = 0; i < g->n; i++) {
        const char *end = memchr(g->name[i], '\0', AXI_CAPNAME);
        if (!end || end == g->name[i]) return -1;
        for (j = 0; j < i; j++)
            if (strcmp(g->name[i], g->name[j]) == 0) return -1;
    }
    return 0;
}

int axi_grants_cap_slot(const axi_grants *g, const char *name,
                        uint32_t *slot)
{
    if (!g || !name || !slot || axi_grants_verify(g) != 0) return -1;
    for (int i = 0; i < g->n; i++) {
        if (strcmp(g->name[i], name) == 0) {
            *slot = (uint32_t)i;
            return 0;
        }
    }
    return -1;
}

int axi_grants_cap_matches(const axi_grants *g, uint32_t slot,
                           const char *atom,
                           uint32_t atom_len)
{
    /* Generation is checked by the invocation door; this resolves slot+atom. */
    size_t len;
    if (!g || !atom || axi_grants_verify(g) != 0
            || slot >= (uint32_t)g->n) return 0;
    len = strlen(g->name[slot]);
    return len == atom_len && memcmp(g->name[slot], atom, atom_len) == 0;
}

/* ---- replay-aware dispatch (MOAT-4) -------------------------------------
 * Every host effect is wrapped so that `axi run --record` can capture the
 * exact bytes that crossed the door and `axi replay` can reproduce them
 * without touching the real world. The wrapper is part of the effect plane
 * (semantics), not the platform layer (mechanism). /AXI-INV-069/ */

static int effect_deadline_allows_attempt(const axi_host_eff_ctx *ctx,
                                          axi_effect_journal *journal,
                                          uint64_t attempt)
{
    if (!ctx || !ctx->resources
            || axi_resource_check_deadline(ctx->resources) == AXI_RESOURCE_OK)
        return 1;
    /* AXI-INV-158: expiry after PREPARED must not claim host entry. */
    ((axi_host_eff_ctx *)ctx)->host_outcome = -1;
    ((axi_host_eff_ctx *)ctx)->attempt_state = AXI_EFFECT_NOT_ATTEMPTED;
    if (journal
            && axi_effect_journal_finish_effect(journal, attempt, ctx) != 0)
        ((axi_host_eff_ctx *)ctx)->evidence_failed = 1;
    return 0;
}

static int replay_scalar_result(const uint8_t bytes[8], long *out)
{
    uint64_t raw = 0;
    int64_t value;
    size_t i;
    if (!bytes || !out) return 0;
    for (i = 0; i < 8; i++) raw = (raw << 8) | bytes[i];
    value = (int64_t)raw;
#if LONG_MAX < INT64_MAX
    if (value > LONG_MAX || value < LONG_MIN) return 0;
#endif
    *out = (long)value;
    return 1;
}

static long axi_eff_dispatch(const axi_host_eff_ctx *ctx, const void *buf, size_t len,
                             const char *cap,
                             long (*real)(const axi_host_eff_ctx *, const void *, size_t))
{
    const char *cell = ctx && ctx->cell_name ? ctx->cell_name : "";
    axi_effect_journal *journal = ctx ? ctx->journal : NULL;
    uint64_t attempt = 0;
    int mode = ctx && ctx->replay ? ctx->replay->mode : AXI_REPLAY_NONE;
    if (!ctx || (!buf && len)) return -1;

    if (mode == AXI_REPLAY_REPLAY) {
        uint8_t *rbuf;
        uint8_t *rdig;
        size_t rlen = 1024u;
        uint64_t fuel_used = 0;
        uint64_t rec_nbytes = 0;
        int has_rec = 0, has_str = 0;
        long replay_result = -1;
        if (!ctx || !ctx->resources || !ctx->account) return -1;
        rdig = ((axi_host_eff_ctx *)ctx)->record_digest_storage;
        if (journal && axi_effect_journal_begin(journal, cap, cell, buf, len,
                                                 &attempt) != 0) return -1;
        if (!effect_deadline_allows_attempt(ctx, journal, attempt)) return -1;
        rbuf = axi_resource_output_alloc(ctx->resources, ctx->account, rlen);
        if (!rbuf) {
            ((axi_host_eff_ctx *)ctx)->host_outcome = -1;
            if (journal)
                (void)axi_effect_journal_finish_effect(journal, attempt, ctx);
            return -1;
        }
        if (axi_replay_peek(ctx->replay, cap, cell, buf, len, rbuf, &rlen,
                            &fuel_used, rdig, &rec_nbytes, &has_rec, &has_str) != 0) {
            if (journal) {
                ((axi_host_eff_ctx *)ctx)->host_outcome = -1;
                (void)axi_effect_journal_finish_effect(journal, attempt, ctx);
            }
            return -1;
        }
        /* Replay must burn the same fuel the original effect burned,
         * including fuel spent by a spawned child. Refuse an invalid budget
         * before ATTEMPTED; subtraction must never wrap into extra authority. */
        if (ctx->fuel_used) {
            if (*ctx->fuel_used > ctx->fuel_budget
                    || fuel_used > ctx->fuel_budget - *ctx->fuel_used) {
                if (ctx->fuel_exhausted) *ctx->fuel_exhausted = 1;
                if (journal) {
                    ((axi_host_eff_ctx *)ctx)->host_outcome = -1;
                    (void)axi_effect_journal_finish_effect(journal, attempt, ctx);
                }
                return -1;
            }
        }
        if (journal && axi_effect_journal_attempt(journal, attempt) != 0)
            return -1;
        ((axi_host_eff_ctx *)ctx)->attempt_state = AXI_EFFECT_ATTEMPTED;
        if (ctx->fuel_used) *ctx->fuel_used += fuel_used;
        if (has_str) {
            if (rlen > (size_t)LONG_MAX) goto replay_failed;
            replay_result = (long)rlen;
            goto replay_done;
        }
        if (rlen == sizeof(uint64_t) && replay_scalar_result(rbuf, &replay_result)) {
            goto replay_done;
        }
replay_failed:
        replay_result = -1;
replay_done:
        if (ctx) {
            ((axi_host_eff_ctx *)ctx)->host_outcome = replay_result;
            ((axi_host_eff_ctx *)ctx)->attempt_state = replay_result >= 0
                ? AXI_EFFECT_COMMITTED : AXI_EFFECT_FAILED;
            if (has_rec) {
                ((axi_host_eff_ctx *)ctx)->record_digest = rdig;
                ((axi_host_eff_ctx *)ctx)->record_nbytes = rec_nbytes;
            } else {
                ((axi_host_eff_ctx *)ctx)->record_digest = NULL;
            }
        }
        if (journal && axi_effect_journal_finish_effect(journal, attempt, ctx) != 0) {
            if (ctx) ((axi_host_eff_ctx *)ctx)->record_digest = NULL;
            return -1;
        }
        if (replay_result < 0) return -1;
        if (axi_replay_commit(ctx->replay) != 0) return -1;
        if (has_str) {
            ((axi_host_eff_ctx *)ctx)->result = rbuf;
            ((axi_host_eff_ctx *)ctx)->result_len = rlen;
            ((axi_host_eff_ctx *)ctx)->has_result = 1;
        }
        return replay_result;
    }

    /* INV-427 / AXI-INV-137: reserve the complete journal transition before
     * touching the host. PREPARED may end FAILED without claiming ATTEMPTED. */
    if (journal && axi_effect_journal_begin(journal, cap, cell, buf, len,
                                             &attempt) != 0) return -1;
    if (!effect_deadline_allows_attempt(ctx, journal, attempt)) return -1;
    if (mode == AXI_REPLAY_RECORD
            && axi_replay_prepare(ctx->replay, len) != 0) {
        if (ctx) ((axi_host_eff_ctx *)ctx)->host_outcome = -1;
        if (journal) (void)axi_effect_journal_finish_effect(journal, attempt, ctx);
        return -1;
    }
    if (journal && axi_effect_journal_attempt(journal, attempt) != 0) return -1;
    if (ctx) ((axi_host_eff_ctx *)ctx)->attempt_state = AXI_EFFECT_ATTEMPTED;
    uint64_t fuel_before = (ctx->fuel_used) ? *ctx->fuel_used : 0;
    long r = real(ctx, buf, len);
    uint64_t fuel_after = (ctx->fuel_used) ? *ctx->fuel_used : fuel_before;
    if (mode == AXI_REPLAY_RECORD && r >= 0) {
        int has_str = ctx->has_result ? 1 : 0;
        if (axi_replay_record(ctx->replay, cap, cell, buf, len,
                              has_str ? ctx->result : &r,
                              has_str ? ctx->result_len : sizeof(r),
                               fuel_after - fuel_before,
                               ctx->record_digest, ctx->record_nbytes,
                               has_str) != 0)
            if (ctx) ((axi_host_eff_ctx *)ctx)->evidence_failed = 1;
    }
    if (ctx) {
        ((axi_host_eff_ctx *)ctx)->host_outcome = r;
        if (r >= 0) ((axi_host_eff_ctx *)ctx)->attempt_state = AXI_EFFECT_COMMITTED;
        else if (ctx->attempt_state != AXI_EFFECT_PARTIAL)
            ((axi_host_eff_ctx *)ctx)->attempt_state = AXI_EFFECT_FAILED;
    }
    if (journal && axi_effect_journal_finish_effect(journal, attempt, ctx) != 0)
        return -1;
    return r;
}

static long axi_eff_write(const axi_host_eff_ctx *ctx, const void *buf, size_t len)
{ return axi_eff_dispatch(ctx, buf, len, "io.Write", axi_host_write); }
static long axi_eff_fs_read(const axi_host_eff_ctx *ctx, const void *buf, size_t len)
{ return axi_eff_dispatch(ctx, buf, len, "fs.Read", axi_host_fs_read); }
static long axi_eff_fs_write(const axi_host_eff_ctx *ctx, const void *buf, size_t len)
{ return axi_eff_dispatch(ctx, buf, len, "fs.Write", axi_host_fs_write); }
static long axi_eff_crypto_hash(const axi_host_eff_ctx *ctx, const void *buf, size_t len)
{ return axi_eff_dispatch(ctx, buf, len, "crypto.Hash", axi_host_crypto_hash); }
static long axi_eff_proc_spawn(const axi_host_eff_ctx *ctx, const void *buf, size_t len)
{ return axi_eff_dispatch(ctx, buf, len, "proc.Spawn", axi_host_proc_spawn); }
static long axi_eff_net_connect(const axi_host_eff_ctx *ctx, const void *buf, size_t len)
{ return axi_eff_dispatch(ctx, buf, len, "net.Connect", axi_host_net_connect); }
static long axi_eff_net_read(const axi_host_eff_ctx *ctx, const void *buf, size_t len)
{ return axi_eff_dispatch(ctx, buf, len, "net.Read", axi_host_net_read); }
static long axi_eff_net_write(const axi_host_eff_ctx *ctx, const void *buf, size_t len)
{ return axi_eff_dispatch(ctx, buf, len, "net.Write", axi_host_net_write); }
static long axi_eff_net_close(const axi_host_eff_ctx *ctx, const void *buf, size_t len)
{ return axi_eff_dispatch(ctx, buf, len, "net.Close", axi_host_net_close); }

/* ---- ledger ------------------------------------------------------------- */
/* h_0 = SHA-256("AXI-LEDGER-v1" || mod_hash): the same seed shape as the W17
 * trace /AXI-INV-032/ — a ledger is evidence ABOUT a module, so the module's
 * identity is inside the seed. Two modules with an identical effect sequence
 * must not produce an identical ledger tip. */
#define LEDGER_SEED "AXI-LEDGER-v1"

void axi_ledger_init(axi_ledger *L, const uint8_t mod_hash[32])
{
    axi_ledger_init_accounted(L, mod_hash, NULL);
}

void axi_ledger_init_accounted(axi_ledger *L, const uint8_t mod_hash[32],
                               axi_mem_account *account)
{
    uint8_t seed[sizeof(LEDGER_SEED) - 1 + 32];
    memcpy(seed, LEDGER_SEED, sizeof(LEDGER_SEED) - 1);
    memcpy(seed + sizeof(LEDGER_SEED) - 1, mod_hash, 32);
    axi_sha256(seed, sizeof seed, L->tip);
    memcpy(L->mod, mod_hash, 32);   /* the receipt states its own root /INV-062/ */
    L->row = NULL; L->n = 0; L->cap = 0; L->oom = 0; L->account = account;
}

void axi_ledger_free(axi_ledger *L)
{
    if (!L) return;
    if (L->row) {
        if (L->account) {
            if (!axi_mem_free(L->account, L->row)) return;
        } else free(L->row);
    }
    L->row = NULL; L->n = L->cap = 0;
}

int axi_ledger_prepare(axi_ledger *L)
{
    size_t bytes;
    if (!L || L->oom) return -1;
    if (L->n > L->cap || (L->cap && !L->row)) {
        L->oom = 1;
        return -1;
    }
    if (L->n == L->cap) {
        uint32_t capacity;
        axi_ledger_row *rows;
        if (L->cap && L->cap > UINT32_MAX / 2) {
            effect_account_size_overflow(L->account);
            L->oom = 1;
            return -1;
        }
        capacity = L->cap ? L->cap * 2 : 8;
        if (effect_array_bytes((size_t)capacity, sizeof *rows, &bytes) != 0) {
            effect_account_size_overflow(L->account);
            L->oom = 1;
            return -1;
        }
        rows = L->account ? axi_mem_realloc(L->account, L->row, bytes)
                          : axi_realloc(L->row, bytes);
        if (!rows) {
            L->oom = 1;
            return -1;
        }
        L->row = rows;
        L->cap = capacity;
    }
    return 0;
}

/* One link: tip' = SHA-256(tip || seq || cap || cell || nbytes || digest).
 * Every field that a reader would use to answer "who did what, in which order,
 * to how much" is inside the hash; a row cannot be edited, reordered, or
 * re-attributed without breaking every later tip /AXI-INV-038/. */
static void row_link(const uint8_t prev[32], const axi_ledger_row *r,
                     uint8_t out[32])
{
    uint8_t b[32 + 8 + AXI_CAPNAME + AXI_CAPNAME + 8 + 32];
    size_t  o = 0;
    memcpy(b + o, prev, 32);                        o += 32;
    for (int i = 0; i < 8; i++) b[o++] = (uint8_t)(r->seq >> (8 * i));
    memset(b + o, 0, AXI_CAPNAME);
    memcpy(b + o, r->cap, strlen(r->cap));          o += AXI_CAPNAME;
    memset(b + o, 0, AXI_CAPNAME);
    memcpy(b + o, r->cell, strlen(r->cell));        o += AXI_CAPNAME;
    for (int i = 0; i < 8; i++) b[o++] = (uint8_t)(r->nbytes >> (8 * i));
    memcpy(b + o, r->digest, 32);                   o += 32;
    axi_sha256(b, o, out);
}

int axi_ledger_append(axi_ledger *L, const char *cap, const char *cell,
                      const void *payload, size_t len)
{
    uint8_t digest[32];
    if ((!payload && len) || !effect_name_ok(cap) || !effect_name_ok(cell))
        return -1;
    axi_sha256(payload, len, digest);
    return axi_ledger_append_digest(L, cap, cell, digest, (uint64_t)len);
}

int axi_ledger_append_digest(axi_ledger *L, const char *cap, const char *cell,
                             const uint8_t digest[32], uint64_t nbytes)
{
    size_t cl = effect_name_len(cap), el = effect_name_len(cell);
    if (!digest || cl == 0 || cl >= AXI_CAPNAME || el == 0 || el >= AXI_CAPNAME)
        return -1;
    if (axi_ledger_prepare(L) != 0) return -1;
    axi_ledger_row *r = &L->row[L->n];
    memset(r, 0, sizeof *r);
    r->seq = (uint64_t)L->n + 1;
    memcpy(r->cap,  cap,  cl);
    memcpy(r->cell, cell, el);
    r->nbytes = nbytes;
    memcpy(r->digest, digest, 32);
    row_link(L->tip, r, r->tip);
    memcpy(L->tip, r->tip, 32);
    L->n++;
    return 0;
}

static void hex32(const uint8_t h[32], char out[65])
{
    static const char *d = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { out[2*i] = d[h[i] >> 4]; out[2*i+1] = d[h[i] & 15]; }
    out[64] = 0;
}

void axi_ledger_tip_hex(const axi_ledger *L, char out[65]) { hex32(L->tip, out); }

void axi_ledger_print(const axi_ledger *L, FILE *out)
{
    char h[65];
    for (uint32_t i = 0; i < L->n; i++) {
        const axi_ledger_row *r = &L->row[i];
        hex32(r->digest, h);
        fprintf(out, "ledger %llu %s %s %llu %.16s\n",
                (unsigned long long)r->seq, r->cap, r->cell,
                (unsigned long long)r->nbytes, h);
    }
    axi_ledger_tip_hex(L, h);
    fprintf(out, "ledger tip %s (%u %s)\n", h, L->n,
            L->n == 1 ? "row" : "rows");
}

static void ledger_json_string(FILE *out, const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    fputc('"', out);
    for (; *p; p++) {
        if (*p == '"' || *p == '\\') {
            fputc('\\', out);
            fputc(*p, out);
        } else if (*p < 0x20 || *p >= 0x7f) {
            fprintf(out, "\\u%04x", (unsigned)*p);
        } else fputc(*p, out);
    }
    fputc('"', out);
}

void axi_ledger_print_json(const axi_ledger *L, FILE *out)
{
    char h[65];
    if (!L || !out || L->n > L->cap || (L->n && !L->row)) return;
    for (uint32_t i = 0; i < L->n; i++)
        if (!memchr(L->row[i].cap, '\0', AXI_CAPNAME)
                || !memchr(L->row[i].cell, '\0', AXI_CAPNAME)) return;
    fputs("{\"ledger\":[", out);
    for (uint32_t i = 0; i < L->n; i++) {
        const axi_ledger_row *r = &L->row[i];
        hex32(r->digest, h);
        fprintf(out, "%s{\"seq\":%llu,\"cap\":", i ? "," : "",
                (unsigned long long)r->seq);
        ledger_json_string(out, r->cap);
        fputs(",\"cell\":", out);
        ledger_json_string(out, r->cell);
        fprintf(out, ",\"bytes\":%llu,\"digest\":\"%s\"}",
                (unsigned long long)r->nbytes, h);
    }
    /* The root goes on the page. Without it a reader can recompute nothing:
     * they would have to be told, out of band, which module this chain hangs
     * from — and "trust me about the first link" is the whole thing we refuse
     * to ask of anyone /AXI-INV-062/. */
    hex32(L->mod, h);
    fprintf(out, "],\"module\":\"%s\"", h);
    axi_ledger_tip_hex(L, h);
    fprintf(out, ",\"tip\":\"%s\",\"rows\":%u}\n", h, L->n);
}

/* ---- host effect table -------------------------------------------------- */
/* The implementations live in the platform layer (axi_platform_*.c). This
 * table is the enumerable contract that `axi caps` prints and the VM checks
 * at runtime. /AXI-INV-036/ */
static const axi_host_eff HOST[] = {
    { "io.Write",    axi_eff_write },
    { "fs.Read",     axi_eff_fs_read },
    { "fs.Write",    axi_eff_fs_write },
    { "crypto.Hash", axi_eff_crypto_hash },
    { "proc.Spawn",  axi_eff_proc_spawn },
    { "net.Connect", axi_eff_net_connect },
    { "net.Read",    axi_eff_net_read },
    { "net.Write",   axi_eff_net_write },
    { "net.Close",   axi_eff_net_close },
};

const axi_host_eff *axi_host_eff_find(const char *name)
{
    for (size_t i = 0; i < sizeof HOST / sizeof HOST[0]; i++)
        if (strcmp(HOST[i].name, name) == 0) return &HOST[i];
    return NULL;   /* unknown effect = refused effect, named in the verdict */
}

size_t axi_host_eff_count(void) { return sizeof HOST / sizeof HOST[0]; }

const axi_host_eff *axi_host_eff_at(size_t i)
{
    return i < axi_host_eff_count() ? &HOST[i] : NULL;
}
