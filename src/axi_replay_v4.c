/* axial - ADR-018 CA16 replay envelope and signed-v7 admission adapter.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * INV-428 / AXI-INV-138: a replay episode is admitted only under its exact
 * execution binding and an explicit recorder trust anchor.  Producer identity
 * never becomes recorder trust, and no refusal publishes partial ownership.
 */
#include "axi_replay_v4.h"

#include "axi_alloc.h"
#include "axi_contract.h"
#include "axi_hash.h"
#include "axi_sign.h"
#include "ed25519.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define V4_BODY_MAX (AXI_REPLAY_V4_MAX_ENCODED - AXI_REPLAY_V4_SIG_TRAILER)

typedef struct {
    uint8_t *p;
    size_t cap;
    size_t off;
    int err;
} v4_writer;

typedef struct {
    const uint8_t *p;
    size_t len;
    size_t off;
    int err;
} v4_reader;

static int bytes_zero(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) if (p[i] != 0) return 0;
    return 1;
}

static int canonical_name(const char name[AXI_CAPNAME])
{
    const char *nul;
    size_t i;
    if (!name) return 0;
    nul = (const char *)memchr(name, '\0', AXI_CAPNAME);
    if (!nul || nul == name) return 0;
    for (i = (size_t)(nul - name) + 1; i < AXI_CAPNAME; i++)
        if (name[i] != '\0') return 0;
    return 1;
}

static int value_verify(uint8_t kind, const uint8_t *bytes, uint32_t len,
                        int argument)
{
    if ((!bytes && len) || len > AXI_REPLAY_V4_MAX_ARG_BYTES) return 0;
    switch (kind) {
    case AXI_REPLAY_V4_KIND_U64:
    case AXI_REPLAY_V4_KIND_I64:
    case AXI_REPLAY_V4_KIND_F64:
        return len == 8;
    case AXI_REPLAY_V4_KIND_BOOL:
    case AXI_REPLAY_V4_KIND_DECISION:
        return len == 1 && bytes[0] <= 1;
    case AXI_REPLAY_V4_KIND_STR:
    case AXI_REPLAY_V4_KIND_BYTES:
    case AXI_REPLAY_V4_KIND_JSON:
        return 1;
    case AXI_REPLAY_V4_KIND_OK:
        return !argument && len == 0;
    case AXI_REPLAY_V4_KIND_ERR:
        return !argument;
    case AXI_REPLAY_V4_KIND_CAP:
    default:
        return 0;
    }
}

int axi_replay_v4_binding_verify(const axi_replay_v4_binding *binding)
{
    uint32_t i;
    if (!binding || !canonical_name(binding->cell_name)
            || binding->operator_budget == 0
            || binding->nargs > AXI_REPLAY_V4_MAX_ARGS
            || binding->ngrants > AXI_REPLAY_V4_MAX_GRANTS) return 1;
    for (i = 0; i < binding->nargs; i++) {
        const axi_replay_v4_arg *arg = &binding->args[i];
        if (!value_verify(arg->kind, arg->bytes, arg->len, 1)) return 1;
    }
    for (i = 0; i < binding->ngrants; i++) {
        if (!canonical_name(binding->grants[i])) return 1;
        if (i && strcmp(binding->grants[i - 1], binding->grants[i]) >= 0)
            return 1;
    }
    return 0;
}

int axi_replay_v4_terminal_verify(const axi_replay_v4_terminal *terminal)
{
    if (!terminal || terminal->output_len > AXI_REPLAY_V4_MAX_TERMINAL
            || !value_verify(terminal->output_kind, terminal->output,
                             terminal->output_len, 0)
            || (terminal->output_tag != AXI_REPLAY_V4_TAG_NONE
                && terminal->output_tag >= AXI_REPLAY_V4_MAX_ARGS)
            || (terminal->journal_state != AXI_REPLAY_V4_JOURNAL_PARTIAL
                && terminal->journal_state != AXI_REPLAY_V4_JOURNAL_COMMITTED
                && terminal->journal_state != AXI_REPLAY_V4_JOURNAL_FAILED))
        return 1;
    return 0;
}

static int binding_equal(const axi_replay_v4_binding *a,
                         const axi_replay_v4_binding *b)
{
    uint32_t i;
    if (memcmp(a->body_root, b->body_root, 32) != 0
            || memcmp(a->producer_pk, b->producer_pk, 32) != 0
            || a->cell_index != b->cell_index
            || memcmp(a->cell_name, b->cell_name, AXI_CAPNAME) != 0
            || memcmp(a->iface_hash, b->iface_hash, 32) != 0
            || memcmp(a->cell_body_hash, b->cell_body_hash, 32) != 0
            || a->operator_budget != b->operator_budget
            || a->nargs != b->nargs || a->ngrants != b->ngrants) return 0;
    for (i = 0; i < a->nargs; i++) {
        if (a->args[i].kind != b->args[i].kind
                || a->args[i].len != b->args[i].len
                || memcmp(a->args[i].bytes, b->args[i].bytes,
                          a->args[i].len) != 0) return 0;
    }
    for (i = 0; i < a->ngrants; i++)
        if (memcmp(a->grants[i], b->grants[i], AXI_CAPNAME) != 0) return 0;
    return 1;
}

static void put_be32(uint8_t out[4], uint32_t v)
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)v;
}

static void put_be64(uint8_t out[8], uint64_t v)
{
    unsigned i;
    for (i = 0; i < 8; i++) out[i] = (uint8_t)(v >> (56 - 8 * i));
}

static uint32_t get_be32(const uint8_t in[4])
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
         | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static uint64_t get_be64(const uint8_t in[8])
{
    uint64_t v = 0;
    unsigned i;
    for (i = 0; i < 8; i++) v = (v << 8) | in[i];
    return v;
}

static void wr_bytes(v4_writer *w, const void *src, size_t len)
{
    if (w->err || len > w->cap - w->off) { w->err = 1; return; }
    if (len) memcpy(w->p + w->off, src, len);
    w->off += len;
}

static void wr_u8(v4_writer *w, uint8_t v)
{
    wr_bytes(w, &v, 1);
}

static void wr_u32(v4_writer *w, uint32_t v)
{
    uint8_t b[4];
    put_be32(b, v);
    wr_bytes(w, b, sizeof b);
}

static void wr_u64(v4_writer *w, uint64_t v)
{
    uint8_t b[8];
    put_be64(b, v);
    wr_bytes(w, b, sizeof b);
}

static const uint8_t *rd_bytes(v4_reader *r, size_t len)
{
    const uint8_t *p;
    if (r->err || len > r->len - r->off) { r->err = 1; return NULL; }
    p = r->p + r->off;
    r->off += len;
    return p;
}

static uint8_t rd_u8(v4_reader *r)
{
    const uint8_t *p = rd_bytes(r, 1);
    return p ? p[0] : 0;
}

static uint32_t rd_u32(v4_reader *r)
{
    const uint8_t *p = rd_bytes(r, 4);
    return p ? get_be32(p) : 0;
}

static uint64_t rd_u64(v4_reader *r)
{
    const uint8_t *p = rd_bytes(r, 8);
    return p ? get_be64(p) : 0;
}

static int size_add(size_t *n, size_t add)
{
    if (add > V4_BODY_MAX - *n) return 0;
    *n += add;
    return 1;
}

static int scalar_from_record(const axi_replay_entry *rec, int64_t *out)
{
    uint64_t raw = 0;
    uint32_t i;
    if (rec->result_len != sizeof(uint64_t)) return 0;
    for (i = 0; i < sizeof(uint64_t); i++)
        raw = (raw << 8) | rec->result[i];
    *out = (int64_t)raw;
    return 1;
}

static int record_verify(const axi_replay_entry *rec,
                         axi_mem_account *account)
{
    uint8_t digest[32];
    int64_t scalar;
    if (!rec || !canonical_name(rec->cap) || !canonical_name(rec->cell)
            || rec->payload_len > sizeof rec->payload
            || rec->result_len > sizeof rec->result
            || rec->nbytes != (uint64_t)rec->payload_len
            || rec->has_record_digest > 1 || rec->has_result_str > 1)
        return 0;
    if (!rec->has_record_digest
            && (!bytes_zero(rec->record_digest, 32) || rec->record_nbytes != 0))
        return 0;
    axi_sha256(rec->payload, rec->payload_len, digest);
    if (memcmp(digest, rec->digest, 32) != 0) return 0;
    if (rec->has_result_str || rec->result_len)
        axi_sha256(rec->result, rec->result_len, digest);
    else memset(digest, 0, sizeof digest);
    if (memcmp(digest, rec->result_digest, 32) != 0) return 0;
    if (!rec->has_result_str && !scalar_from_record(rec, &scalar)) return 0;
    if (!axi_replay_entry_digest_accounted(rec, digest, account)) return 0;
    return memcmp(digest, rec->entry_digest, 32) == 0;
}

static int episode_parts_verify(const axi_replay_v4_binding *binding,
                                const axi_replay *effects,
                                const axi_replay_v4_terminal *terminal,
                                axi_mem_account *account)
{
    size_t i;
    uint64_t effect_fuel = 0;
    if (axi_replay_v4_binding_verify(binding) != 0
            || axi_replay_v4_terminal_verify(terminal) != 0 || !effects
            || effects->n > AXI_REPLAY_V4_MAX_EFFECTS
            || effects->n > effects->cap || effects->cursor > effects->n
            || (effects->n && !effects->records) || effects->oom
            || memcmp(effects->mod_hash, binding->body_root, 32) != 0
            || terminal->total_fuel > binding->operator_budget) return 0;
    for (i = 0; i < effects->n; i++) {
        if (!record_verify(&effects->records[i], account)
                || effects->records[i].fuel_used > UINT64_MAX - effect_fuel)
            return 0;
        effect_fuel += effects->records[i].fuel_used;
    }
    return effect_fuel <= terminal->total_fuel;
}

static int record_wire_size(const axi_replay_entry *rec, size_t *n)
{
    size_t result_wire = rec->has_result_str ? 4 + rec->result_len : 8;
    return size_add(n, 8 + 32 + AXI_CAPNAME + AXI_CAPNAME + 8 + 32 + 32
                       + 8 + 1 + 32 + 8 + 1 + 4)
        && size_add(n, rec->payload_len)
        && size_add(n, result_wire)
        && size_add(n, 32 + 32);
}

static int body_wire_size(const axi_replay_v4_binding *binding,
                          const axi_replay *effects,
                          const axi_replay_v4_terminal *terminal,
                          size_t *out)
{
    uint32_t i;
    size_t n = 0;
    if (!size_add(&n, 4 + 4 + 32 + 32 + 4 + AXI_CAPNAME + 32 + 32 + 8 + 4))
        return 0;
    for (i = 0; i < binding->nargs; i++)
        if (!size_add(&n, 1 + 4)
                || !size_add(&n, binding->args[i].len)) return 0;
    if (!size_add(&n, 4)
            || !size_add(&n, (size_t)binding->ngrants * AXI_CAPNAME)
            || !size_add(&n, 4)) return 0;
    for (i = 0; i < effects->n; i++)
        if (!record_wire_size(&effects->records[i], &n)) return 0;
    if (!size_add(&n, 1 + 4 + 4)
            || !size_add(&n, terminal->output_len)
            || !size_add(&n, 8 + 32 + 32 + 32 + 1)) return 0;
    *out = n;
    return 1;
}

static void transcript_digest(const uint8_t *entry, size_t len, uint8_t out[32])
{
    uint8_t inner[32];
    uint8_t message[sizeof("AXI-REPLAY-v4-ENTRY") + 32];
    axi_sha256(entry, len, inner);
    memcpy(message, "AXI-REPLAY-v4-ENTRY", sizeof("AXI-REPLAY-v4-ENTRY"));
    memcpy(message + sizeof("AXI-REPLAY-v4-ENTRY"), inner, sizeof inner);
    axi_sha256(message, sizeof message, out);
}

static void recorder_message(const uint8_t *body, size_t body_len,
                             uint8_t out[sizeof(AXI_REPLAY_V4_RECORDER_DOMAIN) + 32])
{
    memcpy(out, AXI_REPLAY_V4_RECORDER_DOMAIN,
           sizeof(AXI_REPLAY_V4_RECORDER_DOMAIN));
    axi_sha256(body, body_len,
               out + sizeof(AXI_REPLAY_V4_RECORDER_DOMAIN));
}

static void secure_zero(void *p, size_t len)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (len--) *v++ = 0;
}

typedef struct {
    axi_mem_failure_cause failure;
    size_t failed_request;
    axi_mem_failure_cause denied_failure;
    size_t denied_request;
} v4_mem_failure;

static v4_mem_failure v4_mem_failure_save(const axi_mem_account *account)
{
    v4_mem_failure saved;
    saved.failure = account ? account->failure : AXI_MEM_FAILURE_NONE;
    saved.failed_request = account ? account->failed_request : 0;
    saved.denied_failure = account ? account->denied_failure
                                   : AXI_MEM_FAILURE_NONE;
    saved.denied_request = account ? account->denied_request : 0;
    return saved;
}

static void v4_mem_failure_restore(axi_mem_account *account,
                                   const v4_mem_failure *saved)
{
    if (!account || !saved || saved->failure == AXI_MEM_FAILURE_NONE) return;
    account->failure = saved->failure;
    account->failed_request = saved->failed_request;
    account->denied_failure = saved->denied_failure;
    account->denied_request = saved->denied_request;
}

static int v4_scratch_reserve(axi_mem_account *account, size_t bytes,
                              int *reserved)
{
    *reserved = 0;
    if (!account) return 1;
    if (!axi_mem_reserve(account, bytes)) return 0;
    *reserved = 1;
    return 1;
}

static int v4_scratch_release(axi_mem_account *account, size_t bytes,
                              int *reserved)
{
    v4_mem_failure saved;
    int released;
    if (!*reserved) return 1;
    saved = v4_mem_failure_save(account);
    released = axi_mem_release(account, bytes);
    if (released) {
        *reserved = 0;
        v4_mem_failure_restore(account, &saved);
    }
    return released;
}

static void v4_episode_free_preserving_failure(axi_replay_v4_episode *episode,
                                                axi_mem_account *account)
{
    v4_mem_failure saved = v4_mem_failure_save(account);
    axi_replay_v4_episode_free(episode);
    v4_mem_failure_restore(account, &saved);
}

static int v4_buffer_release_preserving_failure(axi_mem_account *account,
                                                uint8_t *buffer)
{
    v4_mem_failure saved = v4_mem_failure_save(account);
    int released = axi_replay_v4_buffer_release(account, buffer);
    if (released) v4_mem_failure_restore(account, &saved);
    return released;
}

void axi_replay_v4_episode_init(axi_replay_v4_episode *episode)
{
    axi_replay_v4_episode_init_accounted(episode, NULL);
}

void axi_replay_v4_episode_init_accounted(axi_replay_v4_episode *episode,
                                          axi_mem_account *account)
{
    if (!episode) return;
    memset(episode, 0, sizeof *episode);
    axi_replay_init_accounted(&episode->effects, NULL, account);
}

void axi_replay_v4_episode_free(axi_replay_v4_episode *episode)
{
    axi_mem_account *account;
    if (!episode) return;
    account = episode->effects.account;
    axi_replay_free(&episode->effects);
    if (episode->effects.records) return;
    memset(episode, 0, sizeof *episode);
    axi_replay_init_accounted(&episode->effects, NULL, account);
}

int axi_replay_v4_encode_signed(const axi_replay_v4_binding *binding,
                                const axi_replay *effects,
                                const axi_replay_v4_terminal *terminal,
                                const uint8_t recorder_seed[32],
                                uint8_t **out, size_t *out_len)
{
    return axi_replay_v4_encode_signed_accounted(
        binding, effects, terminal, recorder_seed, NULL, out, out_len);
}

int axi_replay_v4_buffer_release(axi_mem_account *account, uint8_t *buffer)
{
    if (!buffer) return 1;
    if (account) return axi_mem_free(account, buffer);
    free(buffer);
    return 1;
}

int axi_replay_v4_encode_signed_accounted(
    const axi_replay_v4_binding *binding,
    const axi_replay *effects,
    const axi_replay_v4_terminal *terminal,
    const uint8_t recorder_seed[32],
    axi_mem_account *account,
    uint8_t **out, size_t *out_len)
{
    uint8_t *framed = NULL;
    uint8_t pk[ED25519_PUBKEY], sk[ED25519_SECKEY], sig[ED25519_SIG];
    uint8_t message[sizeof(AXI_REPLAY_V4_RECORDER_DOMAIN) + 32];
    uint8_t previous[32] = {0};
    size_t body_len, framed_len, i;
    v4_writer w;
    int crypto_reserved = 0;
    int rc = 1;
    if (!binding || !effects || !terminal || !recorder_seed || !out || !out_len
            || !episode_parts_verify(binding, effects, terminal, account)
            || !body_wire_size(binding, effects, terminal, &body_len)
            || body_len > V4_BODY_MAX) return 1;
    framed_len = body_len + AXI_REPLAY_V4_SIG_TRAILER;
    ed25519_keypair_from_seed(recorder_seed, pk, sk);
    if (memcmp(pk, binding->producer_pk, 32) == 0) goto done;
    framed = account
        ? (uint8_t *)axi_mem_alloc(account, framed_len)
        : (uint8_t *)axi_malloc(framed_len);
    if (!framed) goto done;
    w.p = framed; w.cap = body_len; w.off = 0; w.err = 0;
    wr_bytes(&w, AXI_REPLAY_V4_BODY_MAGIC, AXI_REPLAY_V4_BODY_MAGIC_BYTES);
    wr_u32(&w, AXI_REPLAY_V4_VERSION);
    wr_bytes(&w, binding->body_root, 32);
    wr_bytes(&w, binding->producer_pk, 32);
    wr_u32(&w, binding->cell_index);
    wr_bytes(&w, binding->cell_name, AXI_CAPNAME);
    wr_bytes(&w, binding->iface_hash, 32);
    wr_bytes(&w, binding->cell_body_hash, 32);
    wr_u64(&w, binding->operator_budget);
    wr_u32(&w, binding->nargs);
    for (i = 0; i < binding->nargs; i++) {
        wr_u8(&w, binding->args[i].kind);
        wr_u32(&w, binding->args[i].len);
        wr_bytes(&w, binding->args[i].bytes, binding->args[i].len);
    }
    wr_u32(&w, binding->ngrants);
    for (i = 0; i < binding->ngrants; i++)
        wr_bytes(&w, binding->grants[i], AXI_CAPNAME);
    wr_u32(&w, (uint32_t)effects->n);
    for (i = 0; i < effects->n; i++) {
        const axi_replay_entry *rec = &effects->records[i];
        uint8_t linked[32];
        size_t entry_start = w.off;
        wr_u64(&w, (uint64_t)i + 1);
        wr_bytes(&w, previous, 32);
        wr_bytes(&w, rec->cap, AXI_CAPNAME);
        wr_bytes(&w, rec->cell, AXI_CAPNAME);
        wr_u64(&w, rec->nbytes);
        wr_bytes(&w, rec->digest, 32);
        wr_bytes(&w, rec->result_digest, 32);
        wr_u64(&w, rec->fuel_used);
        wr_u8(&w, rec->has_record_digest);
        wr_bytes(&w, rec->record_digest, 32);
        wr_u64(&w, rec->record_nbytes);
        wr_u8(&w, rec->has_result_str ? AXI_REPLAY_V4_RESULT_BYTES
                                      : AXI_REPLAY_V4_RESULT_SCALAR_I64);
        wr_u32(&w, (uint32_t)rec->payload_len);
        wr_bytes(&w, rec->payload, rec->payload_len);
        if (rec->has_result_str) {
            wr_u32(&w, (uint32_t)rec->result_len);
            wr_bytes(&w, rec->result, rec->result_len);
        } else {
            int64_t scalar;
            if (!scalar_from_record(rec, &scalar)) { w.err = 1; break; }
            wr_u64(&w, (uint64_t)scalar);
        }
        wr_bytes(&w, rec->entry_digest, 32);
        if (w.err) break;
        transcript_digest(framed + entry_start, w.off - entry_start, linked);
        wr_bytes(&w, linked, 32);
        memcpy(previous, linked, 32);
    }
    wr_u8(&w, terminal->output_kind);
    wr_u32(&w, terminal->output_tag);
    wr_u32(&w, terminal->output_len);
    wr_bytes(&w, terminal->output, terminal->output_len);
    wr_u64(&w, terminal->total_fuel);
    wr_bytes(&w, terminal->trace_root, 32);
    wr_bytes(&w, terminal->ledger_tip, 32);
    wr_bytes(&w, terminal->journal_tip, 32);
    wr_u8(&w, terminal->journal_state);
    if (w.err || w.off != body_len) goto done;
    recorder_message(framed, body_len, message);
    if (!v4_scratch_reserve(account, AXI_ED25519_MESSAGE_SCRATCH_BYTES,
                            &crypto_reserved)) goto done;
    if (ed25519_sign(sig, message, (uint32_t)sizeof message, sk) != 0) goto done;
    if (!v4_scratch_release(account, AXI_ED25519_MESSAGE_SCRATCH_BYTES,
                            &crypto_reserved)) goto done;
    memcpy(framed + body_len, AXI_REPLAY_V4_SIG_MAGIC, 4);
    put_be32(framed + body_len + 4, AXI_REPLAY_V4_SIG_VERSION);
    memcpy(framed + body_len + 8, pk, 32);
    memcpy(framed + body_len + 40, sig, 64);
    *out = framed;
    *out_len = framed_len;
    framed = NULL;
    rc = 0;
done:
    if (!v4_scratch_release(account, AXI_ED25519_MESSAGE_SCRATCH_BYTES,
                            &crypto_reserved)) rc = 1;
    secure_zero(sk, sizeof sk);
    secure_zero(sig, sizeof sig);
    if (!v4_buffer_release_preserving_failure(account, framed)) rc = 1;
    return rc;
}

static int parse_binding(v4_reader *r, axi_replay_v4_binding *binding)
{
    const uint8_t *p;
    uint32_t i;
    memset(binding, 0, sizeof *binding);
#define V4_READ_FIXED(dst, len) do { \
    p = rd_bytes(r, (len)); \
    if (!p) return 0; \
    memcpy((dst), p, (len)); \
} while (0)
    V4_READ_FIXED(binding->body_root, 32);
    V4_READ_FIXED(binding->producer_pk, 32);
    binding->cell_index = rd_u32(r);
    V4_READ_FIXED(binding->cell_name, AXI_CAPNAME);
    V4_READ_FIXED(binding->iface_hash, 32);
    V4_READ_FIXED(binding->cell_body_hash, 32);
    binding->operator_budget = rd_u64(r);
    binding->nargs = rd_u32(r);
    if (r->err || binding->nargs > AXI_REPLAY_V4_MAX_ARGS) return 0;
    for (i = 0; i < binding->nargs; i++) {
        binding->args[i].kind = rd_u8(r);
        binding->args[i].len = rd_u32(r);
        if (r->err || binding->args[i].len > AXI_REPLAY_V4_MAX_ARG_BYTES)
            return 0;
        V4_READ_FIXED(binding->args[i].bytes, binding->args[i].len);
    }
    binding->ngrants = rd_u32(r);
    if (r->err || binding->ngrants > AXI_REPLAY_V4_MAX_GRANTS) return 0;
    for (i = 0; i < binding->ngrants; i++)
        V4_READ_FIXED(binding->grants[i], AXI_CAPNAME);
#undef V4_READ_FIXED
    return axi_replay_v4_binding_verify(binding) == 0;
}

static int parse_record(v4_reader *r, axi_replay_entry *rec, uint64_t want_seq,
                        const uint8_t previous[32], uint8_t linked[32],
                        axi_mem_account *account)
{
    const uint8_t *p;
    uint8_t result_kind;
    size_t entry_start = r->off;
    uint64_t seq = rd_u64(r);
    memset(rec, 0, sizeof *rec);
    p = rd_bytes(r, 32);
    if (!p || seq != want_seq || memcmp(p, previous, 32) != 0) return 0;
#define V4_REC_FIXED(dst, len) do { \
    p = rd_bytes(r, (len)); \
    if (!p) return 0; \
    memcpy((dst), p, (len)); \
} while (0)
    V4_REC_FIXED(rec->cap, AXI_CAPNAME);
    V4_REC_FIXED(rec->cell, AXI_CAPNAME);
    rec->nbytes = rd_u64(r);
    V4_REC_FIXED(rec->digest, 32);
    V4_REC_FIXED(rec->result_digest, 32);
    rec->fuel_used = rd_u64(r);
    rec->has_record_digest = rd_u8(r);
    V4_REC_FIXED(rec->record_digest, 32);
    rec->record_nbytes = rd_u64(r);
    result_kind = rd_u8(r);
    rec->payload_len = rd_u32(r);
    if (r->err || rec->payload_len > sizeof rec->payload) return 0;
    V4_REC_FIXED(rec->payload, rec->payload_len);
    if (result_kind == AXI_REPLAY_V4_RESULT_BYTES) {
        rec->has_result_str = 1;
        rec->result_len = rd_u32(r);
        if (r->err || rec->result_len > sizeof rec->result) return 0;
        V4_REC_FIXED(rec->result, rec->result_len);
    } else if (result_kind == AXI_REPLAY_V4_RESULT_SCALAR_I64) {
        uint64_t bits = rd_u64(r);
        unsigned i;
        if (r->err) return 0;
        rec->has_result_str = 0;
        rec->result_len = sizeof bits;
        for (i = 0; i < sizeof bits; i++)
            rec->result[i] = (uint8_t)(bits >> (56 - 8 * i));
    } else return 0;
    V4_REC_FIXED(rec->entry_digest, 32);
#undef V4_REC_FIXED
    if (!record_verify(rec, account)) return 0;
    transcript_digest(r->p + entry_start, r->off - entry_start, linked);
    p = rd_bytes(r, 32);
    if (!p || memcmp(p, linked, 32) != 0) return 0;
    return 1;
}

static int parse_terminal(v4_reader *r, axi_replay_v4_terminal *terminal)
{
    const uint8_t *p;
    memset(terminal, 0, sizeof *terminal);
    terminal->output_kind = rd_u8(r);
    terminal->output_tag = rd_u32(r);
    terminal->output_len = rd_u32(r);
    if (r->err || terminal->output_len > AXI_REPLAY_V4_MAX_TERMINAL) return 0;
    p = rd_bytes(r, terminal->output_len);
    if (!p) return 0;
    if (terminal->output_len)
        memcpy(terminal->output, p, terminal->output_len);
    terminal->total_fuel = rd_u64(r);
    p = rd_bytes(r, 32); if (!p) return 0;
    memcpy(terminal->trace_root, p, 32);
    p = rd_bytes(r, 32); if (!p) return 0;
    memcpy(terminal->ledger_tip, p, 32);
    p = rd_bytes(r, 32); if (!p) return 0;
    memcpy(terminal->journal_tip, p, 32);
    terminal->journal_state = rd_u8(r);
    return !r->err && axi_replay_v4_terminal_verify(terminal) == 0;
}

int axi_replay_v4_decode_trusted(axi_replay_v4_episode *out,
                                 const uint8_t *bytes, size_t len,
                                 const axi_replay_v4_binding *expected,
                                 const uint8_t recorder_pk[32])
{
    return axi_replay_v4_decode_trusted_accounted(
        out, bytes, len, expected, recorder_pk, NULL);
}

int axi_replay_v4_decode_trusted_accounted(
    axi_replay_v4_episode *out,
    const uint8_t *bytes, size_t len,
    const axi_replay_v4_binding *expected,
    const uint8_t recorder_pk[32],
    axi_mem_account *account)
{
    axi_replay_v4_episode episode;
    const uint8_t *trailer;
    uint8_t message[sizeof(AXI_REPLAY_V4_RECORDER_DOMAIN) + 32];
    uint8_t previous[32] = {0};
    size_t body_len, i;
    uint32_t count;
    uint64_t effect_fuel = 0;
    v4_reader r;
    int episode_initialized = 0;
    int episode_reserved = 0;
    int crypto_reserved = 0;
    int rc = 1;
    if (!out || !bytes || !expected || !recorder_pk
            || axi_replay_v4_binding_verify(expected) != 0
            || len > AXI_REPLAY_V4_MAX_ENCODED
            || len < AXI_REPLAY_V4_SIG_TRAILER + 8) return 1;
    if (!v4_scratch_reserve(account, sizeof episode, &episode_reserved))
        return 1;
    body_len = len - AXI_REPLAY_V4_SIG_TRAILER;
    trailer = bytes + body_len;
    /* Authentication precedes even reading the body magic. */
    if (memcmp(trailer, AXI_REPLAY_V4_SIG_MAGIC, 4) != 0
            || get_be32(trailer + 4) != AXI_REPLAY_V4_SIG_VERSION
            || memcmp(trailer + 8, recorder_pk, 32) != 0
            || memcmp(recorder_pk, expected->producer_pk, 32) == 0) goto done;
    recorder_message(bytes, body_len, message);
    if (!v4_scratch_reserve(account, AXI_ED25519_MESSAGE_SCRATCH_BYTES,
                            &crypto_reserved)) goto done;
    if (ed25519_verify(trailer + 40, message, (uint32_t)sizeof message,
                       recorder_pk) != 0) goto done;
    if (!v4_scratch_release(account, AXI_ED25519_MESSAGE_SCRATCH_BYTES,
                            &crypto_reserved)) goto done;

    axi_replay_v4_episode_init_accounted(&episode, account);
    episode_initialized = 1;
    r.p = bytes; r.len = body_len; r.off = 0; r.err = 0;
    {
        const uint8_t *magic = rd_bytes(&r, AXI_REPLAY_V4_BODY_MAGIC_BYTES);
        uint32_t version = rd_u32(&r);
        if (!magic || memcmp(magic, AXI_REPLAY_V4_BODY_MAGIC,
                             AXI_REPLAY_V4_BODY_MAGIC_BYTES) != 0
                || version != AXI_REPLAY_V4_VERSION
                || !parse_binding(&r, &episode.binding)
                || !binding_equal(&episode.binding, expected)) goto bad;
    }
    count = rd_u32(&r);
    if (r.err || count > AXI_REPLAY_V4_MAX_EFFECTS
            || (size_t)count > (r.len - r.off) / 365u
            || (count && sizeof(axi_replay_entry) > (size_t)-1 / count))
        goto bad;
    if (count) {
        episode.effects.records = episode.effects.account
            ? (axi_replay_entry *)axi_mem_calloc(
                episode.effects.account, count,
                sizeof *episode.effects.records)
            : (axi_replay_entry *)axi_calloc(
                count, sizeof *episode.effects.records);
        if (!episode.effects.records) goto bad;
    }
    episode.effects.cap = count;
    memcpy(episode.effects.mod_hash, episode.binding.body_root, 32);
    episode.effects.mode = AXI_REPLAY_REPLAY;
    for (i = 0; i < count; i++) {
        uint8_t linked[32];
        if (!parse_record(&r, &episode.effects.records[i], (uint64_t)i + 1,
                           previous, linked, account)
                || episode.effects.records[i].fuel_used
                    > UINT64_MAX - effect_fuel) goto bad;
        effect_fuel += episode.effects.records[i].fuel_used;
        memcpy(previous, linked, 32);
        episode.effects.n = i + 1;
    }
    if (!parse_terminal(&r, &episode.terminal) || r.off != r.len
            || episode.terminal.total_fuel > episode.binding.operator_budget
            || effect_fuel > episode.terminal.total_fuel) goto bad;
    memcpy(episode.recorder_pk, recorder_pk, 32);
    *out = episode;
    episode_initialized = 0;
    rc = 0;
    goto done;
bad:
    v4_episode_free_preserving_failure(&episode, account);
    episode_initialized = 0;
done:
    if (episode_initialized)
        v4_episode_free_preserving_failure(&episode, account);
    if (!v4_scratch_release(account, AXI_ED25519_MESSAGE_SCRATCH_BYTES,
                            &crypto_reserved)) rc = 1;
    if (!v4_scratch_release(account, sizeof episode, &episode_reserved))
        rc = 1;
    return rc;
}

typedef struct {
    uint32_t nreturns;
    uint8_t returns[AXB_MANIFEST_MAX_RETURNS];
    uint32_t nerrors;
    uint8_t error_len[AXB_MANIFEST_MAX_ERRORS];
    uint8_t errors[AXB_MANIFEST_MAX_ERRORS][AXI_REPLAY_V4_ERR_ATOM_MAX];
} v4_result_contract;
typedef char v4_result_contract_size_probe[
    sizeof(v4_result_contract) == AXI_REPLAY_V4_RESULT_CONTRACT_LOCAL_BYTES
        ? 1 : -1];

static int binding_from_admitted_v7(
    axi_replay_v4_binding *out,
    const axb_contract_mod *model,
    const uint8_t producer_pk[32],
    const axi_replay_v4_invocation *invocation,
    v4_result_contract *result_contract,
    axi_mem_account *account)
{
    axi_replay_v4_binding binding;
    const axb_cell *cell;
    const axb_manifest *manifest;
    size_t name_len;
    uint32_t i;
    int binding_reserved = 0;
    int rc = 1;
    if (!out || !model || !producer_pk || !invocation
            || invocation->nargs > AXI_REPLAY_V4_MAX_ARGS
            || invocation->ngrants > AXI_REPLAY_V4_MAX_GRANTS
            || model->body.has_sig != 1 || model->body.body_len < 8
            || model->body.body_len > AXB_CONTRACT_MAX_BYTES
            || memcmp(model->body.sig_pk, producer_pk, 32) != 0
            || !model->body.cells || !model->manifest
            || model->body.n == 0 || model->body.n > 256
            || model->nmanifest != model->body.n
            || invocation->cell_index >= model->body.n) return 1;
    if (!v4_scratch_reserve(account, sizeof binding, &binding_reserved))
        return 1;
    memset(&binding, 0, sizeof binding);
    cell = &model->body.cells[invocation->cell_index];
    manifest = &model->manifest[invocation->cell_index];
    if (!cell->name || manifest->nparams > AXB_MANIFEST_MAX_PARAMS
            || manifest->nreturns > AXB_MANIFEST_MAX_RETURNS
            || manifest->nerrors > AXB_MANIFEST_MAX_ERRORS
            || invocation->nargs != manifest->nparams) goto done;
    for (i = 0; i < invocation->nargs; i++)
        if (invocation->args[i].kind != manifest->params[i].type.tag)
            goto done;
    name_len = strlen(cell->name);
    if (name_len == 0 || name_len >= AXI_CAPNAME) goto done;
    memcpy(binding.body_root, model->body.root, 32);
    memcpy(binding.producer_pk, producer_pk, 32);
    binding.cell_index = invocation->cell_index;
    memcpy(binding.cell_name, cell->name, name_len);
    memcpy(binding.iface_hash, manifest->iface_hash, 32);
    memcpy(binding.cell_body_hash, manifest->body_hash, 32);
    binding.operator_budget = invocation->operator_budget;
    binding.nargs = invocation->nargs;
    for (i = 0; i < invocation->nargs; i++) {
        binding.args[i].kind = invocation->args[i].kind;
        binding.args[i].len = invocation->args[i].len;
        if (binding.args[i].len > AXI_REPLAY_V4_MAX_ARG_BYTES) goto done;
        memcpy(binding.args[i].bytes, invocation->args[i].bytes,
               binding.args[i].len);
    }
    binding.ngrants = invocation->ngrants;
    for (i = 0; i < invocation->ngrants; i++)
        memcpy(binding.grants[i], invocation->grants[i], AXI_CAPNAME);
    if (axi_replay_v4_binding_verify(&binding) != 0) goto done;
    if (result_contract) {
        result_contract->nreturns = manifest->nreturns;
        result_contract->nerrors = manifest->nerrors;
        for (i = 0; i < manifest->nreturns; i++)
            result_contract->returns[i] = manifest->returns[i].tag;
        for (i = 0; i < manifest->nerrors; i++) {
            if (manifest->errors[i].len == 0
                    || manifest->errors[i].len > AXI_REPLAY_V4_ERR_ATOM_MAX
                    || !manifest->errors[i].p) goto done;
            result_contract->error_len[i] =
                (uint8_t)manifest->errors[i].len;
            memcpy(result_contract->errors[i], manifest->errors[i].p,
                   manifest->errors[i].len);
        }
    }
    *out = binding;
    rc = 0;
done:
    if (!v4_scratch_release(account, sizeof binding, &binding_reserved))
        rc = 1;
    return rc;
}

static int binding_from_signed_v7(
    axi_replay_v4_binding *out,
    const uint8_t *artifact, size_t artifact_len,
    const uint8_t producer_pk[32],
    const axi_replay_v4_invocation *invocation,
    v4_result_contract *result_contract)
{
    axb_contract_mod model;
    int rc;
    if (!out || !artifact || !producer_pk || !invocation
            || artifact_len < AXBS_TRAILER + 8) return 1;
    memset(&model, 0, sizeof model);
    if (axb_contract_v7_decode_trusted(&model, artifact, artifact_len,
                                       producer_pk) != 0) return 1;
    rc = binding_from_admitted_v7(out, &model, producer_pk, invocation,
                                   result_contract, NULL);
    axb_contract_mod_free(&model);
    return rc;
}

int axi_replay_v4_binding_from_signed_v7(
    axi_replay_v4_binding *out,
    const uint8_t *artifact, size_t artifact_len,
    const uint8_t producer_pk[32],
    const axi_replay_v4_invocation *invocation)
{
    return binding_from_signed_v7(out, artifact, artifact_len, producer_pk,
                                  invocation, NULL);
}

int axi_replay_v4_binding_from_admitted_v7(
    axi_replay_v4_binding *out,
    const axb_contract_mod *model,
    const uint8_t producer_pk[32],
    const axi_replay_v4_invocation *invocation)
{
    return axi_replay_v4_binding_from_admitted_v7_accounted(
        out, model, producer_pk, invocation, NULL);
}

int axi_replay_v4_binding_from_admitted_v7_accounted(
    axi_replay_v4_binding *out,
    const axb_contract_mod *model,
    const uint8_t producer_pk[32],
    const axi_replay_v4_invocation *invocation,
    axi_mem_account *account)
{
    return binding_from_admitted_v7(out, model, producer_pk, invocation, NULL,
                                    account);
}

static int terminal_matches_contract(const axi_replay_v4_terminal *terminal,
                                     const v4_result_contract *contract)
{
    /* INV-428: an ERR is the signed atom plus exact framing, never a prefix. */
    if (terminal->output_kind == AXI_REPLAY_V4_KIND_ERR) {
        uint32_t atom_len, payload_len, i;
        size_t payload_off;
        int declared = 0;
        if (terminal->output_tag != AXI_REPLAY_V4_TAG_NONE
                || terminal->output_len < AXI_REPLAY_V4_ERR_FRAME_FIXED)
            return 0;
        atom_len = get_be32(terminal->output);
        if (atom_len == 0 || atom_len > AXI_REPLAY_V4_ERR_ATOM_MAX
                || atom_len > terminal->output_len
                    - AXI_REPLAY_V4_ERR_FRAME_FIXED) return 0;
        payload_off = 4u + atom_len;
        payload_len = get_be32(terminal->output + payload_off);
        if (payload_len != terminal->output_len - payload_off - 4u) return 0;
        for (i = 0; i < contract->nerrors; i++)
            if (contract->error_len[i] == atom_len
                    && memcmp(contract->errors[i], terminal->output + 4,
                              atom_len) == 0) {
                declared = 1;
                break;
            }
        return declared;
    }
    if (contract->nreturns == 1)
        return terminal->output_tag == AXI_REPLAY_V4_TAG_NONE
            && terminal->output_kind == contract->returns[0];
    return contract->nreturns > 1
        && terminal->output_tag < contract->nreturns
        && terminal->output_kind == contract->returns[terminal->output_tag];
}

static int decode_admitted_v7_trusted(
    axi_replay_v4_episode *out,
    const uint8_t *bytes, size_t len,
    const axb_contract_mod *model,
    const uint8_t producer_pk[32],
    const axi_replay_v4_invocation *invocation,
    const uint8_t recorder_pk[32],
    axi_mem_account *account)
{
    axi_replay_v4_binding expected;
    axi_replay_v4_episode episode;
    v4_result_contract contract;
    int expected_reserved = 0;
    int episode_reserved = 0;
    int contract_reserved = 0;
    int episode_initialized = 0;
    int rc = 1;
    if (!out || !bytes || !recorder_pk) return 1;
    if (!v4_scratch_reserve(account, sizeof expected, &expected_reserved)
            || !v4_scratch_reserve(account, sizeof episode,
                                   &episode_reserved)
            || !v4_scratch_reserve(account, sizeof contract,
                                   &contract_reserved)) goto done;
    if (binding_from_admitted_v7(&expected, model, producer_pk,
                                  invocation, &contract, account) != 0)
        goto done;
    axi_replay_v4_episode_init_accounted(&episode, account);
    episode_initialized = 1;
    if (axi_replay_v4_decode_trusted_accounted(
            &episode, bytes, len, &expected, recorder_pk, account) != 0
            || !terminal_matches_contract(&episode.terminal, &contract)) {
        v4_episode_free_preserving_failure(&episode, account);
        episode_initialized = 0;
        goto done;
    }
    *out = episode;
    episode_initialized = 0;
    rc = 0;
done:
    if (episode_initialized)
        v4_episode_free_preserving_failure(&episode, account);
    if (!v4_scratch_release(account, sizeof contract, &contract_reserved))
        rc = 1;
    if (!v4_scratch_release(account, sizeof episode, &episode_reserved))
        rc = 1;
    if (!v4_scratch_release(account, sizeof expected, &expected_reserved))
        rc = 1;
    return rc;
}

int axi_replay_v4_decode_admitted_v7_trusted(
    axi_replay_v4_episode *out,
    const uint8_t *bytes, size_t len,
    const axb_contract_mod *model,
    const uint8_t producer_pk[32],
    const axi_replay_v4_invocation *invocation,
    const uint8_t recorder_pk[32])
{
    return decode_admitted_v7_trusted(out, bytes, len, model, producer_pk,
                                       invocation, recorder_pk, NULL);
}

int axi_replay_v4_decode_admitted_v7_trusted_accounted(
    axi_replay_v4_episode *out,
    const uint8_t *bytes, size_t len,
    const axb_contract_mod *model,
    const uint8_t producer_pk[32],
    const axi_replay_v4_invocation *invocation,
    const uint8_t recorder_pk[32],
    axi_mem_account *account)
{
    return decode_admitted_v7_trusted(out, bytes, len, model, producer_pk,
                                       invocation, recorder_pk, account);
}

int axi_replay_v4_decode_signed_v7_trusted(
    axi_replay_v4_episode *out,
    const uint8_t *bytes, size_t len,
    const uint8_t *artifact, size_t artifact_len,
    const uint8_t producer_pk[32],
    const axi_replay_v4_invocation *invocation,
    const uint8_t recorder_pk[32])
{
    axb_contract_mod model;
    int rc;
    if (!artifact || !producer_pk || artifact_len < AXBS_TRAILER + 8) return 1;
    memset(&model, 0, sizeof model);
    if (axb_contract_v7_decode_trusted(&model, artifact, artifact_len,
                                       producer_pk) != 0) return 1;
    rc = decode_admitted_v7_trusted(out, bytes, len, &model, producer_pk,
                                     invocation, recorder_pk, NULL);
    axb_contract_mod_free(&model);
    return rc;
}
