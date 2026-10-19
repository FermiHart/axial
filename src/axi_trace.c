/* axial — determinism trace (W17 / AXI-P1). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 * Doctrine and the three invariants it enforces: see axi_trace.h.
 */
#include "axi_trace.h"
#include "axi_alloc.h"
#include "axi_hash.h"
#include <stdlib.h>
#include <string.h>

#define TRACE_SEED "AXI-TRACE-v1"

/* Records are big-endian on purpose: the same cell must hash the same on the
 * host that builds axial and on the Beyond target that will run it (W23/W25).
 * A memcpy of a native integer would make the trace hash a property of the
 * MACHINE instead of the execution. /AXI-INV-031/ */

static void overflow(axi_trace *t) {
    if (t->owner)
        (void)axi_mem_realloc(t->owner, t->rec, (size_t)-1);
    t->oom = 1;
}

static void grow(axi_trace *t, size_t need) {
    size_t required, ncap, total;
    uint8_t *n;
    if (t->oom) return;
    if (need > (size_t)-1 - t->cur) { overflow(t); return; }
    required = t->cur + need;
    if (required <= t->cap) return;
    if (t->sealed) { t->oom = 1; return; } /* INV-505 / AXI-INV-155 */
    ncap = t->cap ? t->cap : 256;
    while (ncap < required) {
        if (ncap > (size_t)-1 / 2) { ncap = required; break; }
        ncap *= 2;
    }
    if (ncap > (size_t)-1 - 32) { overflow(t); return; }
    total = 32 + ncap;
    n = t->owner
        ? (uint8_t *)axi_mem_realloc(t->owner, t->rec, total)
        : (uint8_t *)axi_realloc(t->rec, total);
    if (!n) { t->oom = 1; return; }       /* fail-closed: see axi_trace_hex */
    t->rec = n; t->cap = ncap;
}

static void emit(axi_trace *t, const void *b, size_t n) {
    grow(t, n);
    if (t->oom) return;
    memcpy(t->rec + 32 + t->cur, b, n);
    t->cur += n;
}

static void be32(axi_trace *t, uint32_t v) {
    uint8_t b[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16),
                     (uint8_t)(v >> 8),  (uint8_t)v };
    emit(t, b, 4);
}

static void be64(axi_trace *t, uint64_t v) {
    uint8_t b[8];
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (56 - 8 * i));
    emit(t, b, 8);
}

/* h_0 = SHA-256("AXI-TRACE-v1" || mod_hash). The artifact's identity enters
 * the chain ONCE, at the root: every later link therefore speaks about this
 * module and no other. A constant seed made the tip say only "this
 * instruction stream ran somewhere". /AXI-INV-032/ */
void axi_trace_init(axi_trace *t, const uint8_t mod_hash[32]) {
    axi_trace_init_accounted(t, mod_hash, NULL);
}

void axi_trace_init_accounted(axi_trace *t, const uint8_t mod_hash[32],
                               axi_mem_account *account) {
    memset(t, 0, sizeof *t);
    t->owner = account;
    uint8_t seed[sizeof TRACE_SEED - 1 + 32];
    memcpy(seed, TRACE_SEED, sizeof TRACE_SEED - 1);
    memcpy(seed + sizeof TRACE_SEED - 1, mod_hash, 32);
    axi_sha256(seed, sizeof seed, t->h);
}

int axi_trace_prepare(axi_trace *t, size_t payload_capacity) {
    if (!t || t->sealed || t->oom) return 0;
    grow(t, payload_capacity);
    if (t->oom || t->cap < payload_capacity) return 0;
    t->sealed = 1;
    return 1;
}

void axi_trace_free(axi_trace *t) {
    if (t->owner) {
        if (t->rec && !axi_mem_free(t->owner, t->rec)) return;
    } else {
        free(t->rec);
    }
    t->rec = NULL; t->cap = 0; t->cur = 0; t->sealed = 0;
}

void axi_trace_step_begin(axi_trace *t, uint32_t cell, uint32_t pc,
                          uint8_t op, uint64_t fuel, uint32_t nregs) {
    t->cur = 0;
    be32(t, cell);
    be32(t, pc);
    emit(t, &op, 1);
    be64(t, fuel);
    be32(t, nregs);
}

void axi_trace_val(axi_trace *t, uint8_t kind, uint8_t aux, uint8_t pay_kind,
                   uint64_t bits, const char *s, uint32_t slen) {
    emit(t, &kind, 1);
    emit(t, &aux, 1);
    /* INV-322 / AXI-INV-104: the payload kind is part of the evidence — two
     * unions with the same tag and different payload kinds seal differently. */
    emit(t, &pay_kind, 1);
    be64(t, bits);
    /* strings by length + bytes: the pointer is not part of the meaning */
    be32(t, s ? slen : 0);
    if (s && slen) emit(t, s, slen);
}

/* One link: h = SHA-256(h || record). The previous hash goes FIRST so the
 * chain cannot be re-ordered or truncated without changing the tip. */
static void link_record(axi_trace *t) {
    if (t->oom) return;
    memcpy(t->rec, t->h, 32);
    axi_sha256(t->rec, 32 + t->cur, t->h);
    t->cur = 0;
}

void axi_trace_step_end(axi_trace *t) {
    link_record(t);
    t->steps++;
}

void axi_trace_verdict(axi_trace *t, const char *code) {
    t->cur = 0;
    be32(t, 0xFFFFFFFFu);          /* verdict tag: not a pc */
    emit(t, code, strlen(code));
    link_record(t);
}

void axi_trace_hex(const axi_trace *t, char out[65]) {
    /* A trace that could not be built must not be presentable as a witness:
     * an all-zero hash is refused by the caller instead of passing for one. */
    if (t->oom) { memset(out, '0', 64); out[64] = 0; return; }
    axi_hash_hex(t->h, out);
}
