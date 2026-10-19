/* axial — determinism trace (W17 / AXI-P1). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * AXI-P1 claims: the same cell on the same inputs runs the same way twice.
 * A claim needs a witness, and the witness is a HASH CHAIN over the machine
 * state history:
 *
 *     h_0     = SHA-256("AXI-TRACE-v1")
 *     h_{n+1} = SHA-256(h_n || record_n)
 *
 * Three properties this shape buys, each of them a bug this house refuses:
 *
 *  - ORDER lives in the shape /AXI-INV-029/. Swap two steps and every later
 *    link changes. A commutative fold (xor/sum of per-step hashes) would call
 *    two different executions identical: it witnesses a MULTISET of steps,
 *    not a history. That is not determinism, it is bookkeeping.
 *
 *  - NO HOST ADDRESS enters the chain /AXI-INV-030/. Values are fed as a
 *    canonical projection (kind, then payload; strings by length + bytes).
 *    Hashing a runtime value struct wholesale would feed its borrowed
 *    `const char *` into the chain: two runs of one cell would disagree for
 *    no semantic reason (ASLR), and P1 would be unprovable. Hence the API
 *    takes projected scalars and never a value pointer.
 *
 *  - ONE HASH DOOR. The chain is built from axi_sha256, the same SHA-256
 *    that seals the Beyond boot chain. A streaming primitive of its own
 *    would be a second door /INV-199 spirit/, so the chain uses the one-shot
 *    door once per link — the boot chain's own shape.
 *
 *  - THE PROGRAM IS IN THE SEED /AXI-INV-032/. h_0 binds the module's
 *    src_hash (W14), so the witness answers "module M ran this way", not the
 *    weaker "some program ran this way". With a constant seed, two modules
 *    that merely share an instruction stream sealed IDENTICAL traces — a
 *    trace could then be presented as evidence about an artifact it never
 *    touched, which is the one thing a flight recorder may not do.
 *
 * The trace is a witness, not a log: it is written to no file and costs
 * nothing when off (`--trace` opts in).
 */
#ifndef AXI_TRACE_H
#define AXI_TRACE_H

#include "axi_mem_account.h"
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t  h[32];
    uint64_t steps;
    uint8_t *rec;      /* previous hash prefix + record scratch */
    size_t   cap;      /* payload capacity; allocation is 32 + cap */
    size_t   cur;      /* record cursor; no file-static state in this door */
    int      oom;      /* fail-closed: a trace that could not be built lies */
    int      sealed;   /* prepared scratch cannot allocate during dispatch */
    axi_mem_account *owner; /* optional; caller-owned and explicit */
} axi_trace;

/* mod_hash: the module's src_hash (W14). Binding the artifact's identity into
 * h_0 is what makes the tip evidence ABOUT a module /AXI-INV-032/. */
void axi_trace_init(axi_trace *t, const uint8_t mod_hash[32]);
/* The account must outlive the trace. NULL selects the legacy unaccounted
 * allocation path used by axi_trace_init. */
void axi_trace_init_accounted(axi_trace *t, const uint8_t mod_hash[32],
                               axi_mem_account *account);
/* Reserve the complete record scratch before execution and prohibit later
 * growth. Returns zero without sealing when the reservation fails. */
int axi_trace_prepare(axi_trace *t, size_t payload_capacity);
void axi_trace_free(axi_trace *t);

/* One link per executed instruction. The register window enters as a
 * projection built by the caller through axi_trace_val, never as memory. */
void axi_trace_step_begin(axi_trace *t, uint32_t cell, uint32_t pc,
                          uint8_t op, uint64_t fuel, uint32_t nregs);
void axi_trace_val(axi_trace *t, uint8_t kind, uint8_t aux, uint8_t pay_kind,
                   uint64_t bits, const char *s, uint32_t slen);
void axi_trace_step_end(axi_trace *t);

/* The verdict is a link too: a deterministic failure is still a determinism
 * claim, so a trap belongs in the witness (this is what lets AXI-P2 lean on
 * the same chain in W18). */
void axi_trace_verdict(axi_trace *t, const char *code);

void axi_trace_hex(const axi_trace *t, char out[65]);

#endif /* AXI_TRACE_H */
