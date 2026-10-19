/* axial — the effect plane (W19). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * Until this file the VM was pure: it computed, it burned fuel, it returned a
 * value. Nothing left the process. W19 opens the first door to the world — and
 * a door is where every interpreter in this language's family gave its
 * authority away for free.
 *
 * Lua hands you `io.write` in the default environment; Python hands you `open`.
 * The authority to touch the world is AMBIENT: any line of any module has it,
 * so a reviewer cannot answer "what can this artifact do?" by reading it — only
 * by reading everything it can reach, forever, including what it loads at
 * runtime. Sandboxing then becomes subtraction (remove `io` from _ENV, audit
 * every hole), and subtraction from an infinite surface never terminates.
 *
 * axial inverts it: an effect is not reachable, it is GRANTED, and it happens
 * exactly once in a record. Four rules, each of them a gate:
 *
 *  1. TWO KEYS /AXI-INV-036/. The artifact DECLARES the authority it wants
 *     (`.eff io.Write`, in the text, therefore inside src_hash — W14), and the
 *     operator GRANTS it at invocation (`--cap io.Write`). Neither key alone
 *     opens the door. A declaration without a grant is a program asking; a
 *     grant without a declaration is an operator offering something the
 *     artifact never asked for, and a flight recorder must not record
 *     authority that the artifact did not request in writing.
 *
 *  2. THE VM IS THE LAST DOOR /AXI-INV-037/. The checker (W07) already
 *     refuses an undeclared cap in a signature — but bytecode can be
 *     hand-assembled, and W21 will sign it. A gate that lives only in the
 *     front end is a gate that a `.axs` file walks around. The refusal is
 *     therefore re-derived at the instant of the effect, from the module and
 *     the grant set, with the checker's verdict as a courtesy, not the
 *     enforcement.
 *
 *  3. ONE EFFECT, ONE ROW /AXI-INV-038/. Every effect that HAPPENS appends
 *     exactly one ledger row, in order, chained. Not a log line — a row in a
 *     hash chain whose seed binds the module (same shape as W17's trace, same
 *     SHA-256 door as the Beyond boot chain). "N effects ⇔ N cells" is the
 *     CARTÓRIO thesis (ADR-0091) and W22 will hammer it; here it is born.
 *
 *  4. THE LEDGER RECORDS WHAT HAPPENED /AXI-INV-039/. The separate effect
 *     journal records honest attempts and their terminal state.
 *     Fuel is charged and the two keys are checked BEFORE the world is
 *     touched; the row is appended only AFTER the host call reports success.
 *     A refused effect and a failed effect both leave the ledger untouched and
 *     both are verdicts. A ledger that says "wrote" when nothing was written
 *     is the one lie that destroys the instrument's reason to exist.
 *
 * The payload is recorded as a DIGEST, never as bytes (/AXI-INV-040/): the
 * record must stay bounded while remaining exact about the bytes that left.
 */
#ifndef AXI_EFFECT_H
#define AXI_EFFECT_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "axi_bc.h"
#include "axi_mem_account.h"
#include "axi_replay.h"
#include "axi_resource_envelope.h"

#define AXI_CAP_MAX   32     /* grants per invocation */
#ifndef AXI_CAPNAME
#define AXI_CAPNAME   64
#endif

struct axi_host_eff_ctx;

/* ---- the grant set: what the OPERATOR authorised (`--cap NAME`) ---------- */
typedef struct {
    char  name[AXI_CAP_MAX][AXI_CAPNAME];
    int   n;
} axi_grants;

void axi_grants_init(axi_grants *g);
/* 0 = ok, -1 = full, -2 = name too long/empty, -3 = duplicate (a grant given
 * twice is an operator who lost track of what they authorised: refuse). */
int  axi_grants_add(axi_grants *g, const char *name);
int  axi_grants_has(const axi_grants *g, const char *name);
int  axi_grants_verify(const axi_grants *g);
int  axi_grants_cap_slot(const axi_grants *g, const char *name,
                         uint32_t *slot);
int  axi_grants_cap_matches(const axi_grants *g, uint32_t slot,
                            const char *atom,
                            uint32_t atom_len);

/* ---- the ledger: one row per effect that happened ----------------------- */
typedef struct {
    uint64_t seq;              /* 1-based position in this invocation      */
    char     cap[AXI_CAPNAME]; /* the authority exercised                  */
    char     cell[AXI_CAPNAME];/* WHO exercised it (attribution)           */
    uint64_t nbytes;           /* how much crossed the door                */
    uint8_t  digest[32];       /* SHA-256 of the exact bytes /INV-040/     */
    uint8_t  tip[32];          /* chain tip AFTER this row                 */
} axi_ledger_row;

typedef struct {
    axi_ledger_row *row;
    uint32_t        n, cap;
    uint8_t         tip[32];   /* h_0 = SHA-256("AXI-LEDGER-v1" || mod_hash) */
    uint8_t         mod[32];   /* the root, kept so the receipt can carry it:
                                  a chain whose first link is off-page cannot
                                  be checked by anyone but us /AXI-INV-062/  */
    int             oom;       /* fail-closed: an unrecordable effect is a
                                  refused effect, never a silent one */
    axi_mem_account *account;  /* optional, caller-owned allocation account */
} axi_ledger;

/* ---- effect journal: honest partial effects ----------------------------- */
#define AXI_JOURNAL_PREPARED  1u
#define AXI_JOURNAL_ATTEMPTED 2u
#define AXI_JOURNAL_PARTIAL   3u
#define AXI_JOURNAL_COMMITTED 4u
#define AXI_JOURNAL_FAILED    5u

#define AXI_EFFECT_NOT_ATTEMPTED 0u
#define AXI_EFFECT_ATTEMPTED     1u
#define AXI_EFFECT_COMMITTED     2u
#define AXI_EFFECT_PARTIAL       3u
#define AXI_EFFECT_FAILED        4u
#define AXI_EFFECT_HOST_FAILED AXI_EFFECT_FAILED

typedef struct {
    uint64_t seq;
    uint64_t attempt;
    uint8_t state;
    char cap[AXI_CAPNAME];
    char cell[AXI_CAPNAME];
    uint64_t nbytes;
    uint8_t digest[32];
    int64_t outcome;
    uint64_t actual_nbytes;
    uint8_t actual_digest[32];
    uint8_t resource_identity[32];
    uint8_t has_actual;
    uint8_t has_resource_identity;
    uint8_t evidence_failed;
    uint8_t tip[32];
} axi_effect_journal_row;

typedef struct {
    axi_effect_journal_row *row;
    uint32_t n, cap;
    uint64_t next_attempt;
    uint64_t open_attempt;
    uint8_t open_state;
    uint8_t tip[32];
    uint8_t mod[32];
    int oom;
    axi_mem_account *account;  /* optional, caller-owned allocation account */
} axi_effect_journal;

void axi_effect_journal_init(axi_effect_journal *J,
                             const uint8_t mod_hash[32]);
/* The account must outlive the journal. NULL preserves the legacy path. */
void axi_effect_journal_init_accounted(axi_effect_journal *J,
                                       const uint8_t mod_hash[32],
                                       axi_mem_account *account);
void axi_effect_journal_free(axi_effect_journal *J);
int axi_effect_journal_begin(axi_effect_journal *J, const char *cap,
                             const char *cell, const void *payload, size_t len,
                             uint64_t *attempt_out);
int axi_effect_journal_attempt(axi_effect_journal *J, uint64_t attempt);
int axi_effect_journal_finish(axi_effect_journal *J, uint64_t attempt,
                               int committed, int64_t outcome);
int axi_effect_journal_finish_effect(axi_effect_journal *J, uint64_t attempt,
                                     const struct axi_host_eff_ctx *ctx);
int axi_effect_journal_verify(const axi_effect_journal *J);
/* Canonical, injection-safe evidence. Returns nonzero on invalid journal or
 * output failure. */
int axi_effect_journal_fprint(const axi_effect_journal *J, FILE *out);

void axi_ledger_init(axi_ledger *L, const uint8_t mod_hash[32]);
/* The account must outlive the ledger. NULL preserves the legacy path. */
void axi_ledger_init_accounted(axi_ledger *L, const uint8_t mod_hash[32],
                               axi_mem_account *account);
void axi_ledger_free(axi_ledger *L);
/* Reserve the next row before an irreversible host effect. */
int  axi_ledger_prepare(axi_ledger *L);
/* Append one row. Returns 0 on success, -1 if the row could not be recorded
 * (caller MUST then refuse the effect: rule 3 has no exception for OOM). */
int  axi_ledger_append(axi_ledger *L, const char *cap, const char *cell,
                       const void *payload, size_t len);
/* Same, but the digest and byte count are supplied by the host effect
 * (net.Read/Write need the ledger to record the digest of the bytes that
 * crossed the wire, not of the handle syntax used to name the connection). */
int  axi_ledger_append_digest(axi_ledger *L, const char *cap, const char *cell,
                              const uint8_t digest[32], uint64_t nbytes);
void axi_ledger_tip_hex(const axi_ledger *L, char out[65]);
void axi_ledger_print(const axi_ledger *L, FILE *out);        /* human rows */
void axi_ledger_print_json(const axi_ledger *L, FILE *out);   /* agent rows */

/* ---- the host effect table --------------------------------------------- */
/* A host effect is a C function the VM may reach ONLY through this table.
 * The context carries everything the effect needs to be accountable:
 * who authorised it, where to file the receipt, and how much fuel is left.
 * `write` returns bytes written; `fs.Read` returns bytes read; `proc.Spawn`
 * returns the child's exit code. A return < 0 is a host failure (rule 4). */
typedef struct axi_host_eff_ctx {
    void             *sink;           /* the world's handle (FILE* for io.Write) */
    const axi_grants *grants;         /* what the OPERATOR authorised            */
    axi_ledger       *led;            /* where every effect is filed             */
    axi_effect_journal *journal;      /* PREPARED/ATTEMPTED/terminal evidence     */
    const axb_mod    *m;              /* the module that is running              */
    const char       *mod_path;       /* path to the .axb (needed by proc.Spawn) */
    const char       *trusted_key_path; /* explicit trust inherited by children */
    uint64_t          fuel_budget;    /* the parent's remaining budget           */
    uint64_t         *fuel_used;      /* the parent's ledger — effects add here  */
    int              *fuel_exhausted; /* set by the host if a child died on fuel */
    /* Result channel: effects that return bytes (fs.Read, crypto.Hash, net.Read)
     * fill this; the VM wraps it in a VK_STR. Effects that return a count
     * (io.Write, fs.Write, proc.Spawn, net.Connect, net.Write) leave it NULL. */
    const void       *result;
    size_t            result_len;
    uint8_t           has_result;
    /* Ledger control: if set, OP_EFF uses this digest instead of SHA-256(payload).
     * record_nbytes is the byte count that crossed the wire. */
    const uint8_t    *record_digest;
    uint8_t           record_digest_storage[32];
    uint64_t            record_nbytes;
    const uint8_t    *resource_identity;
    uint8_t           resource_identity_storage[32];
    /* Replay context: when recording, the effect plane captures every I/O;
     * when replaying, host effects become deterministic mocks. NULL = off. */
    axi_replay       *replay;
    const char       *cell_name;      /* the cell that invoked the effect        */
    /* Optional invocation owner. Legacy/embed callers leave this NULL. */
    axi_mem_account  *account;
    axi_resource_envelope *resources;
    uint8_t           attempt_state;
    int64_t           host_outcome;
    int               evidence_failed;
} axi_host_eff_ctx;

typedef struct {
    const char *name;
    long (*fn)(const axi_host_eff_ctx *ctx, const void *buf, size_t len);
} axi_host_eff;

const axi_host_eff *axi_host_eff_find(const char *name);

/* The table, enumerable. A diagnostic that says "ask the tool what it can do"
 * is a lie unless the tool can answer, so `axi caps` reads this. /AXI-INV-036/
 *
 * The implementations live in the platform layer (axi_platform_*.c), never
 * here. This table is the contract; the platform is the mechanism.
 * AXI-LAW-11: host effects are shims; the sovereign Beyond build replaces
 * them with Single Door syscalls. */
const axi_host_eff *axi_host_eff_at(size_t i);
size_t              axi_host_eff_count(void);

/* Internal CA21 manifest probe. Returns the exact invocation-used automatic
 * scratch charge for a platform effect, or zero for process-owned/no scratch. */
int axi_host_eff_scratch_bytes(const char *name, size_t *bytes);

#endif /* AXI_EFFECT_H */
