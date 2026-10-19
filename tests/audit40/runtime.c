/* Audit40 runtime regressions. SPDX-License-Identifier: LicenseRef-SPL-1.0 */
#include "axi_vm.h"
#include "axi_replay.h"
#include "axi_json.h"
#include "axi_platform.h"
#include "axi_hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned checks, failures;

#define CHECK(condition) do { \
    checks++; \
    if (!(condition)) { \
        fprintf(stderr, "runtime:%d: %s\n", __LINE__, #condition); \
        failures++; \
    } \
} while (0)

static uint32_t instruction(uint8_t op, uint8_t a, uint8_t b, uint8_t c)
{
    return (uint32_t)op | (uint32_t)a << 8 | (uint32_t)b << 16
        | (uint32_t)c << 24;
}

static int run(const uint32_t *code, uint32_t count, uint32_t nregs,
                const axi_vval *args, uint8_t argc,
                axi_vval *out, uint64_t budget, uint64_t *used)
{
    axb_cell cell;
    axb_mod module;
    axi_diags diags;
    memset(&module, 0, sizeof module);
    memset(&cell, 0, sizeof cell);
    memset(&diags, 0, sizeof diags);
    cell.name = "audit";
    cell.nregs = nregs;
    cell.code = (uint32_t *)code;
    cell.nc = count;
    module.cells = &cell;
    module.n = 1;
    return axi_vm_run_cell_diag(&module, 0, args, argc, out, budget, used,
                                NULL, NULL, &diags);
}

static uint64_t fbits(double value)
{
    uint64_t bits;
    memcpy(&bits, &value, sizeof bits);
    return bits;
}

static void arithmetic_aliases(void)
{
    static const uint8_t ops[] = {OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD};
    static const uint64_t integer_expected[] = {10, 4, 21, 2, 1};
    static const double float_expected[] = {10.0, 5.0, 18.75, 3.0};
    for (unsigned kind = 0; kind < 3; kind++) {
        for (unsigned op = 0; op < (kind == 2 ? 4u : 5u); op++) {
            for (uint8_t destination = 0; destination < 3; destination++) {
                axi_vval args[2], out;
                uint64_t used = 0;
                uint32_t code[2] = {
                    instruction(ops[op], destination, 0, 1),
                    instruction(OP_RET, destination, 0, 0)
                };
                memset(args, 0, sizeof args);
                memset(&out, 0, sizeof out);
                args[0].kind = args[1].kind = kind == 0 ? VB_U64
                    : kind == 1 ? VB_I64 : VB_F64;
                args[0].bits = kind == 2 ? fbits(7.5) : 7;
                args[1].bits = kind == 2 ? fbits(2.5) : 3;
                CHECK(run(code, 2, 3, args, 2, &out, 100, &used));
                CHECK(out.kind == args[0].kind);
                CHECK(out.bits == (kind == 2 ? fbits(float_expected[op])
                                             : integer_expected[op]));
                CHECK(used == (uint64_t)axb_op_info(ops[op])->fuel + 1);
            }
        }
    }
    /* Signed wrap and a failing right-alias division retain their verdict. */
    {
        axi_vval args[2], out;
        uint64_t used;
        uint32_t code[] = {instruction(OP_DIV, 1, 0, 1),
                           instruction(OP_RET, 1, 0, 0)};
        memset(args, 0, sizeof args);
        memset(&out, 0, sizeof out);
        args[0].kind = args[1].kind = VB_I64;
        args[0].bits = UINT64_C(1) << 63;
        args[1].bits = UINT64_MAX;
        CHECK(run(code, 2, 2, args, 2, &out, 100, &used));
        CHECK(out.bits == args[0].bits);
        out.bits = 99;
        args[1].bits = 0;
        CHECK(!run(code, 2, 2, args, 2, &out, 100, &used));
        CHECK(out.bits == 99 && used == 4);
        args[1].bits = 3;
        CHECK(!run(code, 2, 2, args, 2, &out, 3, &used));
        CHECK(out.bits == 99 && used == 0);
    }
}

static void union_aliases(void)
{
    static const axi_vkind kinds[] = {
        VB_UNIT, VB_U64, VB_I64, VB_F64, VB_BOOL, VB_STR, VB_BYTES, VB_ERR
    };
    for (unsigned k = 0; k < sizeof kinds / sizeof kinds[0]; k++) {
        axi_vval args[2], out;
        uint64_t used;
        memset(args, 0, sizeof args);
        args[0].kind = VB_U64;
        args[0].bits = 7;
        args[1].kind = kinds[k];
        args[1].bits = kinds[k] == VB_BOOL ? 1 : 42;
        args[1].s = "payload";
        args[1].slen = 7;
        if (kinds[k] == VB_ERR) {
            args[1].atom = "Denied";
            args[1].atom_len = 6;
        }
        for (uint8_t destination = 0; destination < 3; destination++) {
            uint32_t code[] = {instruction(OP_UMAKE, destination, 0, 1),
                               instruction(OP_RET, destination, 0, 0)};
            memset(&out, 0, sizeof out);
            CHECK(run(code, 2, 3, args, 2, &out, 100, &used));
            CHECK(out.kind == VB_UNION && out.tag == 7);
            CHECK(out.payload_kind == kinds[k] && out.bits == args[1].bits);
            CHECK(out.slen == args[1].slen && out.s == args[1].s);
            CHECK(out.atom_len == args[1].atom_len && out.atom == args[1].atom);
            CHECK(used == 2);
        }
        args[0] = args[1];
        args[0].kind = VB_UNION;
        args[0].payload_kind = kinds[k];
        args[0].tag = 0;
        for (unsigned op = 0; op < 3; op++) {
            uint8_t opcode = op == 0 ? OP_UTAG : op == 1 ? OP_UPAY : OP_UCHK;
            for (uint8_t destination = 0; destination < 2; destination++) {
                uint32_t code[] = {instruction(opcode, destination, 0, 0),
                                   instruction(OP_RET, destination, 0, 0)};
                memset(&out, 0, sizeof out);
                CHECK(run(code, 2, 2, args, 1, &out, 100, &used));
                if (opcode == OP_UTAG) {
                    CHECK(out.kind == VB_U64 && out.bits == 0);
                    args[0].tag = 7;
                    CHECK(run(code, 2, 2, args, 1, &out, 100, &used));
                    CHECK(out.kind == VB_U64 && out.bits == 7);
                    args[0].tag = 0;
                } else {
                    CHECK(out.kind == kinds[k] && out.bits == args[1].bits);
                    CHECK(out.slen == args[1].slen && out.s == args[1].s);
                    CHECK(out.atom_len == args[1].atom_len && out.atom == args[1].atom);
                }
                CHECK(used == (uint64_t)axb_op_info(opcode)->fuel + 1);
            }
        }
    }
    /* A nonzero arm propagates its union; it must not become an unwrapped OK. */
    {
        axi_vval arg, out;
        uint64_t used;
        uint32_t code[] = {instruction(OP_UCHK, 0, 0, 0),
                           instruction(OP_HALT, 0, 0, 0)};
        memset(&arg, 0, sizeof arg);
        arg.kind = VB_UNION; arg.tag = 3; arg.payload_kind = VB_U64; arg.bits = 91;
        CHECK(run(code, 2, 1, &arg, 1, &out, 100, &used));
        CHECK(out.kind == VB_UNION && out.tag == 3 && out.bits == 91 && used == 2);
    }
}

static void equal_pair(const axi_vval *left, const axi_vval *right, int expected)
{
    axi_vval args[2] = {*left, *right}, out;
    uint64_t used;
    for (uint8_t destination = 0; destination < 3; destination++) {
        uint32_t code[] = {instruction(OP_EQ, destination, 0, 1),
                           instruction(OP_RET, destination, 0, 0)};
        CHECK(run(code, 2, 3, args, 2, &out, 100, &used));
        CHECK(out.kind == VB_BOOL && out.bits == (uint64_t)expected && used == 2);
    }
}

static void typed_equality(void)
{
    axi_vval left, right;
    memset(&left, 0, sizeof left);
    left.kind = VB_UNION; left.payload_kind = VB_STR; left.tag = 1;
    left.s = "allow"; left.slen = 5;
    right = left; right.s = "deny!";
    equal_pair(&left, &right, 0);
    right.s = "allow";
    equal_pair(&left, &right, 1);
    right.tag = 0;
    equal_pair(&left, &right, 0);
    right = left; right.payload_kind = VB_BYTES;
    equal_pair(&left, &right, 0);
    left.payload_kind = VB_U64; left.bits = 1;
    right = left; right.payload_kind = VB_BOOL;
    equal_pair(&left, &right, 0);
    right.payload_kind = VB_I64;
    equal_pair(&left, &right, 0);
    left.payload_kind = VB_F64; left.bits = fbits(0.0);
    right = left; right.bits = fbits(-0.0);
    equal_pair(&left, &right, 1);
    left.bits = right.bits = UINT64_C(0x7ff8000000000000);
    equal_pair(&left, &right, 0);
    left.payload_kind = VB_ERR; left.atom = "Denied"; left.atom_len = 6;
    left.s = "one"; left.slen = 3;
    right = left; right.atom = "Failed";
    equal_pair(&left, &right, 0);
    right = left; right.s = "two";
    equal_pair(&left, &right, 0);
    right = left;
    equal_pair(&left, &right, 1);
    left.kind = right.kind = VB_ERR; right.s = "two";
    equal_pair(&left, &right, 0);
    right.s = left.s;
    equal_pair(&left, &right, 1);
    left.s = right.s = NULL; left.slen = right.slen = 0;
    equal_pair(&left, &right, 1);
    left.kind = right.kind = VB_F64;
    left.bits = fbits(0.0); right.bits = fbits(-0.0);
    equal_pair(&left, &right, 1);
    left.bits = right.bits = UINT64_C(0x7ff8000000000000);
    equal_pair(&left, &right, 0);
}

typedef struct {
    uint8_t bytes[8192];
    size_t len, cursor;
} replay_buffer;

static size_t replay_write(const void *bytes, size_t len, void *opaque)
{
    replay_buffer *buffer = opaque;
    if (len > sizeof buffer->bytes - buffer->len) return 0;
    memcpy(buffer->bytes + buffer->len, bytes, len);
    buffer->len += len;
    return len;
}

static size_t replay_read(void *bytes, size_t len, void *opaque)
{
    replay_buffer *buffer = opaque;
    if (len > buffer->len - buffer->cursor) return 0;
    memcpy(bytes, buffer->bytes + buffer->cursor, len);
    buffer->cursor += len;
    return len;
}

static void replay_bounds(void)
{
    axi_replay replay, loaded;
    axi_replay_entry saved;
    replay_buffer buffer;
    uint8_t digest[32], output[16];
    uint64_t fuel = 71;
    size_t output_len;
    long result = 3;
    axi_replay_init(&replay, NULL);
    axi_replay_set_mode(&replay, AXI_REPLAY_RECORD);
    CHECK(axi_replay_record(&replay, "io.Write", "audit", "abc", 3,
                            &result, sizeof result, 2, NULL, 0, 0) == 0);
    CHECK(replay.n == 1);
    saved = replay.records[0];
    memset(&buffer, 0, sizeof buffer);
    CHECK(axi_replay_save_to(&replay, replay_write, &buffer) == 0);
    axi_replay_init(&loaded, NULL);
    loaded.mode = AXI_REPLAY_REPLAY;
    CHECK(axi_replay_load_from(&loaded, replay_read, &buffer) == 0);
    CHECK(loaded.n == 1 && loaded.cursor == 0);
    output_len = sizeof output;
    CHECK(axi_replay_next(&loaded, "io.Write", "audit", "abc", 3,
                          output, &output_len, &fuel, NULL, NULL, NULL, NULL) == 0);
    CHECK(output_len == 8 && output[7] == 3 && fuel == 2
          && axi_replay_at_end(&loaded));
    axi_replay_free(&loaded);
    replay.mode = AXI_REPLAY_REPLAY;
    for (unsigned mutation = 0; mutation < 8; mutation++) {
        replay.records[0] = saved;
        switch (mutation) {
        case 0: replay.records[0].payload_len = 1025; break;
        case 1: replay.records[0].result_len = (size_t)-1; break;
        case 2: memset(replay.records[0].cap, 'x', AXI_CAPNAME); break;
        case 3: replay.records[0].has_result_str = 2; break;
        case 4: replay.records[0].nbytes = 4; break;
        case 5: replay.records[0].record_nbytes = 1; break;
        case 6: replay.records[0].payload[0] ^= 1; break;
        case 7: replay.records[0].result[0] ^= 1; break;
        }
        memset(&buffer, 0, sizeof buffer);
        memset(digest, 0xa5, sizeof digest);
        if (mutation < 2) {
            CHECK(!axi_replay_entry_digest_accounted(&replay.records[0], digest, NULL));
            CHECK(digest[0] == 0xa5 && digest[31] == 0xa5);
        }
        CHECK(axi_replay_save_to(&replay, replay_write, &buffer) != 0);
        CHECK(buffer.len == 0);
        memset(output, 0x5a, sizeof output); output_len = sizeof output; fuel = 71;
        CHECK(axi_replay_peek(&replay, "io.Write", "audit", "abc", 3,
                              output, &output_len, &fuel, NULL, NULL, NULL, NULL) != 0);
        CHECK(output[0] == 0x5a && output_len == sizeof output && fuel == 71
              && replay.cursor == 0);
    }
    replay.records[0] = saved;
    output_len = sizeof output;
    CHECK(axi_replay_peek(&replay, "io.Write", "audit", "abc", 3,
                          NULL, &output_len, NULL, NULL, NULL, NULL, NULL) != 0);
    CHECK(axi_replay_peek(&replay, "io.Write", "audit", "abc", 3,
                          output, NULL, NULL, NULL, NULL, NULL, NULL) != 0);
    replay.mode = AXI_REPLAY_RECORD;
    replay.oom = 1;
    CHECK(axi_replay_prepare(&replay, 0) != 0);
    CHECK(axi_replay_record(&replay, "io.Write", "audit", "abc", 3,
                            &result, sizeof result, 2, NULL, 0, 0) != 0);
    CHECK(replay.n == 1);
    replay.oom = 0;
    CHECK(axi_replay_record(&replay, "", "audit", "abc", 3,
                            &result, sizeof result, 2, NULL, 0, 0) != 0);
    CHECK(replay.n == 1);
    axi_replay_free(&replay);
}

static void effect_records_and_grants(void)
{
    axi_ledger ledger;
    axi_effect_journal journal;
    axi_grants grants;
    uint8_t root[32] = {0}, tip[32], digest[32] = {0};
    char too_long[AXI_CAPNAME + 1], text[1024];
    uint64_t attempt;
    FILE *json;
    size_t n;
    axi_ledger_init(&ledger, root);
    memcpy(tip, ledger.tip, sizeof tip);
    memset(too_long, 'a', AXI_CAPNAME); too_long[AXI_CAPNAME] = 0;
    CHECK(axi_ledger_append(&ledger, "", "audit", "abc", 3) != 0);
    CHECK(axi_ledger_append(&ledger, too_long, "audit", "abc", 3) != 0);
    CHECK(axi_ledger_append(&ledger, "io.Write", "audit", NULL, 1) != 0);
    CHECK(axi_ledger_append_digest(&ledger, "io.Write", "audit", NULL, 1) != 0);
    CHECK(ledger.n == 0 && ledger.cap == 0 && memcmp(tip, ledger.tip, 32) == 0);
    CHECK(axi_ledger_append_digest(&ledger, "io.\"Write", "line\nbreak", digest, 3) == 0);
    json = tmpfile();
    CHECK(json != NULL);
    if (json) {
        axi_ledger_print_json(&ledger, json);
        rewind(json);
        n = fread(text, 1, sizeof text - 1, json); text[n] = 0;
        CHECK(axi_json_validate(text, n) == 0);
        CHECK(strstr(text, "io.\\\"Write") != NULL);
        CHECK(strstr(text, "line\\u000abreak") != NULL);
        fclose(json);
    }
    axi_ledger_free(&ledger);
    ledger.n = 1;
    CHECK(axi_ledger_prepare(&ledger) != 0);
    ledger.n = 0;
    axi_effect_journal_init(&journal, root);
    CHECK(axi_effect_journal_begin(&journal, "io.Write", "audit", "a", 1,
                                    &attempt) == 0);
    CHECK(axi_effect_journal_attempt(&journal, attempt) == 0);
    CHECK(axi_effect_journal_finish(&journal, attempt, 1, 1) == 0);
    CHECK(axi_effect_journal_verify(&journal) == 0);
    CHECK(axi_effect_journal_begin(&journal, "io.Write", "audit", NULL, 0,
                                    &attempt) == 0);
    journal.oom = 1;
    CHECK(axi_effect_journal_attempt(&journal, attempt) != 0);
    CHECK(axi_effect_journal_finish(&journal, attempt, 0, -1) != 0);
    journal.oom = 0;
    CHECK(axi_effect_journal_finish(&journal, attempt, 0, -1) == 0);
    axi_effect_journal_free(&journal);
    journal.n = 1;
    CHECK(axi_effect_journal_begin(&journal, "io.Write", "audit", NULL, 0,
                                    &attempt) != 0);
    journal.n = 0;
    axi_grants_init(&grants);
    CHECK(axi_grants_add(&grants, "io.Write") == 0);
    CHECK(axi_grants_has(&grants, "io.Write"));
    CHECK(axi_grants_add(&grants, "io.Write") == -3);
    grants.n = 2; memcpy(grants.name[1], grants.name[0], AXI_CAPNAME);
    CHECK(!axi_grants_has(&grants, "io.Write"));
    CHECK(axi_grants_add(&grants, "fs.Read") != 0);
    memset(grants.name[1], 'x', AXI_CAPNAME);
    CHECK(!axi_grants_has(&grants, "io.Write"));
    CHECK(axi_grants_add(&grants, "fs.Read") != 0);
    CHECK(grants.n == 2);
}

static uint64_t fixed_now(void *opaque, int *ok)
{
    (void)opaque;
    *ok = 1;
    return 1;
}

static void replay_effect_refusal(void)
{
    axi_replay replay;
    axi_effect_journal journal;
    axi_mem_account account;
    axi_resource_envelope resources;
    axi_resource_vector ceiling = {10, 10000, 10000, 10, 10};
    axi_host_eff_ctx ctx;
    const axi_host_eff *effect = axi_host_eff_find("io.Write");
    uint8_t root[32] = {0};
    uint64_t used = 4;
    int exhausted = 0;
    long result = 3;
    axi_replay_init(&replay, root); replay.mode = AXI_REPLAY_RECORD;
    CHECK(axi_replay_record(&replay, "io.Write", "audit", "abc", 3,
                            &result, sizeof result, 2, NULL, 0, 0) == 0);
    replay.mode = AXI_REPLAY_REPLAY;
    axi_effect_journal_init(&journal, root);
    axi_mem_account_init(&account, 65536);
    axi_resource_envelope_init(&resources, &ceiling, 100, fixed_now, NULL);
    memset(&ctx, 0, sizeof ctx);
    ctx.resources = &resources; ctx.account = &account; ctx.replay = &replay;
    ctx.journal = &journal; ctx.cell_name = "audit";
    ctx.fuel_budget = 3; ctx.fuel_used = &used; ctx.fuel_exhausted = &exhausted;
    CHECK(effect != NULL);
    CHECK(effect->fn(&ctx, "abc", 3) < 0);
    CHECK(used == 4 && exhausted == 1 && replay.cursor == 0);
    CHECK(ctx.attempt_state == AXI_EFFECT_NOT_ATTEMPTED);
    CHECK(journal.n == 2 && journal.open_attempt == 0
          && journal.row[1].state == AXI_JOURNAL_FAILED
          && axi_effect_journal_verify(&journal) == 0);
    CHECK(axi_resource_outputs_free(&resources, &account));
    CHECK(account.live == 0);
    axi_effect_journal_free(&journal);
    axi_effect_journal_init(&journal, root);
    axi_mem_account_init(&account, 1); used = 0; exhausted = 0;
    CHECK(effect->fn(&ctx, "abc", 3) < 0);
    CHECK(journal.n == 2 && journal.open_attempt == 0
          && axi_effect_journal_verify(&journal) == 0);
    CHECK(ctx.attempt_state == AXI_EFFECT_NOT_ATTEMPTED && replay.cursor == 0);
    CHECK(effect->fn(NULL, "abc", 3) < 0);
    axi_effect_journal_free(&journal);
    axi_replay_free(&replay);
}

static void resource_transactions(void)
{
    axi_resource_envelope resources;
    axi_resource_vector ceiling = {UINT64_MAX, UINT64_MAX, UINT64_MAX,
                                    UINT64_MAX, UINT64_MAX};
    axi_resource_vector amount = {2, 3, 4, 1, 2}, excessive;
    axi_resource_vector saved_spent, saved_reserved;
    axi_mem_account owner, wrong_owner;
    void *output;
    axi_resource_envelope_init(&resources, &ceiling, 100, fixed_now, NULL);
    CHECK(axi_resource_reserve(&resources, &amount) == AXI_RESOURCE_OK);
    CHECK(axi_resource_commit(&resources, &resources.reserved,
                              &resources.reserved) == AXI_RESOURCE_OK);
    CHECK(resources.spent.calls == 2 && resources.spent.input_bytes == 3
          && resources.spent.output_bytes == 4 && resources.spent.children == 2
          && resources.spent.handles == 1 && resources.live_handles == 1);
    CHECK(resources.reserved.calls == 0 && resources.reserved.handles == 0
          && axi_resource_envelope_valid(&resources));
    CHECK(axi_resource_reserve(&resources, &amount) == AXI_RESOURCE_OK);
    saved_spent = resources.spent; saved_reserved = resources.reserved;
    excessive = amount; excessive.output_bytes++;
    CHECK(axi_resource_commit(&resources, &amount, &excessive) == AXI_RESOURCE_CORRUPT);
    CHECK(memcmp(&saved_spent, &resources.spent, sizeof saved_spent) == 0);
    CHECK(memcmp(&saved_reserved, &resources.reserved, sizeof saved_reserved) == 0);
    CHECK(axi_resource_release(&resources, &resources.reserved) == AXI_RESOURCE_CORRUPT);
    CHECK(resources.reserved.calls == 0 && resources.reserved.output_bytes == 0);
    CHECK(axi_resource_handle_closed(&resources) == AXI_RESOURCE_CORRUPT);
    CHECK(resources.live_handles == 0);
    axi_mem_account_init(&owner, 65536);
    axi_mem_account_init(&wrong_owner, 65536);
    output = axi_resource_output_alloc(&resources, &owner, 8);
    CHECK(output != NULL);
    CHECK(!axi_resource_outputs_free(&resources, &wrong_owner));
    CHECK(resources.owned_output_count == 1 && resources.owned_outputs[0] == output
          && owner.live > 0);
    CHECK(axi_resource_outputs_free(&resources, &owner));
    CHECK(resources.owned_output_count == 0 && owner.live == 0 && owner.active_count == 0);
    resources.owned_output_count = AXI_RESOURCE_MAX_OWNED_OUTPUTS + 1;
    CHECK(!axi_resource_outputs_free(&resources, &owner));
    CHECK(!axi_resource_envelope_valid(&resources));
    resources.owned_output_count = 0;
    resources.live_handles = 2; resources.spent.handles = 1;
    CHECK(!axi_resource_envelope_valid(&resources));
}

static void assembly_spans_and_strings(void)
{
    static const char prefix[] = "cell first nregs=1\nret r0\nend\n";
    static const char with_suffix[] = "cell first nregs=1\nret r0\nend\n"
                                      "cell hidden nregs=1\nret r0\nend\n";
    static const char quoted[] = "cell strings nregs=1\n"
        "k0 str \"tail\\\\\"   # a quoted string ending in a backslash\n"
        "ldk r0 k0\nret r0\nend\n";
    static const char bad_suffix[] = "cell strings nregs=1\n"
        "k0 str \"ok\"x\nret r0\nend\n";
    static const char tabs[] = "cell first nregs=1\ncall r0 @last 0\nret r0\nend\n"
        "cell\tlast\tnregs=1\nret r0\nend\n";
    axb_mod module;
    uint8_t root[32];
    char *exact = malloc(sizeof prefix - 1);
    CHECK(exact != NULL);
    if (!exact) return;
    memcpy(exact, prefix, sizeof prefix - 1);
    memset(&module, 0, sizeof module);
    CHECK(axb_asm_text(exact, sizeof prefix - 1, "bounded", &module) == 0);
    CHECK(module.n == 1 && module.cells[0].nc == 1);
    axb_mod_free(&module);
    free(exact);
    memset(&module, 0, sizeof module);
    CHECK(axb_asm_text(with_suffix, sizeof prefix - 1, "prefix", &module) == 0);
    CHECK(module.n == 1);
    axi_sha256(with_suffix, sizeof prefix - 1, root);
    CHECK(memcmp(root, module.src_hash, 32) == 0);
    axb_mod_free(&module);
    memset(&module, 0, sizeof module);
    CHECK(axb_asm_text(quoted, sizeof quoted - 1, "quoted", &module) == 0);
    CHECK(module.n == 1 && module.cells[0].nk == 1
          && module.cells[0].k[0].slen == 5
          && memcmp(module.cells[0].k[0].s, "tail\\", 5) == 0);
    axb_mod_free(&module);
    memset(&module, 0, sizeof module);
    CHECK(axb_asm_text(bad_suffix, sizeof bad_suffix - 1, "bad-quoted", &module) != 0);
    axb_mod_free(&module);
    memset(&module, 0, sizeof module);
    CHECK(axb_asm_text(tabs, sizeof tabs - 1, "tabs", &module) == 0);
    CHECK(module.n == 2 && ((module.cells[0].code[0] >> 16) & 255u) == 1);
    axb_mod_free(&module);
    CHECK(axb_asm_text(NULL, 1, "missing", &module) != 0);
    CHECK(axb_asm_text(prefix, sizeof prefix - 1, "missing", NULL) != 0);
    {
        const uint32_t nops = 10000;
        size_t bytes = sizeof prefix + (size_t)nops * 4;
        char *source = malloc(bytes);
        size_t used;
        CHECK(source != NULL);
        if (!source) return;
        used = (size_t)sprintf(source, "cell many nregs=1\n");
        for (uint32_t i = 0; i < nops; i++) {
            memcpy(source + used, "nop\n", 4); used += 4;
        }
        memcpy(source + used, "ret r0\nend\n", 11); used += 11;
        memset(&module, 0, sizeof module);
        CHECK(axb_asm_text(source, used, "many", &module) == 0);
        CHECK(module.n == 1 && module.cells[0].nc == nops + 1);
        CHECK(axb_mod_verify(&module, "many", NULL) == 0);
        axb_mod_free(&module);
        free(source);
    }
    {
        char source[257 * 48];
        size_t used = 0;
        for (unsigned i = 0; i < 257; i++)
            used += (size_t)snprintf(source + used, sizeof source - used,
                                     "cell c%u nregs=1\nret r0\nend\n", i);
        memset(&module, 0, sizeof module);
        CHECK(axb_asm_text(source, used, "too-many-cells", &module) != 0);
        CHECK(module.n == 0);
        axb_mod_free(&module);
    }
}

static void memory_account_integrity(void)
{
    axi_mem_account account, wrong;
    unsigned char *first, *middle, *last;
    size_t live;
    axi_mem_account_init(&account, 65536);
    axi_mem_account_init(&wrong, 65536);
    first = axi_mem_alloc(&account, 11);
    middle = axi_mem_alloc(&account, 17);
    last = axi_mem_alloc(&account, 23);
    CHECK(first && middle && last);
    if (!first || !middle || !last) return;
    memset(first, 0x5a, 11); memset(middle, 0xa5, 17); memset(last, 0x3c, 23);
    live = account.live;
    CHECK(!axi_mem_free(&account, first + 1));
    CHECK(account.failure == AXI_MEM_ACCOUNT_CORRUPTION && account.live == live);
    CHECK(axi_mem_realloc(&account, (void *)(uintptr_t)1, 100) == NULL);
    CHECK(account.failure == AXI_MEM_ACCOUNT_CORRUPTION && account.live == live);
    CHECK(!axi_mem_free(&wrong, first) && wrong.live == 0);
    CHECK(axi_mem_realloc(&account, middle, 17) == middle
          && account.failure == AXI_MEM_FAILURE_NONE && account.live == live);
    /* A match at the list head must not bypass total-account validation. */
    account.fixed = 1;
    CHECK(!axi_mem_free(&account, last));
    CHECK(account.failure == AXI_MEM_ACCOUNT_CORRUPTION && account.live == live);
    account.fixed = 0;
    middle = axi_mem_realloc(&account, middle, 4096);
    CHECK(middle != NULL && middle[0] == 0xa5 && middle[16] == 0xa5);
    CHECK(axi_mem_free(&account, middle));
    CHECK(axi_mem_free(&account, first));
    CHECK(last[0] == 0x3c && last[22] == 0x3c);
    CHECK(axi_mem_free(&account, last));
    CHECK(account.live == 0 && account.active_count == 0);
    CHECK(axi_mem_free(&account, NULL) && account.failure == AXI_MEM_FAILURE_NONE);
    CHECK(account.denied_failure == AXI_MEM_ACCOUNT_CORRUPTION);
}

static void dispatch_fuel_boundaries(void)
{
    /* A taken/untaken branch loop executes exactly four operations per
     * increment. Every refused instruction must leave fuel and output at
     * the last completed boundary, even at the final RET. */
    uint32_t code[] = {instruction(OP_ADD, 0, 0, 1),
                       instruction(OP_LT, 3, 0, 2),
                       instruction(OP_JF, 3, 0, 2),
                       instruction(OP_JMP, 0, 255, 253),
                       instruction(OP_RET, 0, 0, 0)};
    axi_vval args[3], out;
    uint64_t used;
    memset(args, 0, sizeof args);
    args[0].kind = args[1].kind = args[2].kind = VB_U64;
    args[1].bits = 1; args[2].bits = 17;
    for (uint64_t budget = 1; budget <= 69; budget++) {
        memset(&out, 0, sizeof out); out.kind = VB_U64; out.bits = 99;
        CHECK(run(code, 5, 4, args, 3, &out, budget, &used) == (budget >= 68));
        CHECK(used == (budget < 68 ? budget : 68));
        CHECK(out.kind == VB_U64 && out.bits == (budget < 68 ? 99u : 17u));
    }
    {
        /* CALL costs four before entering the child. A callee RET and the
         * caller RET share the outer budget, without rounding or recharge. */
        uint32_t caller[] = {instruction(OP_CALL, 0, 1, 1),
                             instruction(OP_RET, 0, 0, 0)};
        uint32_t callee[] = {instruction(OP_RET, 0, 0, 0)};
        axb_cell cells[2];
        axb_mod module;
        axi_diags diags;
        memset(cells, 0, sizeof cells); memset(&module, 0, sizeof module);
        cells[0].name = "caller"; cells[0].nregs = 1;
        cells[0].code = caller; cells[0].nc = 2;
        cells[1].name = "callee"; cells[1].nregs = 1;
        cells[1].code = callee; cells[1].nc = 1;
        module.cells = cells; module.n = 2;
        for (uint64_t budget = 1; budget <= 6; budget++) {
            memset(&diags, 0, sizeof diags); out.bits = 99;
            CHECK(axi_vm_run_cell_diag(&module, 0, args + 1, 1, &out,
                    budget, &used, NULL, NULL, &diags) == (budget == 6));
            CHECK(used == (budget < 4 ? 0 : budget));
            CHECK(out.bits == (budget == 6 ? 1u : 99u));
            CHECK(budget == 6 || (diags.n == 1
                                 && !strcmp(diags.d[0].code, "AXI-R008")));
        }
    }
}

static int worker_exit_without_frame(void *opaque)
{
    int *marker = opaque;
    char entered = 'x';
    if (write(*marker, &entered, 1) != 1) _exit(2);
    _exit(0);
}

static int worker_success(void *opaque)
{
    (void)opaque;
    return 0;
}

static void worker_transport(void)
{
    axi_resource_envelope resources;
    axi_resource_vector ceiling = {1, 0, 0, 0, 1};
    axi_host_eff_ctx ctx;
    int clock_ok, marker[2];
    uint64_t now = axi_platform_monotonic_ns(NULL, &clock_ok);
    char entered = 0;
    CHECK(clock_ok);
    axi_resource_envelope_init(&resources, &ceiling, now + 2000000000u,
                               axi_platform_monotonic_ns, NULL);
    resources.reserved.children = 1;
    memset(&ctx, 0, sizeof ctx); ctx.resources = &resources;
    CHECK(pipe(marker) == 0);
    CHECK(axi_platform_blocking_call(&ctx, worker_exit_without_frame, &marker[1]) < 0);
    close(marker[1]);
    CHECK(read(marker[0], &entered, 1) == 1 && entered == 'x');
    close(marker[0]);
    CHECK(resources.first_denial == AXI_RESOURCE_OK);
    CHECK(axi_platform_blocking_call(&ctx, worker_success, NULL) == 0);
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--workers") == 0) {
        worker_transport();
        printf("audit40 workers: %u checks, %u failures\n", checks, failures);
        return failures != 0;
    }
    arithmetic_aliases();
    union_aliases();
    typed_equality();
    replay_bounds();
    effect_records_and_grants();
    replay_effect_refusal();
    resource_transactions();
    assembly_spans_and_strings();
    memory_account_integrity();
    dispatch_fuel_boundaries();
    printf("audit40 runtime: %u checks, %u failures\n", checks, failures);
    return failures != 0;
}
