/* Audit40 runtime regressions. SPDX-License-Identifier: LicenseRef-SPL-1.0 */
#include "axi_vm.h"
#include "axi_replay.h"
#include "axi_json.h"

#include <stdio.h>
#include <string.h>

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

int main(void)
{
    arithmetic_aliases();
    union_aliases();
    typed_equality();
    replay_bounds();
    effect_records_and_grants();
    printf("audit40 runtime: %u checks, %u failures\n", checks, failures);
    return failures != 0;
}
