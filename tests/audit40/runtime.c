/* Audit40 runtime regressions. SPDX-License-Identifier: LicenseRef-SPL-1.0 */
#include "axi_vm.h"

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

int main(void)
{
    arithmetic_aliases();
    printf("audit40 runtime: %u checks, %u failures\n", checks, failures);
    return failures != 0;
}
