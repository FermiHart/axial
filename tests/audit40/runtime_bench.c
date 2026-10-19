/* Focused baseline/final microbenchmarks; no performance pass threshold.
 * Compile against the product sources, excluding both standalone mains.
 * Usage: runtime_bench vm 5000000 | alloc 8192 | asm 250000
 * SPDX-License-Identifier: LicenseRef-SPL-1.0 */
#include "axi_vm.h"
#include "axi_mem_account.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t now_ns(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) exit(2);
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static uint32_t op(uint8_t opcode, uint8_t a, uint8_t b, uint8_t c)
{
    return opcode | (uint32_t)a << 8 | (uint32_t)b << 16 | (uint32_t)c << 24;
}

static int bench_vm(uint64_t count)
{
    axb_cell cell;
    axb_mod module;
    axi_diags diags;
    axi_vval args[3], out;
    uint64_t used = 0, start, elapsed;
    uint32_t code[] = {op(OP_ADD, 0, 0, 1), op(OP_LT, 3, 0, 2),
                       op(OP_JF, 3, 0, 2), op(OP_JMP, 0, 255, 253),
                       op(OP_RET, 0, 0, 0)};
    memset(&cell, 0, sizeof cell); memset(&module, 0, sizeof module);
    memset(&diags, 0, sizeof diags); memset(args, 0, sizeof args);
    cell.name = "count"; cell.nregs = 4; cell.code = code; cell.nc = 5;
    module.cells = &cell; module.n = 1;
    args[0].kind = args[1].kind = args[2].kind = VB_U64;
    args[1].bits = 1; args[2].bits = count;
    start = now_ns();
    int ok = axi_vm_run_cell_diag(&module, 0, args, 3, &out, count * 4,
                                  &used, NULL, NULL, &diags);
    elapsed = now_ns() - start;
    if (!ok || out.kind != VB_U64 || out.bits != count || used != count * 4)
        return 1;
    printf("{\"case\":\"vm\",\"iterations\":%llu,\"fuel\":%llu,\"ns\":%llu}\n",
            (unsigned long long)count, (unsigned long long)used,
            (unsigned long long)elapsed);
    return 0;
}

static int bench_alloc(size_t count)
{
    axi_mem_account account;
    void **p = calloc(count, sizeof *p);
    uint64_t start, allocated, freed, sum = 0;
    if (!p) return 1;
    axi_mem_account_init(&account, (axi_mem_header_bytes() + 32) * count);
    start = now_ns();
    for (size_t i = 0; i < count; i++) {
        p[i] = axi_mem_alloc(&account, 32);
        if (!p[i]) return 1;
        ((unsigned char *)p[i])[0] = (unsigned char)i;
    }
    allocated = now_ns() - start;
    start = now_ns();
    for (size_t i = 0; i < count; i++) {
        sum += ((unsigned char *)p[i])[0];
        if (!axi_mem_free(&account, p[i])) return 1;
    }
    freed = now_ns() - start;
    if (account.live || account.active_count) return 1;
    printf("{\"case\":\"alloc\",\"count\":%zu,\"allocate_ns\":%llu,"
            "\"free_ns\":%llu,\"peak_bytes\":%zu,\"checksum\":%llu}\n",
            count, (unsigned long long)allocated, (unsigned long long)freed,
            account.peak, (unsigned long long)sum);
    free(p);
    return 0;
}

static int bench_asm(size_t count)
{
    axb_mod module;
    char *source = malloc(count * 4 + 64);
    size_t len;
    uint64_t start, elapsed;
    if (!source) return 1;
    len = (size_t)sprintf(source, "cell many nregs=1\n");
    for (size_t i = 0; i < count; i++) { memcpy(source + len, "nop\n", 4); len += 4; }
    memcpy(source + len, "ret r0\nend\n", 12); len += 11;
    memset(&module, 0, sizeof module);
    start = now_ns();
    int ok = axb_asm_text(source, len, "benchmark", &module) == 0;
    elapsed = now_ns() - start;
    if (!ok || module.n != 1 || module.cells[0].nc != count + 1) return 1;
    printf("{\"case\":\"asm\",\"instructions\":%zu,\"source_bytes\":%zu,\"ns\":%llu}\n",
            count + 1, len, (unsigned long long)elapsed);
    axb_mod_free(&module);
    free(source);
    return 0;
}

int main(int argc, char **argv)
{
    char *end = NULL;
    uint64_t count;
    if (argc != 3) {
        puts("usage: runtime_bench vm 5000000 | alloc 8192 | asm 250000");
        return argc == 1 ? 0 : 2;
    }
    count = strtoull(argv[2], &end, 10);
    if (!end || *end || count == 0 || count > 100000000) return 2;
    if (!strcmp(argv[1], "vm")) return bench_vm(count);
    if (!strcmp(argv[1], "alloc") && count <= 32768) return bench_alloc((size_t)count);
    if (!strcmp(argv[1], "asm") && count <= 1000000) return bench_asm((size_t)count);
    return 2;
}
