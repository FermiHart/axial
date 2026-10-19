/* Exercise the final two 32-bit handle generations without billions of
 * allocations. This isolated translation unit can position private state;
 * it adds no test hook or mutable control to the production API.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0 */
#include "../../src/axi_handle_table.c"
#include <stdio.h>

int main(void)
{
    axi_handle_table table;
    uint64_t first, last, unchanged = 123;
    intptr_t value = 0;
    axi_handle_table_init(&table);
    next_generation = UINT32_MAX - 2u;
    if (axi_handle_table_insert(&table, 1, &first) != 0
            || axi_handle_table_remove(&table, first, &value) != 0 || value != 1
            || axi_handle_table_insert(&table, 2, &last) != 0
            || (uint32_t)(last >> 32) != UINT32_MAX
            || axi_handle_table_get(&table, first, &value) == 0
            || axi_handle_table_remove(&table, last, &value) != 0 || value != 2
            || axi_handle_table_insert(&table, 3, &unchanged) == 0
            || unchanged != 123 || table.live != 0
            || axi_handle_table_get(&table, first, &value) == 0
            || axi_handle_table_get(&table, last, &value) == 0) {
        fputs("audit40 handle generation exhaustion: FAIL\n", stderr);
        return 1;
    }
    puts("audit40 handle generation exhaustion: PASS");
    return 0;
}
