#include "axi_handle_table.h"

#include <sched.h>
#include <string.h>

static uint32_t next_generation;

static uint32_t allocate_generation(void)
{
    uint32_t previous = __atomic_load_n(&next_generation, __ATOMIC_RELAXED);
    for (;;) {
        /* Generation zero is invalid. Never recycle a nonzero generation:
         * otherwise a sufficiently old handle can acquire new authority. */
        if (previous == UINT32_MAX) return 0;
        if (__atomic_compare_exchange_n(&next_generation, &previous,
                                         previous + 1u, 0,
                                         __ATOMIC_RELAXED, __ATOMIC_RELAXED))
            return previous + 1u;
    }
}

static void table_lock(axi_handle_table *table)
{
    while (__atomic_test_and_set(&table->lock, __ATOMIC_ACQUIRE))
        sched_yield();
}

static void table_unlock(axi_handle_table *table)
{
    __atomic_clear(&table->lock, __ATOMIC_RELEASE);
}

void axi_handle_table_init(axi_handle_table *table)
{
    if (!table) return;
    memset(table, 0, sizeof *table);
}

int axi_handle_table_insert_identified(axi_handle_table *table, intptr_t value,
                                       const uint8_t identity[32],
                                       uint64_t *handle)
{
    uint32_t slot;
    if (!table || !handle || value == 0) return -1;
    table_lock(table);
    for (slot = 0; slot < AXI_HANDLE_TABLE_CAP; slot++) {
        if (table->state[slot] == AXI_HANDLE_FREE) {
            uint32_t generation = allocate_generation();
            if (generation == 0) {
                table_unlock(table);
                return -1;
            }
            table->value[slot] = value;
            table->generation[slot] = generation;
            __atomic_store_n(&table->references[slot], 0u, __ATOMIC_RELAXED);
            if (identity) memcpy(table->identity[slot], identity, 32);
            else memset(table->identity[slot], 0, 32);
            table->state[slot] = AXI_HANDLE_LIVE;
            table->live++;
            *handle = ((uint64_t)generation << 32) | slot;
            table_unlock(table);
            return 0;
        }
    }
    table_unlock(table);
    return -1;
}

int axi_handle_table_insert(axi_handle_table *table, intptr_t value,
                            uint64_t *handle)
{
    return axi_handle_table_insert_identified(table, value, NULL, handle);
}

int axi_handle_table_get(const axi_handle_table *table, uint64_t handle,
                         intptr_t *value)
{
    uint32_t generation = (uint32_t)(handle >> 32);
    uint32_t slot = (uint32_t)handle;
    axi_handle_table *mutable_table = (axi_handle_table *)table;
    if (!table || !value || slot >= AXI_HANDLE_TABLE_CAP)
        return -1;
    table_lock(mutable_table);
    if (generation != table->generation[slot]
            || table->state[slot] != AXI_HANDLE_LIVE) {
        table_unlock(mutable_table);
        return -1;
    }
    *value = table->value[slot];
    table_unlock(mutable_table);
    return 0;
}

int axi_handle_table_acquire(axi_handle_table *table, uint64_t handle,
                             intptr_t *value)
{
    return axi_handle_table_acquire_identified(table, handle, value, NULL);
}

int axi_handle_table_acquire_identified(axi_handle_table *table, uint64_t handle,
                                        intptr_t *value, uint8_t identity[32])
{
    uint32_t generation = (uint32_t)(handle >> 32);
    uint32_t slot = (uint32_t)handle;
    if (!table || !value || slot >= AXI_HANDLE_TABLE_CAP) return -1;
    table_lock(table);
    if (generation != table->generation[slot]
            || table->state[slot] != AXI_HANDLE_LIVE
            || __atomic_load_n(&table->references[slot], __ATOMIC_RELAXED)
               == UINT32_MAX) {
        table_unlock(table);
        return -1;
    }
    __atomic_add_fetch(&table->references[slot], 1u, __ATOMIC_ACQUIRE);
    *value = table->value[slot];
    if (identity) memcpy(identity, table->identity[slot], 32);
    table_unlock(table);
    return 0;
}

int axi_handle_table_release(axi_handle_table *table, uint64_t handle)
{
    uint32_t generation = (uint32_t)(handle >> 32);
    uint32_t slot = (uint32_t)handle;
    if (!table || slot >= AXI_HANDLE_TABLE_CAP) return -1;
    table_lock(table);
    if (generation != table->generation[slot]
            || table->state[slot] == AXI_HANDLE_FREE
            || __atomic_load_n(&table->references[slot], __ATOMIC_RELAXED)
               == 0) {
        table_unlock(table);
        return -1;
    }
    __atomic_sub_fetch(&table->references[slot], 1u, __ATOMIC_RELEASE);
    table_unlock(table);
    return 0;
}

static int remove_slot(axi_handle_table *table, uint32_t slot,
                       uint32_t generation, intptr_t *value)
{
    table_lock(table);
    if (slot >= AXI_HANDLE_TABLE_CAP
            || generation != table->generation[slot]
            || table->state[slot] != AXI_HANDLE_LIVE) {
        table_unlock(table);
        return -1;
    }
    table->state[slot] = AXI_HANDLE_CLOSING;
    table_unlock(table);
    while (__atomic_load_n(&table->references[slot], __ATOMIC_ACQUIRE) != 0)
        sched_yield();
    table_lock(table);
    *value = table->value[slot];
    table->value[slot] = 0;
    memset(table->identity[slot], 0, 32);
    table->state[slot] = AXI_HANDLE_FREE;
    table->live--;
    table_unlock(table);
    return 0;
}

int axi_handle_table_remove(axi_handle_table *table, uint64_t handle,
                            intptr_t *value)
{
    return !table || !value ? -1
        : remove_slot(table, (uint32_t)handle, (uint32_t)(handle >> 32), value);
}

int axi_handle_table_take(axi_handle_table *table, intptr_t *value)
{
    uint32_t slot, generation = 0;
    if (!table || !value) return -1;
    table_lock(table);
    for (slot = 0; slot < AXI_HANDLE_TABLE_CAP; slot++) {
        if (table->state[slot] == AXI_HANDLE_LIVE) {
            generation = table->generation[slot];
            break;
        }
    }
    table_unlock(table);
    if (slot == AXI_HANDLE_TABLE_CAP) return 1;
    return remove_slot(table, slot, generation, value);
}
