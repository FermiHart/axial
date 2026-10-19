#ifndef AXI_HANDLE_TABLE_H
#define AXI_HANDLE_TABLE_H

#include <stdint.h>

#define AXI_HANDLE_TABLE_CAP 64u

typedef enum {
    AXI_HANDLE_FREE = 0,
    AXI_HANDLE_LIVE = 1,
    AXI_HANDLE_CLOSING = 2
} axi_handle_state;

typedef struct {
    intptr_t value[AXI_HANDLE_TABLE_CAP];
    uint32_t generation[AXI_HANDLE_TABLE_CAP];
    uint32_t references[AXI_HANDLE_TABLE_CAP];
    uint8_t state[AXI_HANDLE_TABLE_CAP];
    uint8_t identity[AXI_HANDLE_TABLE_CAP][32];
    uint32_t live;
    uint8_t lock;
} axi_handle_table;

void axi_handle_table_init(axi_handle_table *table);
int axi_handle_table_insert(axi_handle_table *table, intptr_t value,
                             uint64_t *handle);
int axi_handle_table_insert_identified(axi_handle_table *table, intptr_t value,
                                       const uint8_t identity[32],
                                       uint64_t *handle);
int axi_handle_table_get(const axi_handle_table *table, uint64_t handle,
                          intptr_t *value);
int axi_handle_table_acquire(axi_handle_table *table, uint64_t handle,
                             intptr_t *value);
int axi_handle_table_acquire_identified(axi_handle_table *table, uint64_t handle,
                                        intptr_t *value, uint8_t identity[32]);
int axi_handle_table_release(axi_handle_table *table, uint64_t handle);
int axi_handle_table_remove(axi_handle_table *table, uint64_t handle,
                             intptr_t *value);
int axi_handle_table_take(axi_handle_table *table, intptr_t *value);

#endif
