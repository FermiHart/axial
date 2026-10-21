/* Legacy inactive-store persistence fixture; not a host-identity authority proof. */
#ifndef AUDIT80_RUNTIME_STORE_H
#define AUDIT80_RUNTIME_STORE_H
#include "axi_ag1_v1.h"
#include "axi_local_attempt_v1.h"
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct {
    char directory[128];
    uint8_t signed_grant[AXI_AG1_V1_SIGNED_SIZE], pk[32], root[32];
    uint8_t action_bytes[4096], action_root[32], context_root[32];
    size_t action_len;
    axi_local_admission_v1_pins pins;
    axi_local_admission_v1_observed observed;
} runtime80_store;

extern const uint8_t runtime80_store_payload[];
extern const size_t runtime80_store_payload_size;
int runtime80_store_init(runtime80_store *store);
int runtime80_store_commit(runtime80_store *store, axi_local_attempt_v1_outcome *out);
int runtime80_store_content(runtime80_store *store, int new_payload);
int runtime80_store_scan(runtime80_store *store, unsigned expected_count, unsigned expected_state);
int runtime80_store_destroy(runtime80_store *store);

enum {
    R80_IO_NONE, R80_IO_SHORT, R80_IO_WRITE_EINTR, R80_IO_READ_EINTR,
    R80_IO_PAYLOAD_ENOSPC, R80_IO_PAYLOAD_FSYNC, R80_IO_PAYLOAD_RENAME,
    R80_IO_TERMINAL_WRITE, R80_IO_TERMINAL_FSYNC, R80_IO_TERMINAL_RENAME,
    R80_IO_TERMINAL_DIRECTORY_FSYNC
};
enum {
    R80_CRASH_NONE, R80_CRASH_EMPTY_RECORD, R80_CRASH_PARTIAL_RECORD,
    R80_CRASH_WRITTEN_RECORD, R80_CRASH_SPEND_FILE, R80_CRASH_SPEND_RECORDS,
    R80_CRASH_SPEND_STORE, R80_CRASH_PAYLOAD_FILE, R80_CRASH_PAYLOAD_RENAME,
    R80_CRASH_PAYLOAD_STORE, R80_CRASH_TERMINAL_FILE, R80_CRASH_TERMINAL_RENAME,
    R80_CRASH_TERMINAL_RECORDS
};
int runtime80_io_attach(const runtime80_store *store);
void runtime80_io_fault(unsigned fault);
void runtime80_io_crash(unsigned point, int report_fd);
void runtime80_io_detach(void);
unsigned runtime80_io_hits(void);
unsigned runtime80_io_publishes(void);
ssize_t runtime80_io_write(int fd, const void *bytes, size_t n);
ssize_t runtime80_io_read(int fd, void *bytes, size_t n);
int runtime80_io_fsync(int fd);
int runtime80_io_renameat(int from, const char *name, int to, const char *target);
#endif

