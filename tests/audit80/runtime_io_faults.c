#include "runtime_store.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { fprintf(stderr, "store-faults:%d: %s\n", __LINE__, #c); return 1; } } while (0)

static int one(unsigned fault)
{
    runtime80_store store;
    axi_local_attempt_v1_outcome out, status;
    unsigned expected_call = AXI_LOCAL_ATTEMPT_V1_COMMITTED;
    unsigned expected_status, published = 1, before;
    int rc;
    CHECK(runtime80_store_init(&store) == 0);
    CHECK(runtime80_io_attach(&store) == 0);
    runtime80_io_fault(fault);
    alarm(5);
    rc = runtime80_store_commit(&store, &out);
    alarm(0);
    if (fault >= R80_IO_PAYLOAD_ENOSPC && fault <= R80_IO_PAYLOAD_RENAME) {
        expected_call = AXI_LOCAL_ATTEMPT_V1_FAILED; published = 0;
    } else if (fault >= R80_IO_TERMINAL_WRITE) expected_call = AXI_LOCAL_ATTEMPT_V1_UNKNOWN;
    expected_status = fault == R80_IO_TERMINAL_DIRECTORY_FSYNC
                      ? AXI_LOCAL_ATTEMPT_V1_COMMITTED : expected_call;
    CHECK(rc == (fault <= R80_IO_READ_EINTR ? AXI_LOCAL_ATTEMPT_V1_OK : AXI_LOCAL_ATTEMPT_V1_REFUSED));
    CHECK(out.state == expected_call && out.effect_performed == published);
    CHECK(memcmp(out.grant_root, store.root, 32) == 0);
    CHECK(axi_local_attempt_v1_status(store.directory, store.root, &status) == AXI_LOCAL_ATTEMPT_V1_OK);
    CHECK(status.state == expected_status && status.effect_performed == 0);
    CHECK(memcmp(status.grant_root, store.root, 32) == 0);
    CHECK(fault ? runtime80_io_hits() > 0 : runtime80_io_hits() == 0);
    printf("{\"case\":\"store_io_fault\",\"fault\":%u,\"hits\":%u,\"call_state\":%u,"
           "\"query_state\":%u,\"effect_performed\":%u}\n", fault, runtime80_io_hits(),
           out.state, status.state, out.effect_performed);
    runtime80_io_fault(R80_IO_NONE);
    CHECK(runtime80_store_content(&store, (int)published) == 0);
    CHECK(runtime80_store_scan(&store, 1, expected_status) == 0);
    CHECK(runtime80_io_publishes() == published);
    before = runtime80_io_publishes();
    CHECK(runtime80_store_commit(&store, &out) == AXI_LOCAL_ATTEMPT_V1_REFUSED);
    CHECK(out.state == expected_status && out.effect_performed == 0);
    CHECK(runtime80_io_publishes() == before);
    CHECK(runtime80_store_content(&store, (int)published) == 0);
    runtime80_io_detach();
    CHECK(runtime80_store_destroy(&store) == 0);
    return 0;
}

int main(void)
{
    unsigned fault;
    for (fault = R80_IO_NONE; fault <= R80_IO_TERMINAL_DIRECTORY_FSYNC; fault++)
        if (one(fault)) return 1;
    printf("audit80 local I/O faults: %u checks PASS\n", checks);
    return 0;
}

