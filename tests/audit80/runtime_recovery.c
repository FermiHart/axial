/* Abrupt death of our own writer child. Kernel/filesystem remain running. */
#include "runtime_store.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { fprintf(stderr, "store-recovery:%d: %s\n", __LINE__, #c); return 1; } } while (0)

static int count_visit(const axi_local_attempt_v1_record_view *view, void *opaque)
{
    unsigned *count = opaque;
    (void)view; (*count)++;
    return 0;
}

static int one(unsigned point)
{
    runtime80_store store;
    axi_local_attempt_v1_outcome out;
    int pipefd[2], child_status, rc, status_rc, query_state;
    unsigned expected, visits = 0, published = point >= R80_CRASH_PAYLOAD_RENAME;
    pid_t child, waited;
    uint8_t observed_point = 0;
    ssize_t n;
    CHECK(runtime80_store_init(&store) == 0);
    CHECK(runtime80_io_attach(&store) == 0);
    CHECK(pipe(pipefd) == 0);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        close(pipefd[0]);
        runtime80_io_crash(point, pipefd[1]);
        (void)runtime80_store_commit(&store, &out);
        _exit(80); /* requested crash point was not reached */
    }
    close(pipefd[1]); alarm(5);
    do { n = read(pipefd[0], &observed_point, 1); } while (n < 0 && errno == EINTR);
    close(pipefd[0]);
    do { waited = waitpid(child, &child_status, 0); } while (waited < 0 && errno == EINTR);
    alarm(0);
    CHECK(n == 1 && observed_point == point && waited == child);
    CHECK(WIFSIGNALED(child_status) && WTERMSIG(child_status) == SIGKILL);
    CHECK(runtime80_store_content(&store, (int)published) == 0);
    CHECK(runtime80_io_publishes() == 0); /* parent has never published */
    status_rc = axi_local_attempt_v1_status(store.directory, store.root, &out);
    query_state = status_rc == AXI_LOCAL_ATTEMPT_V1_OK ? (int)out.state : -1;
    if (point == R80_CRASH_PARTIAL_RECORD) {
        CHECK(status_rc == AXI_LOCAL_ATTEMPT_V1_CORRUPT);
        CHECK(axi_local_attempt_v1_scan(store.directory, count_visit, &visits) == AXI_LOCAL_ATTEMPT_V1_CORRUPT);
        CHECK(visits == 0);
        rc = runtime80_store_commit(&store, &out);
        CHECK(rc == AXI_LOCAL_ATTEMPT_V1_CORRUPT && out.effect_performed == 0);
    } else {
        expected = point == R80_CRASH_EMPTY_RECORD ? AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED
                   : point >= R80_CRASH_TERMINAL_RENAME ? AXI_LOCAL_ATTEMPT_V1_COMMITTED
                   : AXI_LOCAL_ATTEMPT_V1_UNKNOWN;
        CHECK(status_rc == AXI_LOCAL_ATTEMPT_V1_OK && out.state == expected);
        CHECK(out.effect_performed == 0 && memcmp(out.grant_root, store.root, 32) == 0);
        CHECK(runtime80_store_scan(&store, expected == AXI_LOCAL_ATTEMPT_V1_NOT_ATTEMPTED ? 0 : 1, expected) == 0);
        rc = runtime80_store_commit(&store, &out);
        if (point == R80_CRASH_EMPTY_RECORD) {
            CHECK(rc == AXI_LOCAL_ATTEMPT_V1_OK && out.state == AXI_LOCAL_ATTEMPT_V1_COMMITTED);
            CHECK(out.effect_performed == 1 && runtime80_io_publishes() == 1);
            published = 1;
            CHECK(runtime80_store_commit(&store, &out) == AXI_LOCAL_ATTEMPT_V1_REFUSED);
            CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_COMMITTED && out.effect_performed == 0);
        } else {
            CHECK(rc == AXI_LOCAL_ATTEMPT_V1_REFUSED && out.state == expected);
            CHECK(out.effect_performed == 0 && runtime80_io_publishes() == 0);
        }
    }
    CHECK(runtime80_store_content(&store, (int)published) == 0);
    printf("{\"case\":\"store_process_interruption\",\"point\":%u,\"signal\":%u,"
           "\"query_rc\":%d,\"query_state\":%d,\"new_config_after_interruption\":%u,"
           "\"new_config_after_recovery\":%u,\"recovery_publishes\":%u}\n",
           point, (unsigned)WTERMSIG(child_status), status_rc, query_state,
           (unsigned)(point >= R80_CRASH_PAYLOAD_RENAME), published, runtime80_io_publishes());
    runtime80_io_detach();
    CHECK(runtime80_store_destroy(&store) == 0);
    return 0;
}

int main(void)
{
    unsigned point, repeat;
    for (repeat = 0; repeat < 3; repeat++)
        for (point = R80_CRASH_EMPTY_RECORD; point <= R80_CRASH_TERMINAL_RECORDS; point++)
            if (one(point)) return 1;
    printf("audit80 process interruption/recovery: %u checks PASS\n", checks);
    return 0;
}

