/* Only axi_local_attempt_v1.c is compiled with these I/O names redirected. */
#include "runtime_store.h"
#include "axi_hash.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { ROLE_OTHER, ROLE_STORE, ROLE_RECORDS, ROLE_RECORD, ROLE_PAYLOAD, ROLE_TERMINAL };
static int store_fd = -1, event_fd = -1;
static char record_name[65];
static unsigned selected_fault, hits, payload_publishes, terminal_publishes, crash_point;

static int same(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

static int descriptor_role(int fd)
{
    struct stat st, entry;
    int records = -1, role = ROLE_OTHER, saved = errno;
    if (store_fd < 0 || fstat(fd, &st)) goto done;
    if (!fstat(store_fd, &entry) && same(&st, &entry)) { role = ROLE_STORE; goto done; }
    if (!fstatat(store_fd, ".tmp.attempt", &entry, AT_SYMLINK_NOFOLLOW) && same(&st, &entry)) {
        role = ROLE_PAYLOAD; goto done;
    }
    records = openat(store_fd, "records", O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (records < 0) goto done;
    if (!fstat(records, &entry) && same(&st, &entry)) { role = ROLE_RECORDS; goto done; }
    if (!fstatat(records, ".tmp.rec", &entry, AT_SYMLINK_NOFOLLOW) && same(&st, &entry)) {
        role = ROLE_TERMINAL; goto done;
    }
    if (!fstatat(records, record_name, &entry, AT_SYMLINK_NOFOLLOW) && same(&st, &entry)) role = ROLE_RECORD;
done:
    if (records >= 0) close(records);
    errno = saved;
    return role;
}

static void at_crash_point(unsigned point)
{
    if (crash_point == point) {
        uint8_t byte = (uint8_t)point;
        ssize_t n;
        do { n = write(event_fd, &byte, 1); } while (n < 0 && errno == EINTR);
        if (n != 1) _exit(91);
        kill(getpid(), SIGKILL); /* only the harness's own child process */
        _exit(92);
    }
}

int runtime80_io_attach(const runtime80_store *store)
{
    if (store_fd >= 0) return -1;
    store_fd = open(store->directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    axi_hash_hex(store->root, record_name);
    selected_fault = hits = payload_publishes = terminal_publishes = crash_point = 0;
    event_fd = -1;
    return store_fd >= 0 ? 0 : -1;
}

void runtime80_io_fault(unsigned fault) { selected_fault = fault; hits = 0; }
void runtime80_io_crash(unsigned point, int fd) { crash_point = point; event_fd = fd; }
void runtime80_io_detach(void)
{
    if (store_fd >= 0) close(store_fd);
    store_fd = -1; event_fd = -1; selected_fault = crash_point = 0;
}
unsigned runtime80_io_hits(void) { return hits; }
unsigned runtime80_io_publishes(void) { return payload_publishes; }

ssize_t runtime80_io_write(int fd, const void *bytes, size_t n)
{
    int role = descriptor_role(fd);
    ssize_t result;
    if (role == ROLE_RECORD) {
        at_crash_point(R80_CRASH_EMPTY_RECORD);
        if (crash_point == R80_CRASH_PARTIAL_RECORD) {
            result = write(fd, bytes, n > 7 ? 7 : n);
            if (result > 0) at_crash_point(R80_CRASH_PARTIAL_RECORD);
            return result;
        }
    }
    if (selected_fault == R80_IO_WRITE_EINTR && !hits) { hits++; errno = EINTR; return -1; }
    if ((selected_fault == R80_IO_PAYLOAD_ENOSPC && role == ROLE_PAYLOAD)
            || (selected_fault == R80_IO_TERMINAL_WRITE && role == ROLE_TERMINAL)) {
        if (!hits++) return write(fd, bytes, n > 1 ? n / 2 : n);
        errno = selected_fault == R80_IO_PAYLOAD_ENOSPC ? ENOSPC : EIO;
        return -1;
    }
    if (selected_fault == R80_IO_SHORT && n > 3) { hits++; n = 3; }
    result = write(fd, bytes, n);
    if (role == ROLE_RECORD && result == (ssize_t)n) at_crash_point(R80_CRASH_WRITTEN_RECORD);
    return result;
}

ssize_t runtime80_io_read(int fd, void *bytes, size_t n)
{
    if (selected_fault == R80_IO_READ_EINTR && !hits) { hits++; errno = EINTR; return -1; }
    if (selected_fault == R80_IO_SHORT && n > 3) { hits++; n = 3; }
    return read(fd, bytes, n);
}

int runtime80_io_fsync(int fd)
{
    int role = descriptor_role(fd), result;
    if (!hits && ((selected_fault == R80_IO_PAYLOAD_FSYNC && role == ROLE_PAYLOAD)
            || (selected_fault == R80_IO_TERMINAL_FSYNC && role == ROLE_TERMINAL)
            || (selected_fault == R80_IO_TERMINAL_DIRECTORY_FSYNC && role == ROLE_RECORDS
                && terminal_publishes))) {
        hits++; errno = EIO; return -1;
    }
    result = fsync(fd);
    if (result == 0) {
        if (role == ROLE_RECORD) at_crash_point(R80_CRASH_SPEND_FILE);
        if (role == ROLE_RECORDS) at_crash_point(terminal_publishes
                       ? R80_CRASH_TERMINAL_RECORDS : R80_CRASH_SPEND_RECORDS);
        if (role == ROLE_STORE) at_crash_point(payload_publishes
                       ? R80_CRASH_PAYLOAD_STORE : R80_CRASH_SPEND_STORE);
        if (role == ROLE_PAYLOAD) at_crash_point(R80_CRASH_PAYLOAD_FILE);
        if (role == ROLE_TERMINAL) at_crash_point(R80_CRASH_TERMINAL_FILE);
    }
    return result;
}

int runtime80_io_renameat(int from, const char *name, int to, const char *target)
{
    int payload = !strcmp(name, ".tmp.attempt"), terminal = !strcmp(name, ".tmp.rec");
    int result;
    if (!hits && ((selected_fault == R80_IO_PAYLOAD_RENAME && payload)
            || (selected_fault == R80_IO_TERMINAL_RENAME && terminal))) {
        hits++; errno = EIO; return -1;
    }
    result = renameat(from, name, to, target);
    if (result == 0 && payload) { payload_publishes++; at_crash_point(R80_CRASH_PAYLOAD_RENAME); }
    if (result == 0 && terminal) { terminal_publishes++; at_crash_point(R80_CRASH_TERMINAL_RENAME); }
    return result;
}

