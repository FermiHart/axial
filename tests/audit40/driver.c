/* Exercise the actual CLI snapshot reader, including special-file refusal. */
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

static const char *watched_source;
static unsigned source_opens;
static int audited_open(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (watched_source && strcmp(path, watched_source) == 0) source_opens++;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return open(path, flags, mode);
}
#define open audited_open
#define main axi_test_cli_main
#include "../../src/axi_main.c"
#undef main
#undef open

static unsigned checks;
#define CHECK(expr) do { checks++; if (!(expr)) { \
    fprintf(stderr, "driver:%d: %s\n", __LINE__, #expr); return 1; \
} } while (0)

int main(void)
{
    static const char source[] =
        "cell hello : fn(a: u64, b: u64) -> u64\n"
        "  fuel 10_000\n  pure\n{\n  let n = a + b\n  ret n\n}\n";
    char dir[] = "/tmp/axi-driver.XXXXXX", path[256];
    char *bytes;
    size_t n = 99;
    int fd;
    CHECK(mkdtemp(dir) != NULL);
    CHECK(snprintf(path, sizeof path, "%s/source", dir) > 0);
    fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
    CHECK(fd >= 0);
    CHECK(write(fd, "abc", 3) == 3);
    bytes = read_file(path, &n);
    CHECK(bytes && n == 3 && memcmp(bytes, "abc\0", 4) == 0);
    free(bytes);
    CHECK(ftruncate(fd, 0) == 0);
    bytes = read_file(path, &n);
    CHECK(bytes && n == 0 && bytes[0] == '\0');
    free(bytes);
    CHECK(ftruncate(fd, (off_t)AXI_CLI_FILE_MAX + 1) == 0);
    CHECK(read_file(path, &n) == NULL && n == 0 && errno == EFBIG);
    CHECK(close(fd) == 0 && unlink(path) == 0);
    CHECK(read_file(NULL, &n) == NULL && n == 0);
    CHECK(read_file(dir, &n) == NULL && n == 0);
    CHECK(read_file("/dev/null", &n) == NULL && n == 0);
    CHECK(mkfifo(path, 0600) == 0);
    alarm(2); /* A FIFO must be refused before waiting for a writer. */
    CHECK(read_file(path, &n) == NULL && n == 0);
    alarm(0);
    CHECK(unlink(path) == 0);
    fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
    CHECK(fd >= 0 && write(fd, source, sizeof source - 1) == sizeof source - 1);
    CHECK(close(fd) == 0);
    {
        axi_node *unit;
        char *snapshot = NULL, *canonical;
        watched_source = path;
        source_opens = 0;
        unit = load_unit_or_null(path, &snapshot, 0);
        watched_source = NULL;
        CHECK(unit != NULL && snapshot != NULL);
        CHECK(source_opens == 1); /* Check and projection share one read. */
        CHECK(unlink(path) == 0);
        canonical = axi_canon_render(snapshot, strlen(snapshot), unit);
        CHECK(canonical && strcmp(canonical, source) == 0);
        free(canonical);
        axi_ast_free(unit);
        free(snapshot);
    }
    CHECK(rmdir(dir) == 0);
    printf("audit driver: %u checks PASS\n", checks);
    return 0;
}
