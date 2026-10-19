/* Exercise the actual CLI snapshot reader, including special-file refusal. */
#define main axi_test_cli_main
#include "../../src/axi_main.c"
#undef main

static unsigned checks;
#define CHECK(expr) do { checks++; if (!(expr)) { \
    fprintf(stderr, "driver:%d: %s\n", __LINE__, #expr); return 1; \
} } while (0)

int main(void)
{
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
    CHECK(unlink(path) == 0 && rmdir(dir) == 0);
    printf("audit driver: %u checks PASS\n", checks);
    return 0;
}
