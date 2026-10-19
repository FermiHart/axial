/* Product-only fsync redirection: real time advances, identities stay real. */
#define main audit80_ordinary_main
#include "security.c"
#undef main

static int delay_mode, delay_done;

int audit80_fsync(int fd)
{
    char link[64], path[512];
    ssize_t n;
    int rc = fsync(fd), selected = 0;
    if (rc != 0 || !delay_mode || delay_done) return rc;
    CHECK(snprintf(link, sizeof link, "/proc/self/fd/%d", fd) > 0);
    n = readlink(link, path, sizeof path - 1);
    CHECK(n >= 0 && (size_t)n < sizeof path - 1); path[n] = 0;
    if (delay_mode == 1 && strstr(path, "/records/") != NULL) selected = 1;
    if (delay_mode == 2 && strstr(path, "/.tmp.attempt") != NULL) selected = 1;
    if (selected) { delay_done = 1; expire_pause(); }
    return rc;
}

static void delayed_expiry(int mode)
{
    fixture f;
    axi_local_authority_v1 *owner = NULL;
    axi_local_authority_v1_prepared *prepared;
    axi_local_attempt_v1_outcome out;
    new_fixture(&f); provision(&f);
    CHECK(axi_local_authority_v1_enable(f.dir, f.pk) == 0);
    CHECK(axi_local_authority_v1_open(f.dir, &owner) == 0);
    f.action.ttl_ns = UINT64_C(1000000000);
    prepared = ready(&f, owner);
    delay_mode = mode; delay_done = 0;
    CHECK(axi_local_authority_v1_commit(prepared, f.grant, sizeof f.grant, 0, &out)
            == AXI_LOCAL_AUTHORITY_V1_REFUSED);
    CHECK(delay_done == 1 && out.state == AXI_LOCAL_ATTEMPT_V1_UNKNOWN && !out.effect_performed);
    delay_mode = 0;
    CHECK(!exists(f.dir, "config") && !exists(f.dir, ".tmp.attempt"));
    CHECK(axi_local_attempt_v1_status(f.dir, f.grant_root, &out) == 0);
    CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_UNKNOWN && !out.effect_performed);
    CHECK(axi_local_authority_v1_commit(prepared, f.grant, sizeof f.grant, 0, &out)
            == AXI_LOCAL_AUTHORITY_V1_REFUSED);
    CHECK(out.state == AXI_LOCAL_ATTEMPT_V1_UNKNOWN && !out.effect_performed);
    axi_local_authority_v1_prepared_close(prepared); axi_local_authority_v1_close(owner);
    rm_fixture(f.dir);
}

int main(void)
{
    int rc = setup_host();
    if (rc) return rc;
    delayed_expiry(1); delayed_expiry(2);
    printf("audit80 security faults: %u checks PASS (real-clock expiry)\n", checks);
    return 0;
}
