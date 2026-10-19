/* Deterministic primitive-work measurements; no wall-clock benchmark claims. */
#define main security_normal_main
#include "security.c"
#undef main
static size_t hash_calls, hash_bytes;

void audit_count_hash(const void *bytes, size_t n, uint8_t out[32])
{
    hash_calls++; hash_bytes += n;
    axi_sha256(bytes, n, out);
}

int main(int argc, char **argv)
{
    axi_delegation_v1 chain[AXI_DELEGATION_V1_MAX_DEPTH];
    axi_delegation_v1_authority root, wanted, got;
    axi_sd1_leaf leaf;
    uint8_t tag[32] = {1}, salt[32] = {2}, value[4096];
    int report_only = argc == 2 && strcmp(argv[1], "report") == 0;
    memset(value, 7, sizeof value);
    hash_calls = hash_bytes = 0;
    CHECK(axi_sd1_make_leaf(&leaf, AXI_SD1_PROTECTED, 1, tag, 0, salt, value, sizeof value) == 0);
    printf("selective_disclosure_4096: hashes=%zu bytes=%zu\n", hash_calls, hash_bytes);
    if (!report_only) CHECK(hash_calls == 2);
    chain_fixture(chain, &root, &wanted);
    hash_calls = hash_bytes = 0;
    CHECK(axi_delegation_v1_verify_chain(chain, AXI_DELEGATION_V1_MAX_DEPTH, &root, &got) == 0);
    CHECK(memcmp(&got, &wanted, sizeof got) == 0);
    printf("delegation_depth_32: hashes=%zu bytes=%zu\n", hash_calls, hash_bytes);
    if (!report_only) CHECK(hash_calls == AXI_DELEGATION_V1_MAX_DEPTH);
    return 0;
}
