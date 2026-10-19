/* Deterministic primitive-work measurements; no wall-clock benchmark claims. */
#define main security_normal_main
#include "security.c"
#undef main
static size_t hash_calls, hash_bytes;
static size_t compare_calls;
static size_t allocation_calls, allocation_fail_at;

void audit_count_hash(const void *bytes, size_t n, uint8_t out[32])
{
    hash_calls++; hash_bytes += n;
    axi_sha256(bytes, n, out);
}

int audit_count_compare(const void *a, const void *b, size_t n)
{
    compare_calls++;
    return memcmp(a, b, n);
}

void *audit_count_malloc(size_t n)
{
    allocation_calls++;
    if (allocation_fail_at && allocation_calls == allocation_fail_at) return NULL;
    return malloc(n);
}

int main(int argc, char **argv)
{
    axi_delegation_v1 chain[AXI_DELEGATION_V1_MAX_DEPTH];
    axi_delegation_v1_authority root, wanted, got;
    axi_sd1_leaf leaf;
    uint8_t tag[32] = {1}, salt[32] = {2}, value[4096];
    char rf[65536];
    axi_rf1_pin_v1 pin;
    size_t rf_len;
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
    rf_len = rf_fixture(rf, sizeof rf, 2048);
    compare_calls = 0;
    CHECK(axi_rf1_pin_v1_parse(rf, rf_len, &pin) == AXI_RF1_PIN_V1_OK);
    printf("rf1_2048_records: comparisons=%zu bytes=%zu\n", compare_calls, rf_len);
    if (!report_only) CHECK(compare_calls < 60000);
    if (!report_only) {
        for (allocation_fail_at = 1; allocation_fail_at <= 2; allocation_fail_at++) {
            allocation_calls = 0; memset(&pin, 0xa5, sizeof pin);
            CHECK(axi_rf1_pin_v1_parse(rf, rf_len, &pin) == AXI_RF1_PIN_V1_REFUSED);
            CHECK(pin.records == 0 && pin.unknowns == 0);
        }
    }
    return 0;
}
