/* Phase probe: instrumented sequential lifecycle, never a throughput claim. */
#include "runtime_fixture.h"
#include "axi_hash.h"
#include "ed25519.h"
#include <stdio.h>
#include <stdlib.h>

static unsigned enabled;
static uint64_t hash_ns, hash_calls, hash_bytes, signature_ns, signature_calls;
void __real_axi_sha256(const void *, size_t, uint8_t[32]);
int __real_ed25519_verify(const uint8_t[64], const uint8_t *, uint32_t, const uint8_t[32]);

void __wrap_axi_sha256(const void *bytes, size_t len, uint8_t out[32])
{
    uint64_t before = enabled ? runtime80_now_ns() : 0;
    __real_axi_sha256(bytes, len, out);
    if (enabled) {
        hash_ns += runtime80_now_ns() - before;
        hash_calls++; hash_bytes += len;
    }
}

int __wrap_ed25519_verify(const uint8_t sig[64], const uint8_t *bytes,
                          uint32_t len, const uint8_t pk[32])
{
    uint64_t before = enabled ? runtime80_now_ns() : 0;
    int rc = __real_ed25519_verify(sig, bytes, len, pk);
    if (enabled) { signature_ns += runtime80_now_ns() - before; signature_calls++; }
    return rc;
}

int main(int argc, char **argv)
{
    runtime80_fixture fixture;
    axi_embed_v1_context *context;
    unsigned count = 100, i, cells = 13, laws = 0;
    uint64_t total_ns = 0, before;
    if (argc == 4) {
        cells = (unsigned)strtoul(argv[1], NULL, 10);
        laws = (unsigned)strtoul(argv[2], NULL, 10);
        count = (unsigned)strtoul(argv[3], NULL, 10);
    } else if (argc != 1) return 2;
    if (!count || count > 10000 || runtime80_fixture_init(&fixture, cells, laws)) return 2;
    if (runtime80_context(&fixture, laws ? AXI_EMBED_V1_ADMIT_CHECKED
                          : AXI_EMBED_V1_ADMIT_SIGNATURE_VALID, &context)) return 1;
    axi_embed_v1_context_destroy(context);
    for (i = 0; i < count; i++) {
        enabled = 1; before = runtime80_now_ns();
        if (runtime80_context(&fixture, laws ? AXI_EMBED_V1_ADMIT_CHECKED
                              : AXI_EMBED_V1_ADMIT_SIGNATURE_VALID, &context)) return 1;
        total_ns += runtime80_now_ns() - before; enabled = 0;
        axi_embed_v1_context_destroy(context);
    }
    printf("{\"case\":\"context_phase_profile\",\"cells\":%u,\"laws\":%u,\"iterations\":%u,"
           "\"total_ns\":%llu,\"sha256_ns\":%llu,\"sha256_calls\":%llu,\"sha256_bytes\":%llu,"
           "\"ed25519_verify_ns\":%llu,\"ed25519_verify_calls\":%llu}\n", cells, laws, count,
           (unsigned long long)total_ns, (unsigned long long)hash_ns,
           (unsigned long long)hash_calls, (unsigned long long)hash_bytes,
           (unsigned long long)signature_ns, (unsigned long long)signature_calls);
    runtime80_fixture_free(&fixture);
    return signature_calls == count && hash_calls > count ? 0 : 1;
}

