/* Host mint/spend adapter. Verification uses axi_ag1_core_v1.c on every target. */
#include "axi_ag1_v1.h"
#include "axi_ag1_crypto_v1.h"
#include "axi_hash.h"
#include "axi_wipe.h"
#include "ed25519.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int axi_ag1_crypto_hash(const void *bytes, size_t size, uint8_t out[32])
{
    axi_sha256(bytes, size, out); return 0;
}
int axi_ag1_crypto_verify(const uint8_t sig[64], const uint8_t *message,
                          size_t size, const uint8_t pk[32])
{
    if (size > UINT32_MAX) return -1;
    return ed25519_verify(sig, message, (uint32_t)size, pk);
}
int axi_ag1_v1_encode_signed(const axi_ag1_v1 *g, const uint8_t seed[32],
                              uint8_t out[AXI_AG1_V1_SIGNED_SIZE])
{
    uint8_t sk[64], msg[AXI_AG1_V1_SIG_MSG_SIZE];
    int rc;
    if (!g || !seed || !out || axi_ag1_v1_encode(g, out) != 0) return -1;
    memcpy(out + AXI_AG1_V1_BODY_SIZE, "AG1S", 4);
    out[AXI_AG1_V1_BODY_SIZE + 4] = 0; out[AXI_AG1_V1_BODY_SIZE + 5] = 0;
    out[AXI_AG1_V1_BODY_SIZE + 6] = 0; out[AXI_AG1_V1_BODY_SIZE + 7] = 1;
    ed25519_keypair_from_seed(seed, out + AXI_AG1_V1_BODY_SIZE + 8, sk);
    rc = axi_ag1_signature_message(out, msg);
    if (rc == 0) rc = ed25519_sign(out + AXI_AG1_V1_BODY_SIZE + 40, msg, sizeof msg, sk);
    axi_private_wipe(sk, sizeof sk);
    return rc == 0 ? 0 : -1;
}
static int root_zero(const uint8_t root[32])
{
    size_t i;
    for (i = 0; i < 32; ++i) if (root[i]) return 0;
    return 1;
}
static void hex32(const uint8_t root[32], char out[65])
{
    static const char hex[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < 32; ++i) { out[i * 2] = hex[root[i] >> 4]; out[i * 2 + 1] = hex[root[i] & 15]; }
    out[64] = 0;
}
int axi_ag1_v1_consume_spent(const char *directory, const uint8_t root[32])
{
    char name[71];
    int dfd, fd, rc = -1;
    size_t off = 0;
    struct stat st;
    if (!directory || !*directory || !root || root_zero(root)) return -1;
    hex32(root, name); memcpy(name + 64, ".spent", 7);
    dfd = open(directory, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) return -1;
    if (fstat(dfd, &st) != 0 || !S_ISDIR(st.st_mode)) goto done;
    fd = openat(dfd, name, O_WRONLY | O_CREAT | O_EXCL, 0444);
    if (fd < 0) { rc = errno == EEXIST ? 1 : -1; goto done; }
    while (off < 32) {
        ssize_t n = write(fd, root + off, 32 - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        off += (size_t)n;
    }
    if (off == 32 && fsync(fd) == 0) rc = 0;
    if (close(fd) != 0) rc = -1;
    if (rc == 0) { if (fsync(dfd) != 0) rc = -1; }
    else (void)unlinkat(dfd, name, 0);
done:
    (void)close(dfd); return rc;
}
