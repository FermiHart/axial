#include "axi_coverage_v1.h"

#include "axi_hash.h"

#include <string.h>

static const axi_coverage_v1_row COVERAGE[] = {
    { AXI_COVERAGE_V1_CLASS_HOST_EFFECT, "crypto.Hash", 1, AXI_COVERAGE_V1_OPACITY_CLEAR, AXI_COVERAGE_V1_SUPPORT_SUPPORTED, AXI_COVERAGE_V1_MATURITY_CHECKED },
    { AXI_COVERAGE_V1_CLASS_HOST_EFFECT, "fs.Read", 1, AXI_COVERAGE_V1_OPACITY_CLEAR, AXI_COVERAGE_V1_SUPPORT_SUPPORTED, AXI_COVERAGE_V1_MATURITY_CHECKED },
    { AXI_COVERAGE_V1_CLASS_HOST_EFFECT, "fs.Write", 1, AXI_COVERAGE_V1_OPACITY_CLEAR, AXI_COVERAGE_V1_SUPPORT_SUPPORTED, AXI_COVERAGE_V1_MATURITY_CHECKED },
    { AXI_COVERAGE_V1_CLASS_HOST_EFFECT, "io.Write", 1, AXI_COVERAGE_V1_OPACITY_CLEAR, AXI_COVERAGE_V1_SUPPORT_SUPPORTED, AXI_COVERAGE_V1_MATURITY_CHECKED },
    { AXI_COVERAGE_V1_CLASS_HOST_EFFECT, "net.Close", 1, AXI_COVERAGE_V1_OPACITY_CLEAR, AXI_COVERAGE_V1_SUPPORT_SUPPORTED, AXI_COVERAGE_V1_MATURITY_CHECKED },
    { AXI_COVERAGE_V1_CLASS_HOST_EFFECT, "net.Connect", 1, AXI_COVERAGE_V1_OPACITY_CLEAR, AXI_COVERAGE_V1_SUPPORT_SUPPORTED, AXI_COVERAGE_V1_MATURITY_CHECKED },
    { AXI_COVERAGE_V1_CLASS_HOST_EFFECT, "net.Read", 1, AXI_COVERAGE_V1_OPACITY_CLEAR, AXI_COVERAGE_V1_SUPPORT_SUPPORTED, AXI_COVERAGE_V1_MATURITY_CHECKED },
    { AXI_COVERAGE_V1_CLASS_HOST_EFFECT, "net.Write", 1, AXI_COVERAGE_V1_OPACITY_CLEAR, AXI_COVERAGE_V1_SUPPORT_SUPPORTED, AXI_COVERAGE_V1_MATURITY_CHECKED },
    { AXI_COVERAGE_V1_CLASS_HOST_EFFECT, "proc.Spawn", 1, AXI_COVERAGE_V1_OPACITY_CLEAR, AXI_COVERAGE_V1_SUPPORT_SUPPORTED, AXI_COVERAGE_V1_MATURITY_CHECKED },
};

size_t axi_coverage_v1_manifest_count(void)
{
    return sizeof COVERAGE / sizeof COVERAGE[0];
}

const axi_coverage_v1_row *axi_coverage_v1_manifest_at(size_t index)
{
    return index < axi_coverage_v1_manifest_count() ? &COVERAGE[index] : NULL;
}

int axi_coverage_v1_classify(const char *door, axi_coverage_v1_row *out)
{
    size_t i;
    if (!door || !*door) return -1;
    for (i = 0; i < axi_coverage_v1_manifest_count(); i++) {
        if (strcmp(COVERAGE[i].door, door) == 0) {
            if (out) *out = COVERAGE[i];
            return 0;
        }
    }
    return -1;
}

int axi_coverage_v1_verify_runtime(void)
{
    size_t i;
    if (axi_host_eff_count() != axi_coverage_v1_manifest_count()) return -1;
    for (i = 0; i < axi_coverage_v1_manifest_count(); i++) {
        if (i && strcmp(COVERAGE[i - 1].door, COVERAGE[i].door) >= 0) return -1;
        if (!axi_host_eff_find(COVERAGE[i].door)) return -1;
    }
    for (i = 0; i < axi_host_eff_count(); i++) {
        const axi_host_eff *host = axi_host_eff_at(i);
        if (!host || axi_coverage_v1_classify(host->name, NULL) != 0) return -1;
    }
    return 0;
}

int axi_coverage_v1_runtime_root(uint8_t out[32])
{
    uint8_t bytes[sizeof(AXI_COVERAGE_V1_DOMAIN) + 2
        + (AXI_CAPNAME + 5) * (sizeof COVERAGE / sizeof COVERAGE[0])];
    size_t off = 0, i, j;
    if (!out || axi_coverage_v1_verify_runtime() != 0) return -1;
    memcpy(bytes + off, AXI_COVERAGE_V1_DOMAIN, sizeof(AXI_COVERAGE_V1_DOMAIN));
    off += sizeof(AXI_COVERAGE_V1_DOMAIN);
    bytes[off++] = (uint8_t)(axi_coverage_v1_manifest_count() >> 8);
    bytes[off++] = (uint8_t)axi_coverage_v1_manifest_count();
    for (i = 0; i < axi_coverage_v1_manifest_count(); i++) {
        bytes[off++] = COVERAGE[i].action_class;
        for (j = 0; j < AXI_CAPNAME; j++) bytes[off++] = (uint8_t)COVERAGE[i].door[j];
        bytes[off++] = COVERAGE[i].receipt_required;
        bytes[off++] = COVERAGE[i].opacity;
        bytes[off++] = COVERAGE[i].support;
        bytes[off++] = COVERAGE[i].maturity;
    }
    axi_sha256(bytes, off, out);
    return 0;
}

void axi_coverage_v1_channel_init(axi_coverage_v1_channel *channel,
                                  const uint8_t channel_id[32])
{
    if (!channel) return;
    memset(channel, 0, sizeof *channel);
    if (channel_id) memcpy(channel->channel_id, channel_id, 32);
}

int axi_coverage_v1_channel_reserve(axi_coverage_v1_channel *channel,
                                    uint64_t *seq_out)
{
    if (!channel || channel->high_water >= AXI_COVERAGE_V1_MAX_CHANNEL) return -1;
    channel->high_water++;
    if (seq_out) *seq_out = channel->high_water;
    return 0;
}

int axi_coverage_v1_channel_terminal(axi_coverage_v1_channel *channel,
                                     uint64_t seq)
{
    if (!channel || seq == 0 || seq > channel->high_water
            || seq > AXI_COVERAGE_V1_MAX_CHANNEL)
        return -1;
    channel->terminal[seq - 1] = 1;
    return 0;
}

int axi_coverage_v1_channel_has_gap(const axi_coverage_v1_channel *channel)
{
    uint64_t i;
    if (!channel || channel->high_water > AXI_COVERAGE_V1_MAX_CHANNEL) return 1;
    for (i = 0; i < channel->high_water; i++)
        if (!channel->terminal[i]) return 1;
    return 0;
}

int axi_coverage_v1_channel_root(const axi_coverage_v1_channel *channel,
                                 uint8_t out[32])
{
    uint8_t bytes[sizeof(AXI_COVERAGE_V1_CHANNEL_DOMAIN) + 32 + 8
        + AXI_COVERAGE_V1_MAX_CHANNEL];
    size_t off = 0;
    int i;
    if (!channel || !out || channel->high_water > AXI_COVERAGE_V1_MAX_CHANNEL)
        return -1;
    memcpy(bytes + off, AXI_COVERAGE_V1_CHANNEL_DOMAIN,
           sizeof(AXI_COVERAGE_V1_CHANNEL_DOMAIN));
    off += sizeof(AXI_COVERAGE_V1_CHANNEL_DOMAIN);
    memcpy(bytes + off, channel->channel_id, 32); off += 32;
    for (i = 7; i >= 0; i--) bytes[off++] = (uint8_t)(channel->high_water >> (i * 8));
    memcpy(bytes + off, channel->terminal, AXI_COVERAGE_V1_MAX_CHANNEL);
    off += AXI_COVERAGE_V1_MAX_CHANNEL;
    axi_sha256(bytes, off, out);
    return 0;
}
