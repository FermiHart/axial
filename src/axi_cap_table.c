/* axial — capability effect table (ADR-007). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * GENERATED from docs/CAP-METHODS.tsv by tools/gen_cap_table.py.
 * DO NOT EDIT BY HAND — regenerate. /AXI-INV-100/
 */
#include "axi_cap_table.h"
#include <string.h>
#include <stdint.h>

static const axi_cap_info CAP_INFO[CAP__COUNT] = {
    [CAP_NONE] = { CAP_NONE, "", "" },
    [CAP_FS_READ] = { CAP_FS_READ, "fs.Read", "fs.Read" },
    [CAP_FS_WRITE] = { CAP_FS_WRITE, "fs.Write", "fs.Write" },
    [CAP_FS_METADATA] = { CAP_FS_METADATA, "fs.Metadata", "fs.Metadata" },
    [CAP_ENV_READ] = { CAP_ENV_READ, "env.Read", "env.Read" },
    [CAP_ENV_WRITE] = { CAP_ENV_WRITE, "env.Write", "env.Write" },
    [CAP_PROC_INSPECT] = { CAP_PROC_INSPECT, "proc.Inspect", "proc.Inspect" },
    [CAP_PROC_SPAWN] = { CAP_PROC_SPAWN, "proc.Spawn", "proc.Spawn" },
    [CAP_NET_CONNECT] = { CAP_NET_CONNECT, "net.Connect", "net.Connect" },
    [CAP_NET_BIND] = { CAP_NET_BIND, "net.Bind", "net.Bind" },
    [CAP_NET_READ] = { CAP_NET_READ, "net.Read", "net.Read" },
    [CAP_NET_WRITE] = { CAP_NET_WRITE, "net.Write", "net.Write" },
    [CAP_NET_CLOSE] = { CAP_NET_CLOSE, "net.Close", "net.Close" },
    [CAP_TIME_NOW] = { CAP_TIME_NOW, "time.Now", "time.Now" },
    [CAP_CRYPTO_HASH] = { CAP_CRYPTO_HASH, "crypto.Hash", "crypto.Hash" },
    [CAP_SIGIL_ATTEST] = { CAP_SIGIL_ATTEST, "sigil.Attest", "sigil.Attest" },
    [CAP_IO_WRITE] = { CAP_IO_WRITE, "io.Write", "io.Write" },
};

/* The closed method set. v0 keeps exactly one method per effect whose
 * host frame is a single bounded str; effects with compound frames
 * (fs.Write path|content, net.*, proc.Spawn argv) have NO method until
 * the frame encoding is part of the generated spec. A cap without a
 * method row rejects every method call at typecheck time. */
static const axi_cap_method CAP_METHODS[] = {
    { CAP_FS_READ, "read", "fs.Read", "str" },
    { CAP_CRYPTO_HASH, "hash", "crypto.Hash", "str" },
    { CAP_IO_WRITE, "write", "io.Write", "u64" },
};

const axi_cap_info *axi_cap_info_by_kind(axi_cap_kind k)
{
    return ((unsigned)k < (unsigned)CAP__COUNT) ? &CAP_INFO[(unsigned)k] : NULL;
}

const char *axi_cap_name(axi_cap_kind k)
{
    const axi_cap_info *ci = axi_cap_info_by_kind(k);
    return ci ? ci->cap_name : "";
}

axi_cap_kind axi_cap_kind_by_name(const char *name, size_t len)
{
    for (int i = 1; i < CAP__COUNT; i++) {
        const axi_cap_info *ci = &CAP_INFO[i];
        if (strlen(ci->cap_name) == len && memcmp(ci->cap_name, name, len) == 0)
            return (axi_cap_kind)i;
    }
    return CAP_NONE;
}

const char *axi_cap_host_verb(axi_cap_kind k)
{
    const axi_cap_info *ci = axi_cap_info_by_kind(k);
    return ci ? ci->host_verb : "";
}

const axi_cap_method *axi_cap_method_find(axi_cap_kind cap,
                                          const char *method, size_t len)
{
    for (size_t i = 0; i < sizeof CAP_METHODS / sizeof CAP_METHODS[0]; i++) {
        const axi_cap_method *m = &CAP_METHODS[i];
        if (m->cap == cap && strlen(m->method) == len
                && memcmp(m->method, method, len) == 0)
            return m;
    }
    return NULL;
}

size_t axi_cap_count(void)
{
    return CAP__COUNT - 1;  /* exclude CAP_NONE */
}
