/* axial — capability effect table (ADR-007). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * This table maps Capability Kind -> Effect -> Host Verb, and the closed
 * (cap, method) -> effect ABI of v0. It is the SINGLE SOURCE OF TRUTH for
 * cap inference, cap-method typechecking and codegen.
 * GENERATED from docs/CAP-METHODS.tsv by tools/gen_cap_table.py.
 * DO NOT EDIT BY HAND — regenerate. /AXI-INV-100/
 */
#ifndef AXI_CAP_TABLE_H
#define AXI_CAP_TABLE_H

#include <stdint.h>
#include <stddef.h>

#define AXI_CAP_MAX  32     /* max distinct capabilities */

typedef enum {
    CAP_NONE = 0,
    CAP_FS_READ,
    CAP_FS_WRITE,
    CAP_FS_METADATA,
    CAP_ENV_READ,
    CAP_ENV_WRITE,
    CAP_PROC_INSPECT,
    CAP_PROC_SPAWN,
    CAP_NET_CONNECT,
    CAP_NET_BIND,
    CAP_NET_READ,
    CAP_NET_WRITE,
    CAP_NET_CLOSE,
    CAP_TIME_NOW,
    CAP_CRYPTO_HASH,
    CAP_SIGIL_ATTEST,
    CAP_IO_WRITE,
    CAP__COUNT
} axi_cap_kind;

/* Map capability -> host verb string (for --cap grant names) */
typedef struct {
    axi_cap_kind kind;
    const char *host_verb;     /* e.g., "fs.Read" */
    const char *cap_name;      /* e.g., "fs.Read" (same as host verb in v0) */
} axi_cap_info;

/* The closed v0 method ABI: one scalar str argument, one scalar return.
 * A method absent from this table does not exist; typechecking,
 * inference and codegen must all refuse it through THIS lookup. */
typedef struct {
    axi_cap_kind cap;
    const char *method;   /* source name: read, write, hash */
    const char *effect;   /* .eff table name == host verb */
    const char *ret;      /* "str" | "u64" */
} axi_cap_method;

const axi_cap_info *axi_cap_info_by_kind(axi_cap_kind k);
const char *axi_cap_name(axi_cap_kind k);  /* "fs.Read" etc */
axi_cap_kind axi_cap_kind_by_name(const char *name, size_t len);  /* "fs.Read" -> CAP_FS_READ */
const char *axi_cap_host_verb(axi_cap_kind k);
const axi_cap_method *axi_cap_method_find(axi_cap_kind cap,
                                          const char *method, size_t len);

/* Return number of distinct capabilities */
size_t axi_cap_count(void);

#endif /* AXI_CAP_TABLE_H */
