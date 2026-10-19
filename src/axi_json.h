/* axial — bounded JSON parser (W12 / CA12). Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0
 *
 * INV-322... AXI-INV-105 / INV-323: no consumer may interpret bytes the
 * parser did not accept. The document is parsed in full before any value is
 * extracted: trailing garbage, truncation, duplicate keys, raw control bytes
 * in strings, malformed escapes and numbers, and depth past the bound are all
 * the same answer — refusal. A policy never decides over a partial value.
 */
#ifndef AXI_JSON_H
#define AXI_JSON_H

#include <stddef.h>

#define AXI_JSON_SCRATCH_SIZE 65536u
/* Shared bound for repeated scans, independent of nesting/duplicate layout. */
#define AXI_JSON_WORK_LIMIT (8u * 1024u * 1024u)

typedef int (*axi_json_sink)(void *ctx, const char *bytes, size_t len);

/* JSON string-body escaper. Input is an arbitrary byte slice, including NUL.
 * Valid UTF-8 is preserved; controls and invalid bytes become ASCII escapes. */
int axi_json_escape(const char *bytes, size_t len,
                    axi_json_sink sink, void *ctx);

/* Validate a complete JSON document. 0 = well-formed, -1 = refused. */
int axi_json_validate(const char *doc, size_t len);

/* Extract a path ("$.a.b[0]") from a VALID document. Strings are returned
 * with v0 ASCII escapes decoded; every other type is its raw validated slice.
 * The result borrows the immutable document or CALLER-owned scratch. No TLS.
 * Do not alias scratch with input or result storage. 0 = found, -1 = refused. */
int axi_json_get(const char *doc, size_t len, const char *path, size_t plen,
                 char *scratch, size_t scratch_cap,
                 const char **out, size_t *outlen);

/* Opt-in typed view: kind is never inferred from decoded text. Complete
 * validation precedes lookup. Missing/invalid preserve *out. Scratch may change
 * on refusal. Bytes are borrowed; caller owns lifetime and exclusive scratch.
 * No claim about the provenance/truth of a fact follows from its JSON type. */
typedef enum {
    AXI_JSON_STRING = 1, AXI_JSON_NUMBER, AXI_JSON_BOOLEAN,
    AXI_JSON_NULL, AXI_JSON_ARRAY, AXI_JSON_OBJECT
} axi_json_kind;
typedef struct {
    axi_json_kind kind;
    const char *bytes;
    size_t length;
} axi_json_value;
enum { AXI_JSON_FOUND = 0, AXI_JSON_MISSING = 1, AXI_JSON_INVALID = -1 };
int axi_json_get_typed(const char *doc, size_t len, const char *path, size_t plen,
                       char *scratch, size_t scratch_cap, axi_json_value *out);

#endif /* AXI_JSON_H */
