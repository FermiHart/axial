/* ADR-059 AXV2-25: read-only VAP RF1 pins for the narrow profile.
 * Private C interface; no installed ABI promise. This adapter parses
 * canonical RF1 bytes and binds them to a content root the CALLER may
 * log; it proves nothing about truth, authority, freshness or
 * soundness, mints no facts or caps, and carries a fixed UNPROVEN
 * maturity by contract (there is no knob to raise it). Unknown records
 * are counted, never silently dropped. Shaping beyond framing (field
 * regexes, sort order, graph soundness) belongs to the VAP checker,
 * never to this envelope.
 */
#ifndef AXI_RF1_PIN_V1_H
#define AXI_RF1_PIN_V1_H

#include <stddef.h>
#include <stdint.h>

#define AXI_RF1_PIN_V1_MAX_BYTES 65536u
#define AXI_RF1_PIN_V1_OK 0
#define AXI_RF1_PIN_V1_REFUSED (-1)

typedef struct {
    uint8_t rf_root[32];
    uint32_t records;
    uint32_t unknowns;
} axi_rf1_pin_v1;

/* Parse canonical RF1. Refuses (no partial output): empty/oversize
 * input, missing or doubled final LF, CR/NUL/DEL/non-ASCII bytes,
 * bad header, unknown record kind, empty fields, out-of-order groups,
 * duplicate lines. Unknown records parse and increment unknowns.
 * Success fills *out with the domain-separated root
 * (SHA-256("BEYOND-RF1" + NUL + exact bytes)) and the counts. */
int axi_rf1_pin_v1_parse(const void *bytes, size_t len,
                         axi_rf1_pin_v1 *out);

#endif
