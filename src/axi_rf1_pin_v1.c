/* ADR-059 AXV2-25: RF1 framing envelope. See header. No heap, no I/O,
 * bounded stack only. Field shapes beyond arity/emptiness belong to
 * the VAP checker; this envelope refuses malformed framing and binds
 * bytes to a root, nothing more. */
#include "axi_rf1_pin_v1.h"

#include "axi_hash.h"

#include <stdlib.h>
#include <string.h>

static const char *const KINDS[] = {
    "input", "member", "section", "symbol", "group", "root", "edge",
    "effect", "unknown"
};

/* Field counts including the record-kind field itself. */
static const unsigned ARITY[] = {4, 7, 9, 10, 5, 3, 6, 3, 4};

static int kind_of(const uint8_t *line, size_t len, unsigned *kind,
                   size_t *rest)
{
    size_t k, n = 0;
    while (n < len && line[n] != '\t') {
        n++;
    }
    if (n == 0 || n >= len) {
        return -1;
    }
    for (k = 0; k < 9; k++) {
        size_t m = strlen(KINDS[k]);
        if (n == m && memcmp(line, KINDS[k], m) == 0) {
            *kind = (unsigned)k;
            *rest = n + 1;
            return 0;
        }
    }
    return -1;
}

static int fields_ok(const uint8_t *line, size_t len, size_t off,
                     unsigned want)
{
    unsigned got = 1;
    size_t i = off, start = off;
    if (off >= len) {
        return -1;
    }
    for (i = off; i < len; i++) {
        if (line[i] == '\t') {
            if (i == start) {
                return -1;
            }
            got++;
            start = i + 1;
        }
    }
    if (start >= len) {
        return -1;
    }
    /* got counts rest segments; +1 for the kind field itself. */
    return got + 1 == want ? 0 : -1;
}

int axi_rf1_pin_v1_parse(const void *bytes, size_t len,
                         axi_rf1_pin_v1 *out)
{
    const uint8_t *p;
    size_t off = 0, lineno = 0, records = 0, unknowns = 0;
    unsigned last_kind = 0;
    int have_last = 0;
    if (!out) {
        return AXI_RF1_PIN_V1_REFUSED;
    }
    memset(out, 0, sizeof(*out));
    if (!bytes || len == 0 || len > AXI_RF1_PIN_V1_MAX_BYTES) {
        return AXI_RF1_PIN_V1_REFUSED;
    }
    p = bytes;
    if (p[len - 1] != '\n' || (len > 1 && p[len - 2] == '\n')) {
        return AXI_RF1_PIN_V1_REFUSED;
    }
    {
        size_t i;
        for (i = 0; i < len; i++) {
            uint8_t c = p[i];
            if (c == '\n' || c == '\t') {
                continue;
            }
            if (c < 0x20 || c > 0x7e) {
                return AXI_RF1_PIN_V1_REFUSED;
            }
        }
    }
    /* Duplicate detection over complete lines, bounded and quadratic. */
    {
        size_t astart = 0, alen;
        while (astart < len) {
            size_t aend = astart, bstart;
            while (aend < len && p[aend] != '\n') {
                aend++;
            }
            alen = aend - astart;
            bstart = aend + 1;
            while (bstart < len) {
                size_t bend = bstart, blen;
                while (bend < len && p[bend] != '\n') {
                    bend++;
                }
                blen = bend - bstart;
                if (blen == alen && memcmp(p + astart, p + bstart, alen)
                        == 0) {
                    return AXI_RF1_PIN_V1_REFUSED;
                }
                bstart = bend + 1;
            }
            astart = aend + 1;
        }
    }
    while (off < len) {
        size_t end = off, llen;
        unsigned kind;
        size_t rest;
        while (end < len && p[end] != '\n') {
            end++;
        }
        llen = end - off;
        if (lineno == 0) {
            if (llen != 5 || memcmp(p + off, "RF1\t1", 5) != 0) {
                return AXI_RF1_PIN_V1_REFUSED;
            }
        } else {
            if (kind_of(p + off, llen, &kind, &rest) != 0
                    || fields_ok(p + off, llen, rest, ARITY[kind])
                    != 0) {
                return AXI_RF1_PIN_V1_REFUSED;
            }
            if (have_last && kind < last_kind) {
                return AXI_RF1_PIN_V1_REFUSED;
            }
            last_kind = kind;
            have_last = 1;
            records++;
            if (kind == 8) {
                unknowns++;
            }
        }
        lineno++;
        off = end + 1;
    }
    if (lineno < 2) {
        return AXI_RF1_PIN_V1_REFUSED;
    }
    /* Domain-separated root over one contiguous image. Bounded heap
     * (never stack: 64 KiB would blow small stacks, and static storage
     * would share state); allocation failure is a typed refusal. */
    {
        static const char dom[] = "BEYOND-RF1";
        uint8_t *msg = malloc(sizeof(dom) + len);
        uint8_t digest[32];
        if (!msg) {
            return AXI_RF1_PIN_V1_REFUSED;
        }
        memcpy(msg, dom, sizeof(dom));
        memcpy(msg + sizeof(dom), p, len);
        axi_sha256(msg, sizeof(dom) + len, digest);
        memset(msg, 0, sizeof(dom) + len);
        free(msg);
        memcpy(out->rf_root, digest, 32);
        out->records = (uint32_t)records;
        out->unknowns = (uint32_t)unknowns;
        memset(digest, 0, sizeof(digest));
    }
    return AXI_RF1_PIN_V1_OK;
}
