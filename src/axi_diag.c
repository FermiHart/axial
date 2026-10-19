/* axial diagnostic ABI. Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0 */
#include "axi_diag.h"
#include "axi_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

void axi_diags_init(axi_diags *ds)
{
    ds->n = 0;
    ds->dropped = 0;
}

static void copy_str(char *dst, size_t cap, const char *src)
{
    size_t i = 0;
    if (cap == 0) return;
    while (src[i] != '\0' && i + 1 < cap) { dst[i] = src[i]; i++; }
    dst[i] = '\0';
}

static int before(const axi_diag *a, const axi_diag *b)
{
    if (a->off == AXI_NO_OFF) return 0;
    if (b->off == AXI_NO_OFF) return 1;
    return a->off < b->off;
}

void axi_diag_add_fix(axi_diags *ds, const char *code,
                      uint32_t line, uint32_t col, uint32_t len, uint32_t off,
                      const char *msg, const char *fix,
                      uint32_t ed_off, uint32_t ed_len,
                      const char *repl, uint32_t replen)
{
    axi_diag d;
    int at;

    if (!ds) return;
    if (ds->n >= AXI_DIAG_MAX) {
        if (ds->dropped < INT_MAX) ds->dropped++;
        return;
    }
    memset(&d, 0, sizeof d);
    copy_str(d.code, sizeof d.code, code);
    d.line = line; d.col = col; d.len = len; d.off = off;
    copy_str(d.msg, sizeof d.msg, msg);
    copy_str(d.fix, sizeof d.fix, fix ? fix : "");
    /* A repair we cannot carry whole is not carried at all. */
    if (repl && replen < sizeof d.ed_text && off != AXI_NO_OFF) {
        memcpy(d.ed_text, repl, replen);
        d.ed_text[replen] = '\0';
        d.ed_textlen = replen;
        d.ed_off = ed_off; d.ed_len = ed_len;
        d.has_edit = 1;
    }

    /* Public diagnostic sets are byte-ordered. Equal offsets remain stable. */
    at = ds->n;
    while (at > 0 && before(&d, &ds->d[at - 1])) {
        ds->d[at] = ds->d[at - 1];
        at--;
    }
    ds->d[at] = d;
    ds->n++;
}

void axi_diag_add_at(axi_diags *ds, const char *code,
                     uint32_t line, uint32_t col, uint32_t len, uint32_t off,
                     const char *msg, const char *fix)
{
    axi_diag_add_fix(ds, code, line, col, len, off, msg, fix, 0, 0, NULL, 0);
}

void axi_diag_add(axi_diags *ds, const char *code,
                  uint32_t line, uint32_t col, uint32_t len,
                  const char *msg, const char *fix)
{
    axi_diag_add_fix(ds, code, line, col, len, AXI_NO_OFF, msg, fix,
                     0, 0, NULL, 0);
}

void axi_diag_add_source(axi_diags *ds, const char *code, const char *src,
                         uint32_t off, uint32_t len,
                         const char *msg, const char *fix)
{
    uint32_t line = 1, col = 1, i;
    /* A saturated diagnostic set cannot publish these coordinates. Avoid
     * rescanning the prefix for every rejected byte of a hostile source. */
    if (!ds) return;
    if (ds->n >= AXI_DIAG_MAX) {
        if (ds->dropped < INT_MAX) ds->dropped++;
        return;
    }
    if (!src) {
        axi_diag_add(ds, code, 0, 0, 0, msg, fix);
        return;
    }
    for (i = 0; i < off; i++) {
        if (src[i] == '\n') { line++; col = 1; }
        else col++;
    }
    axi_diag_add_at(ds, code, line, col, len, off, msg, fix);
}

int axi_diags_edits_ok(const axi_diags *ds, char *why, size_t whycap)
{
    int i;
    uint32_t prev_end = 0;
    int first = 1;
    if (!ds || ds->n < 0 || ds->n > AXI_DIAG_MAX) return 0;
    for (i = 0; i < ds->n; i++) {
        const axi_diag *d = &ds->d[i];
        if (!d->has_edit) continue;
        if (d->ed_textlen >= AXI_DIAG_MSG ||
            d->ed_len > UINT32_MAX - d->ed_off) return 0;
        if (!first && d->ed_off < prev_end) {
            if (why && whycap)
                snprintf(why, whycap,
                         "%s edit at %lu overlaps the previous edit ending at "
                         "%lu (edits must be disjoint and sorted)",
                         d->code, (unsigned long)d->ed_off,
                         (unsigned long)prev_end);
            return 0;
        }
        prev_end = d->ed_off + d->ed_len;
        first = 0;
    }
    return 1;
}

int axi_diags_apply(const axi_diags *ds, const char *src, size_t len,
                    char **out, size_t *outlen, int *napplied)
{
    size_t cap, w = 0, cursor = 0;
    char *buf;
    int i, n = 0;

    if (!src || !out || !outlen || len == (size_t)-1 ||
        !axi_diags_edits_ok(ds, NULL, 0)) return 0;
    cap = len + 1;
    for (i = 0; i < ds->n; i++) {
        const axi_diag *d = &ds->d[i];
        if (!d->has_edit) continue;
        if ((size_t)d->ed_off > len || d->ed_len > len - d->ed_off ||
            d->ed_textlen > (size_t)-1 - cap) return 0;
        cap += d->ed_textlen;
    }
    buf = (char *)axi_malloc(cap);
    if (!buf) return 0;
    for (i = 0; i < ds->n; i++) {
        const axi_diag *d = &ds->d[i];
        if (!d->has_edit) continue;
        if (d->ed_off < cursor || (size_t)d->ed_off > len || d->ed_len > len - d->ed_off) {
            free(buf); return 0;
        }
        memcpy(buf + w, src + cursor, d->ed_off - cursor);
        w += d->ed_off - cursor;
        memcpy(buf + w, d->ed_text, d->ed_textlen);
        w += d->ed_textlen;
        cursor = (size_t)d->ed_off + d->ed_len;
        n++;
    }
    memcpy(buf + w, src + cursor, len - cursor);
    w += len - cursor;
    buf[w] = '\0';
    *out = buf; *outlen = w;
    if (napplied) *napplied = n;
    return 1;
}
