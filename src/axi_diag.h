/* axial diagnostic ABI. Bear Core.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0 */
#ifndef AXI_DIAG_H
#define AXI_DIAG_H

#include <stddef.h>
#include <stdint.h>

#define AXI_DIAG_MAX 64
#define AXI_DIAG_MSG 160
#define AXI_DIAG_SCHEMA_VERSION 1u
#define AXI_DIAG_SCHEMA "axi.diags.v1"
#define AXI_NO_OFF 0xFFFFFFFFu

typedef struct {
    char     code[12];
    uint32_t line, col, len;
    uint32_t off;
    char     msg[AXI_DIAG_MSG];
    char     fix[AXI_DIAG_MSG];
    int      has_edit;
    uint32_t ed_off, ed_len;
    uint32_t ed_textlen;
    char     ed_text[AXI_DIAG_MSG];
} axi_diag;

typedef struct axi_diags {
    axi_diag d[AXI_DIAG_MAX];
    int      n;
    int      dropped;
} axi_diags;

void axi_diags_init(axi_diags *ds);
void axi_diag_add(axi_diags *ds, const char *code,
                  uint32_t line, uint32_t col, uint32_t len,
                  const char *msg, const char *fix);
void axi_diag_add_at(axi_diags *ds, const char *code,
                     uint32_t line, uint32_t col, uint32_t len, uint32_t off,
                     const char *msg, const char *fix);
void axi_diag_add_fix(axi_diags *ds, const char *code,
                      uint32_t line, uint32_t col, uint32_t len, uint32_t off,
                      const char *msg, const char *fix,
                      uint32_t ed_off, uint32_t ed_len,
                      const char *repl, uint32_t replen);

/* INV-340 / AXI-INV-106: source coordinates have one authority: byte offset.
 * line/col are derived here, never independently typed at a call site. */
void axi_diag_add_source(axi_diags *ds, const char *code, const char *src,
                         uint32_t off, uint32_t len,
                         const char *msg, const char *fix);

int axi_diags_edits_ok(const axi_diags *ds, char *why, size_t whycap);
int axi_diags_apply(const axi_diags *ds, const char *src, size_t len,
                    char **out, size_t *outlen, int *napplied);

#endif /* AXI_DIAG_H */
