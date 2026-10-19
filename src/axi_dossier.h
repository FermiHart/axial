/* axial - bounded offline AXB v7 dossier. SPDX-License-Identifier: LicenseRef-SPL-1.0 */
#ifndef AXI_DOSSIER_H
#define AXI_DOSSIER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns 0 for an accepted dossier, 1 for a refusal dossier, and 2 for an
 * invalid API call or allocation failure. Caller outputs change only on 0/1. */
int axi_dossier_bytes(const uint8_t *artifact, size_t len,
                      const uint8_t trusted_pk[32],
                      char **json_out, size_t *json_len);
void axi_dossier_free(char *json);

#ifdef __cplusplus
}
#endif

#endif /* AXI_DOSSIER_H */
