/* ADR-059 AXV2-35: trust-snapshot canon. See header. */
#include "axi_trust_canon_v1.h"

#include "axi_hash.h"

#include <string.h>

int axi_trust_canon_v1_root(const uint8_t page[4096], uint8_t root[32],
                            size_t page_len)
{
    /* AXI-INV-218: spell the domain length out. sizeof("...") counts
     * the NUL and once smuggled a second zero into the digest; the
     * Python differential caught it in the lab (AXV3-04). */
    static const uint8_t dom[16] = "SINGUOS-TRUST-v1";
    uint8_t cat[16 + 1 + AXI_TRUST_CANON_V1_COVERED_SIZE];
    if (!page || !root
        || page_len != AXI_TRUST_CANON_V1_PAGE_SIZE) {
        return AXI_TRUST_CANON_V1_REFUSED;
    }
    memcpy(cat, dom, 16);
    cat[16] = 0;
    memcpy(cat + 17, page, AXI_TRUST_CANON_V1_COVERED_SIZE);
    axi_sha256(cat, sizeof(cat), root);
    return AXI_TRUST_CANON_V1_OK;
}
