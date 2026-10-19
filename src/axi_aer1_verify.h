#ifndef AXI_AER1_VERIFY_H
#define AXI_AER1_VERIFY_H

#include <stddef.h>
#include <stdint.h>

#include "axi_aer1.h"

int axi_aer1_verify_signed(axi_aer1 *receipt, const uint8_t *bytes,
                           size_t len, const uint8_t trusted_pk[32]);

#endif
