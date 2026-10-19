/* Trusted link-time target ports for portable AG1; no requester callbacks. */
#ifndef AXI_AG1_CRYPTO_V1_H
#define AXI_AG1_CRYPTO_V1_H
#include "axi_ag1_v1.h"
int axi_ag1_crypto_hash(const void *bytes, size_t size, uint8_t out[32]);
int axi_ag1_crypto_verify(const uint8_t signature[64], const uint8_t *message,
                          size_t size, const uint8_t public_key[32]);
int axi_ag1_signature_message(const uint8_t body[AXI_AG1_V1_BODY_SIZE],
                              uint8_t out[AXI_AG1_V1_SIG_MSG_SIZE]);
#endif
