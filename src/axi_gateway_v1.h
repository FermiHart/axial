#ifndef AXI_GATEWAY_V1_H
#define AXI_GATEWAY_V1_H

#include <stddef.h>
#include <stdint.h>

#define AXI_GATEWAY_V1_DOMAIN "AXI-GATEWAY-v1"
#define AXI_GATEWAY_V1_MAX_RECORDS 8u

enum {
    AXI_GATEWAY_NEW = 0,
    AXI_GATEWAY_DUPLICATE = 1,
    AXI_GATEWAY_REFUSED = 2
};

typedef struct {
    uint8_t request_id[32];
    uint8_t principal_root[32];
    uint8_t admission_root[32];
    uint8_t action_descriptor_root[32];
    uint8_t ag1_action_root[32];
    uint8_t payload_root[32];
    uint8_t sequence_root[32];
    const char *action_name;
} axi_gateway_request;

/* Mutable state has one trusted owner or external serialization; this is not
 * a thread-safe scheduler, signature verifier or guest authorization door. */
typedef struct {
    uint8_t request_id[AXI_GATEWAY_V1_MAX_RECORDS][32];
    uint8_t digest[AXI_GATEWAY_V1_MAX_RECORDS][32];
    size_t n;
} axi_gateway_idempotency_state;

int axi_gateway_v1_action_known(const char *action_name);
int axi_gateway_v1_request_digest(const axi_gateway_request *request,
                                  uint8_t out[32]);
int axi_gateway_v1_admit(axi_gateway_idempotency_state *state,
                         const axi_gateway_request *request,
                         uint8_t digest_out[32]);

#endif /* AXI_GATEWAY_V1_H */
