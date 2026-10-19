#ifndef AXI_SELECTIVE_DISCLOSURE_V1_H
#define AXI_SELECTIVE_DISCLOSURE_V1_H

#include <stddef.h>
#include <stdint.h>

#define AXI_SD1_LEAF_DOMAIN "AXI-SD1-LEAF-v1"
#define AXI_SD1_ROOT_DOMAIN "AXI-SD1-ROOT-v1"

enum {
    AXI_SD1_PUBLIC = 1,
    AXI_SD1_PROTECTED = 2,
    AXI_SD1_DISCLOSE_ONLY = 3,
    AXI_SD1_FORBIDDEN = 4
};

typedef struct {
    uint8_t class_id;
    uint8_t type_id;
    uint8_t field_tag[32];
    uint32_t index;
    uint64_t value_len;
    uint8_t commitment[32];
} axi_sd1_leaf;

int axi_sd1_commit_field(uint8_t class_id, uint8_t type_id,
                         const uint8_t field_tag[32], uint32_t index,
                         const uint8_t salt[32],
                         const uint8_t *value, uint64_t value_len,
                         uint8_t out[32]);
int axi_sd1_make_leaf(axi_sd1_leaf *leaf, uint8_t class_id, uint8_t type_id,
                      const uint8_t field_tag[32], uint32_t index,
                      const uint8_t salt[32],
                      const uint8_t *value, uint64_t value_len);
int axi_sd1_verify_disclosure(const axi_sd1_leaf *leaf,
                              const uint8_t salt[32],
                              const uint8_t *value, uint64_t value_len);
int axi_sd1_root(const axi_sd1_leaf *leaves, size_t n, uint8_t out[32]);

#endif /* AXI_SELECTIVE_DISCLOSURE_V1_H */
