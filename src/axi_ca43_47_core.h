#ifndef AXI_CA43_47_CORE_H
#define AXI_CA43_47_CORE_H

#include <stddef.h>
#include <stdint.h>

#define AXI_CA43_47_CORE_DOMAIN "AXI-CA43-47-CORE-v1"

enum { AXI_TARGET_EFFECT_MISSING = 0, AXI_TARGET_EFFECT_MAPPED = 1 };
enum { AXI_FACT_CLAIMED = 1, AXI_FACT_CHECKED = 2 };
enum { AXI_MATRIX_REQUIRED = 1, AXI_MATRIX_OPTIONAL = 2, AXI_MATRIX_BLOCKED = 3 };
enum { AXI_JOB_PASS = 1, AXI_JOB_FAIL = 2, AXI_JOB_SKIP = 3 };

typedef struct {
    uint8_t action_root[32];
    uint8_t grant_action_root[32];
    uint64_t budget_limit;
    uint64_t budget_cost;
    uint8_t spent;
} axi_fd1_attempt;

typedef struct {
    uint8_t maturity;
    uint8_t checker_root[32];
    uint8_t module_root[32];
    uint8_t action_root[32];
    uint8_t requested_root[32];
    uint8_t observed_root[32];
    uint8_t policy_root[32];
} axi_vfact1;

typedef struct {
    const char *name;
    uint8_t requirement;
    uint8_t result;
    uint8_t evidence_root[32];
} axi_matrix1_row;

int axi_target1_effect_mapping(const char *effect_name);
int axi_target1_registry_root(uint8_t out[32]);
int axi_fd1_admit_once(axi_fd1_attempt *attempt);
int axi_vfact1_consume(const axi_vfact1 *fact, const uint8_t action_root[32]);
int axi_sdkpkg1_symbol_allowed(const char *symbol);
int axi_sdkpkg1_include_allowed(const char *include_path);
int axi_matrix1_release_green(const axi_matrix1_row *rows, size_t n);

#endif /* AXI_CA43_47_CORE_H */
