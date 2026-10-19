/* AX30: one registry shared by typecheck, codegen and runtime metadata.
 * Extends named builtins, not opcode numbers or embed-v1 layout.
 * SPDX-License-Identifier: LicenseRef-SPL-1.0 */
#ifndef AXI_BUILTIN_REGISTRY_H
#define AXI_BUILTIN_REGISTRY_H
#define AXI_BUILTIN_REGISTRY(X) \
 X("fs.path_under", 2, STR, STR, UNIT, BOOL, CAP_FS_READ, "fs.Read", 1) \
 X("json.get", 2, JSON, STR, UNIT, JSON, CAP_NONE, NULL, 0) \
 X("json.bool", 2, JSON, STR, UNIT, BOOL, CAP_NONE, NULL, 0) \
 X("json.u64", 2, JSON, STR, UNIT, U64, CAP_NONE, NULL, 0) \
 X("json.i64", 2, JSON, STR, UNIT, I64, CAP_NONE, NULL, 0) \
 X("json.string", 2, JSON, STR, UNIT, STR, CAP_NONE, NULL, 0) \
 X("json.kind", 2, JSON, STR, UNIT, STR, CAP_NONE, NULL, 0) \
 X("budget.fits", 3, U64, U64, U64, BOOL, CAP_NONE, NULL, 0) \
 X("budget.fits_product", 3, U64, U64, U64, BOOL, CAP_NONE, NULL, 0) \
 X("math.add_checked", 2, U64, U64, UNIT, U64, CAP_NONE, NULL, 0) \
 X("math.sub_checked", 2, U64, U64, UNIT, U64, CAP_NONE, NULL, 0) \
 X("math.mul_checked", 2, U64, U64, UNIT, U64, CAP_NONE, NULL, 0) \
 X("math.div_checked", 2, U64, U64, UNIT, U64, CAP_NONE, NULL, 0) \
 X("math.mod_checked", 2, U64, U64, UNIT, U64, CAP_NONE, NULL, 0)
#endif
