/* AX30: advisory AST lint, NOT a policy proof or authorization result. */
#ifndef AXI_POLICY_LINT_H
#define AXI_POLICY_LINT_H
#include "axi_ast.h"
void axi_policy_lint(const axi_node *unit, axi_diags *diags);
#endif
