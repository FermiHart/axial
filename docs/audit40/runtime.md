# Audit40: runtime, bytecode, effects and resource accounting

Owner: W11–W20. Production AXB/replay layouts, frozen embed-v1 ABI and
instruction fuel costs remain unchanged. Commands use the normal product
sources, excluding the CLI's two standalone `main` translation units.

## W11 — arithmetic source/destination aliasing

**Problem.** Arithmetic copied the left operand into its destination before
reading the right operand. Valid instructions such as `sub r1 r0 r1` therefore
overwrote their right input. A right-aliased division by zero incorrectly
succeeded. The first regression run produced 18 failing checks of 174.

**Change.** Publish the scalar result after consuming both inputs and checking
the divisor. This applies to u64, i64 and f64, including signed wrap semantics.

**Evidence.** `tests/audit40/runtime.c` covers all arithmetic opcodes with
destination equal to either input or a separate register, exact fuel charges,
signed MIN/-1, divide-by-zero and insufficient fuel. 174 checks pass after the
fix. Failed calls retain the caller's output value.

**Limits.** Floating arithmetic still follows the existing IEEE/canonical-NaN
contract; this wave changes neither its rounding environment nor op costs.
