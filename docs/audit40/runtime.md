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

## W12 — alias-safe union construction and extraction

**Problem.** UMAKE, UTAG, UPAY and successful UCHK initialized the destination
before consuming every input. Self-unwrapping lost payloads and kinds; building
over the tag register changed the arm. The added cases failed 83 checks before
the fix.

**Change.** Construct the complete union in a temporary; capture tags before
publishing; share one payload extraction helper that returns the value before
the destination register changes.

**Evidence.** The suite now has 560 checks, covering eight payload kinds,
separate and aliased destinations, all four union instructions, exact fuel,
error atom/payload retention and nonzero-arm early propagation. All pass.

**Limits.** Nested union and CAP payloads remain outside the existing format.

## W13 — type- and content-aware value equality

**Problem.** EQ compared unions by tag and scalar bits only, making different
string payloads, error atoms and even payload kinds equal. Union f64 equality
also treated signed zero and NaN differently from scalar f64. Scalar errors
ignored their payload. New tests reproduced 24 failing comparisons.

**Change.** One closed-kind comparison handles scalars and union payloads.
Union arms and kinds must match; strings/bytes compare their exact lengths and
contents; errors compare atom and payload; f64 keeps IEEE equality. Zero-byte
comparisons do not call `memcmp` with null payload pointers.

**Evidence.** 656 checks pass, including equal/different string bytes, union
arms, equal bits with different kinds, +/-0, NaN, error atom and payload, and
all EQ destination aliases. Fuel remains two units including RET.

**Compatibility.** Programs relying on the erroneous equality of distinct
union/error values now receive false. Wire representations are unchanged.
