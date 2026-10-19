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

## W14 — bounded, fail-closed replay records

**Problem.** The shared replay entry digest trusted caller-controlled lengths
and copied them into a 2,306-byte automatic buffer. ASan reproduced an
out-of-bounds write with payload_len=1024 and result_len=1025 on the baseline.
The v3 writer published malformed record prefixes, while recording could
silently truncate identity names or resume after a prior failed reservation.

**Change.** Check digest lengths before any copy, validate record shape and
content before replay/callback output, validate the whole record set before
serialization, reject invalid names/pointers/flags, preserve failed state, and
require an actual output destination for nonempty replay results. The v3
decoder applies the same record-shape rules. The v4 wire codec is unchanged.

**Evidence.** 706 checks pass, including record/load/replay round trip,
oversized and SIZE_MAX lengths, malformed names and flags, content tampering,
invalid receipt fields, sticky failure, and unchanged outputs/cursor/callback
count on refusal. ASan+UBSan also pass with leak detection disabled because
this execution host reports that LeakSanitizer cannot run under ptrace.

**Limits.** This validates in-memory structure and byte framing; authenticity
continues to belong to the existing explicitly trusted signed-v4 boundary.

## W15 — effect evidence and grant-table boundary validation

**Problem.** Ledger appends truncated long names, admitted empty identities and
dereferenced null payload/digest arguments. Corrupt row counts could bypass
reservation. Journal transitions could continue after evidence failure.
Grant lookup could return a matching early entry before noticing an invalid
or duplicate later entry. Direct ledger JSON interpolation did not escape
quoted or control-character names.

**Change.** Reject malformed receipt inputs before allocation or hashing,
check ledger/journal storage shape, stop failed journal transitions, validate
the complete grant table before mutation or lookup, and escape JSON names.

**Evidence.** 734 checks pass, covering unchanged ledger tip/count on refusal,
valid JSON output for quotes/newlines, malformed row counts, terminal journal
transitions, sticky failure, duplicates and unterminated grant entries.

**Limits.** Existing canonical production names serialize byte-identically.
The grant set remains a fixed maximum of 32 entries; whole-table validation
is intentional at the authority boundary.

## W16 — effect preflight and observable worker failures

**Problem.** A recorder key equal to the producer key was rejected only while
signing replay evidence, after effects had run. Replay fuel subtraction could
wrap for an already-overdrawn context, and output-allocation refusal left a
PREPARED journal attempt open. Worker datagram sockets do not expose peer EOF,
so a child exiting without a frame hid failure until the full deadline.

**Change.** Check recorder independence before VM execution, reserve and wipe
the temporary key material, reject overdrawn replay/spawn fuel before
subtraction, finish failed replay preparation, and use UNIX sequenced-packet
worker channels. Packet framing and FD passing stay exact; unsupported hosts
refuse the effect rather than falling back to a weaker transport.

**Evidence.** 746 normal checks pass. `runtime --workers` adds six checks for
a child exiting without a frame and a successful worker; these pass with
ordinary local UNIX IPC enabled. A signed io.Write CLI probe using identical
keys exits 1 with AXI-R025 and zero stdout bytes, before the write. The baseline
had written before its signing refusal.

**Environment.** This sandbox returns EPERM for worker socket sends. That is
not a normal-host fsync defect; positive worker tests were run through the
authorized unsandboxed local-test door. No network endpoint was contacted.

## W17 — resource transaction aliasing and lifetime exhaustion

**Problem.** Committing an envelope's own reserved vector as both reservation
and actual usage zeroed it before charging the spend. Output cleanup removed
ownership pointers even when the supplied memory account refused to free
them. Malformed output counts could read beyond the fixed ownership table.
Handle generation wrapped after UINT32_MAX, making stale identities reusable.

**Change.** Snapshot resource-commit inputs, validate the envelope before the
transaction, preserve ownership on failed cleanup, bound cleanup counts and
live-handle accounting, and saturate generation allocation with a refusal at
exhaustion. The 64-bit handle format stays unchanged.

**Evidence.** 766 runtime checks pass, including aliased commits, all-or-none
refusal, cleanup under a wrong account followed by successful owner cleanup,
malformed ownership counts and impossible live-handle totals.
`tests/audit40/runtime_handles.c` separately positions the private counter at
its final two generations and confirms that exhaustion never revives stale
handles or changes the caller's output. Compile it standalone with `-Isrc`;
it deliberately includes the handle implementation for boundary setup.

**Limits.** After 4,294,967,295 process-wide generations, creating a new handle
fails safely. Applications requiring a larger lifetime need a separately
versioned handle representation; this audit does not change that format.
