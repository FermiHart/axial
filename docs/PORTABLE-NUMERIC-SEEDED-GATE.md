# Isolated seeded numeric gate

Run the focused gate without touching shared build artifacts:

```sh
node --test tests/portable-numeric-seeded.test.cjs
AXIAL_NUMERIC_SANITIZERS=1 node --test tests/portable-numeric-seeded.test.cjs
```

`tools/portable-numeric-seeded-gate.cjs` builds the real compiler/VM via the
official Makefile in a fresh temporary `BUILD` directory, and links a separate
numeric exporter against those objects. All temporary artifacts are removed.
Source digest checks detect compiler-source edits across the run.

The fixed seed `0x6d1f009abeef1234` produces 6,120 cases per fixture. Eleven
existing fixtures plus five composed arithmetic/branch fixtures give **97,920
native-VM/portable comparisons**. The corpus covers signed endpoints and near
endpoints, values beyond Number precision, 32-bit boundaries, negative operands,
zero divisors, chained wraparound, signed constants, branch paths and fuel
prefixes 0–24 plus the maximum request 4,096. Another 512 seeded invalid opcode
mutations must fail structural admission. Output includes seed, corpus SHA256,
compiler identity, Node version and per-outcome counts.

The ordinary run was executed with GCC 14.2.0, Node 24.22.1 on Linux x64:
73,735 successful values, 23,303 fuel traps, 882 other traps, 512 malformed
programs refused. Corpus SHA256:
`54d95306e825fb87496a2bd550b10a8b351a17fa18943c08874996f91dad4589`.

## Sanitizer mode and environment limitations

Sanitizer mode uses ASan/UBSan, frame pointers, `halt_on_error=1` and explicit
non-PIE binaries. Leak checking is enabled by default. It **does not silently
fall back** when a sanitizer cannot run. In this execution environment the
default sanitizer invocation failed during `axi canon` with:

```
LeakSanitizer has encountered a fatal error.
LeakSanitizer does not work under ptrace (strace, gdb, etc)
```

To test address/undefined-behavior checks independently in such an environment,
the caller may explicitly use:

```sh
AXIAL_NUMERIC_SANITIZERS=1 AXIAL_NUMERIC_LEAKS=0 node --test tests/portable-numeric-seeded.test.cjs
# Equivalent direct tool: node tools/portable-numeric-seeded-gate.cjs --sanitize --no-leaks
```

The JSON then records `leakDetection:false`. Such a run must never be described
as a passed leak check. This explicit ASan/UBSan-only run was executed on the
same host and passed all 97,920 comparisons and 512 refusals, with the identical
corpus hash and outcome counts above and no sanitizer finding. Leak detection
remains unverified. None of these tests establishes all-platform determinism,
general VM safety, race freedom or production performance. No numeric semantics
or native source ABI are changed by this gate.
