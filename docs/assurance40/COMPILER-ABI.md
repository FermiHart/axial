# W11–W16 — Compiler and ABI evidence

Reviewed 2026-11-27 at PR head `543848917e198f00eb4dbf05a5f7c80ceee2e33d`. GitHub PR checks
may test a merge revision; exact source identity belongs to each checkout.
The following are actual workflow job/step conclusions, not reconstructed
stdout or a new local run.

| Evidence | Result and boundary |
| --- | --- |
| [Audit gate](https://github.com/FermiHart/axial/actions/runs/46001741433) | normal, release, sanitizers, threads, Clang, optimized UBSan and leak-fast jobs succeeded. |
| Default flags | Makefile: C99, -Wall -Wextra -Werror -O1, POSIX/Darwin feature macros. |
| Release flags | audit.yml: C99, -Wall -Wextra -Werror -O2, POSIX macro. Both normal/release run gate-fast against the same checked-in goldens. |
| Leak scope | Job 140514957090, address/leak fast gate, detect_leaks=1, no authority fixture. Full sanitizer matrix explicitly disables leak detection; no whole-process/traced workload LSan claim. |
| Numeric leak scope | Games run 46001741509, job 140514839338, native numeric address/undefined/leak sanitizer step succeeded on Ubuntu Node 24. |
| Native consumer matrix | [Games adapters](https://github.com/FermiHart/axial/actions/runs/46001741509): Ubuntu Node 20/22/24, Ubuntu ARM Node 24, macOS 15 Node 24 all passed native compiler fixture and adapter regression. Benchmarks skipped; numeric sanitizer skipped outside Ubuntu x64 Node 24. Not full C ABI qualification on ARM/macOS. |
| ABI | Scope guard and gate-audit succeeded for normal, release and sanitizer profiles; gate-audit includes tests/audit40/abi.c (72 compile-time checks plus endian/version). Public ABI is amd64 SysV LP64, not a newly supported platform. |

## Additional matrix

[Compiler matrix](../../.github/workflows/assurance-compiler.yml) builds
ordinary goldens at O1/O2 under GCC and Clang, with identical feature macros
and explicit compiler/target/source identity in logs. All four jobs compare
against the same goldens. The existing frozen header guard and layout probe
run independently; the four declared public prefix symbols in the tracked
ABI TSV are compared to defined global symbols of the embed implementation
object. This is an object symbol inventory, not a new archive/distribution
or calling-convention certification.

The separate warnings jobs measure format, shadow and strict-prototype
diagnostics, keeping existing ordinary warnings-as-errors except the
specified informational categories. Counts include duplicate diagnostic
occurrences and unclassified warnings. Build failures remain failures.
No warning-driven source changes are made before observing results.
Compiler packages are hosted image inputs, not immutable package pins;
exact compiler versions, warning counts and matrix outcomes are pending.
