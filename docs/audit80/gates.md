# W77 — permanent audit gates

`make gate` includes the existing identity, golden, CLI, audit40, worker and
compiler checks, plus the audit80 frontend, numeric, local-authority and
runtime regressions. A refused or unavailable required test fails the gate.
The new targets do not impose timing thresholds or run performance benchmarks.

| Target | Coverage |
| --- | --- |
| `gate-frontend` | Both audit40 and audit80 frontend runners; `gate-frontend40` and `gate-frontend80` also run individually. |
| `gate-numeric` | Exact numeric reader/formatter oracle, lexer integration, scratch/fenv limits and CLI behavior. |
| `gate-authority` | Real-host W41–W50 assertions, injected owner I/O/source failures and compiled-out-provider refusal. |
| `gate-authority-build` | Build those three authority executables, without running them or invoking sudo. |
| `gate-compiler` | All `tests/audit80/compiler_*.c` plus CLI/real-allocation-failure coverage. |
| `gate-runtime` | W69–W76 workload/lifecycle/memory/stack/concurrency/I/O-fault/process-recovery fixtures. |
| `gate-tsan` | Separate ThreadSanitizer run of cached, uncached and forced-software concurrency lanes. |

## Compiler flags and build separation

All gate runners inherit `HOSTCC`, `CPPFLAGS`, `CFLAGS` and `LDFLAGS`.
Shell runners also accept `LDLIBS` and frontend runners accept `PYTHON`.
`CC` remains a standalone security-runner fallback; `AXI_AUDIT_CFLAGS` remains
an explicit override of `CFLAGS`. The Makefile passes its selected CFLAGS as
that override. Preprocessor flags reach every product and harness compilation;
linker flags reach links, including test-only redirected objects' executables.
Changed compiler commands, flags and headers invalidate the corresponding
object caches.

Use a distinct `BUILD` for each profile; the workflow uses `build-normal`,
`build-release`, `build-sanitize` and `build-tsan`. Component runners place
their objects in separate subdirectories of that selected build. Concurrent
invocations must not share the same component build directory.

```sh
make -j2 BUILD=build-normal AUTHORITY_RUNNER=sudo gate
make -j2 BUILD=build-release AUTHORITY_RUNNER=sudo \
  CFLAGS='-std=c99 -Wall -Wextra -Werror -O2 -D_POSIX_C_SOURCE=200809L' gate
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
make -j2 BUILD=build-sanitize AUTHORITY_RUNNER=sudo \
  CFLAGS='-std=c99 -Wall -Wextra -Werror -O1 -g -D_POSIX_C_SOURCE=200809L -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -fno-pie' \
  LDFLAGS='-fsanitize=address,undefined -fno-sanitize-recover=all -no-pie' gate
TSAN_OPTIONS=halt_on_error=1 make BUILD=build-tsan gate-tsan
```

`tools/audit80-runtime-bench.py` preserves its existing modes, `--output`,
`--cflags` and benchmark JSON fields. It adds `--cppflags`, `--ldflags` and
`--out-dir` (alias for `--output`), with environment defaults. Compiler command,
preprocessor and linker flags are recorded in new JSON fields; CFLAGS remain
in the existing `flags`/profile fields. The cache includes all flag groups.
`-pthread` is applied during both compilation and linking of these fixtures.

## Actual authority credentials

`AUTHORITY_RUNNER=direct` is the default. A supported host must let the test
establish two real, distinct, nonzero UIDs, or must already launch it with
those credentials. The fixture uses actual kernel `getuid/geteuid` observations;
it does not substitute authentication callbacks or invented requester IDs.
When launched with effective UID zero, it drops supplementary groups, sets
GID 1001 and switches to real UID 1000 / effective UID 1001 before the tests.
All stores are private temporary fixtures, cleaned by their test process.

On the non-root Ubuntu CI runner, `AUTHORITY_RUNNER=sudo` compiles everything
as the invoking user, then invokes `sudo -n` **only for the already-built
`security` and `security_faults` executables**. Their small shell wrapper runs
without elevation. `ASAN_OPTIONS` and `UBSAN_OPTIONS` are passed explicitly
through sudo; neither `sudo -E`, a privileged compiler, nor a privileged
generic shell/interpreter is used. The disabled-provider binary needs no
elevation. Missing sudo permission, credential-setup failure and exit 77 all
fail the gate with a diagnostic; none is treated as a skipped success.

To separate build review from execution:

```sh
make BUILD=build-authority-review gate-authority-build
AUTHORITY_RUNNER=sudo sh tests/audit80/security_run.sh \
  "$PWD/build-authority-review/audit80-security/security"
AUTHORITY_RUNNER=sudo sh tests/audit80/security_run.sh \
  "$PWD/build-authority-review/audit80-security/faults/security_faults"
build-authority-review/audit80-security/nohost/security_nohost
```

Standalone security runners retain `AXI_AUDIT_BUILD_ONLY=1`,
`AXI_AUDIT_BUILD` and `AXI_AUDIT_SOURCE_ROOT`. Build-only is compilation evidence,
not a passing authority test. Local authority remains an explicit Linux host
profile: these gates do not authenticate remote principals or demonstrate
universal guest mediation.

## ThreadSanitizer scope

The earlier W72 evidence instrumented the full product and exercised three
test-header variants against a common product build. W77 also compiles the
**entire product** with each uncached/software macro, in separate cache
directories `profiles/sha-nocache` and `profiles/sha-software`. The default
product stays in the runtime output root. The existing
`runtime_concurrency_uncached` name remains valid; `runtime_concurrency_nocache`
is an alias. Every lane joins all readers before context destruction.

`gate-tsan` and the dedicated CI job run these fixtures without changing ASLR,
kernel settings or other global host configuration. TSan startup failures
remain failures; there is no retry/skip fallback. A compatible host/compiler
runtime is required. ASan/UBSan and TSan are separate profiles, and observed
clean runs concern the exercised lifetimes and inputs. LeakSanitizer is not
claimed: the documented ASan profile sets `detect_leaks=0`.

## Integration smoke evidence

Before the final combined W78–W80 matrix, W77 passed shell syntax checks,
workflow YAML parsing and a full `make -n gate gate-tsan` recipe inspection.
A temporary command-capture smoke checked 139 compile-only recipes, 23 links
and six Python-oracle invocations: flag placement, a multiword HOSTCC wrapper,
relative build paths, build-only with no test/sudo execution, the two explicit
sudo binary invocations, and refusal propagation for exit 77, sudo failure and
an invalid runner mode. These captures used stubs and establish runner command
routing, not product correctness or successful privilege acquisition.

Two real probes were then compiled from the captured recipes with GCC and ran
successfully: `frontend_strings.c` (allocation-free decoding and atomic
refusals) and `numeric_limits.c` (locale/rounding-mode preservation and 1 MiB
decimal tails/magnitudes). The latter host exposed three locale names but no
non-dot separator locale; that missing environmental case is not claimed.
No full gate or benchmark was run during this concurrent integration smoke.
