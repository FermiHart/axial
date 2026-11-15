# Darwin compiler portability repair

The newly added macOS 15 Games job exposed native build failures: POSIX feature
selection hid Darwin's `O_NOFOLLOW` and `flock`/`LOCK_*` interfaces, and Darwin
spells nanosecond stat timestamps `st_mtimespec`/`st_ctimespec` rather than
`st_mtim`/`st_ctim`.

The default Makefile CFLAGS, portable compiler/exporter build helpers, isolated
numeric gate and trust-canon standalone compiler now explicitly enable
`_DARWIN_C_SOURCE` alongside `_POSIX_C_SOURCE=200809L`. This retains the Darwin
interfaces actually used rather than weakening the implementation. Custom
builds that replace those flags must also expose these required interfaces.

`src/axi_stat_time.h` maps the two host field spellings. All timestamp accesses
in `axi_local_authority_v1.c` use it. Seconds **and nanoseconds** remain part of
the metadata stability comparisons and overflow-checked timestamp conversion.
No `O_NOFOLLOW`, `O_CLOEXEC`, lock operation or file ownership/mode check was
removed, emulated with zero, or relaxed. The Linux boot-ID/CLOCK_BOOTTIME local
authority remains explicitly unsupported on other hosts; compiling the shared
core is not a claim that this Linux-specific authority works on Darwin.

## Reviewed source identity

After this change, `tools/axi-checker-identity.py --write` produced commitment
`692b770d321519e20ef19e8838e89ca9564941b8a3ac782cbe9dcdbdf02035b8`
over 127 source files and confirmed unchanged public v1 ABI pins.

The v1 access, v2 access and numeric add fixture exports were captured before
and after rebuilding. Parsed records differ **only** in `compilerSourceDigest`.
Source hashes, interface hashes, body hashes, constants and instructions remain
identical. The v1 artifact pin was updated only after that comparison, to
`3934f07ed55afbe847c035f16c85e8ee4c2aa89c648670345bc8f54f8d6cc122`.

## Executed evidence and limit

On Linux x64, `make gate-identity gate-fast` passed (67 native checks), the
trust-canon gate passed 256 SHA256 comparisons and refusal cases, and the serial
portable-policy/decision/numeric regression set passed 35 tests, including the
97,920-case seeded native numeric corpus. No Apple SDK or macOS executor was
available locally. The macOS CI rerun is still required before declaring that
platform green; a successful Linux rebuild alone does not prove the fix there.
