#!/bin/sh
# Compile only the local owner modules with syscall name redirection. No product hook.
set -eu
audit_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
audit_source=${AXI_AUDIT_SOURCE_ROOT:-$audit_root}
audit_build=${AXI_AUDIT_BUILD:-$audit_root/build/audit80-security}
audit_cc=${HOSTCC:-${CC:-cc}}
audit_flags=${AXI_AUDIT_CFLAGS-${CFLAGS--std=c99 -Wall -Wextra -Werror -O2 -g -D_POSIX_C_SOURCE=200809L}}
audit_cppflags=${CPPFLAGS:-}
audit_ldflags=${LDFLAGS:-}
audit_ldlibs=${LDLIBS--lm}
mkdir -p "$audit_build"
audit_build=$(CDPATH= cd -- "$audit_build" && pwd)
AXI_AUDIT_BUILD_ONLY=1 sh "$audit_root/tests/audit80/security.sh"
audit_modes="$*"
mkdir -p "$audit_build/faults"
set --
for audit_unit in axi_local_attempt_v1 axi_local_authority_v1; do
    # shellcheck disable=SC2086
    # Fortified libc inline aliases bypass syscall name redirection. This
    # override is limited to the test-only owner objects, never a product build.
    $audit_cc $audit_cppflags $audit_flags -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
        -I"$audit_source/src" -I"$audit_source/include" -I"$audit_source/vendor" \
        -Dfsync=audit80_fsync -Dwrite=audit80_write -Dread=audit80_read \
        -Dunlinkat=audit80_unlinkat -Dclock_gettime=audit80_clock_gettime \
        -Dfcntl=audit80_fcntl -Daxi_calloc=audit80_calloc \
        -c "$audit_source/src/$audit_unit.c" -o "$audit_build/faults/$audit_unit.o"
    set -- "$@" "$audit_build/faults/$audit_unit.o"
done
for audit_object in "$audit_build"/*.o; do
    case "$audit_object" in */axi_local_attempt_v1.o|*/axi_local_authority_v1.o|*/security.o) continue ;; esac
    set -- "$@" "$audit_object"
done
# shellcheck disable=SC2086
$audit_cc $audit_cppflags $audit_flags -I"$audit_source/src" -I"$audit_source/include" -I"$audit_source/vendor" \
    -x c -c "$audit_root/tests/audit80/security_faults.inc" -o "$audit_build/faults/test.o"
# shellcheck disable=SC2086
$audit_cc $audit_flags "$@" "$audit_build/faults/test.o" $audit_ldflags -o "$audit_build/faults/security_faults" $audit_ldlibs
[ "${AXI_AUDIT_BUILD_ONLY:-0}" = 1 ] && exit 0
# shellcheck disable=SC2086
sh "$audit_root/tests/audit80/security_run.sh" "$audit_build/faults/security_faults" $audit_modes
