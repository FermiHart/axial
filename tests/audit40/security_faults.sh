#!/bin/sh
# Test-only I/O redirection, without a product hook or LD_PRELOAD dependency.
set -eu
audit_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
audit_source=${AXI_AUDIT_SOURCE_ROOT:-$audit_root}
audit_build=${AXI_AUDIT_BUILD:-$audit_root/build/audit40-security}
audit_cc=${HOSTCC:-${CC:-cc}}
audit_flags=${AXI_AUDIT_CFLAGS-${CFLAGS--std=c99 -Wall -Wextra -Werror -O2 -g -D_POSIX_C_SOURCE=200809L}}
audit_cppflags=${CPPFLAGS:-}
audit_ldflags=${LDFLAGS:-}
audit_ldlibs=${LDLIBS--lm}
AXI_AUDIT_BUILD_ONLY=1 sh "$audit_root/tests/audit40/security.sh"
audit_modes="$*"
mkdir -p "$audit_build/faults"
set --
for audit_src in axi_local_attempt_v1 axi_local_epoch_v1; do
    # shellcheck disable=SC2086
    $audit_cc $audit_cppflags $audit_flags -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
        -I"$audit_source/src" -I"$audit_source/include" -I"$audit_source/vendor" \
        -Dwrite=audit_fault_write -Dread=audit_fault_read -Dreaddir=audit_fault_readdir -Dfsync=audit_fault_fsync \
        -c "$audit_source/src/$audit_src.c" -o "$audit_build/faults/$audit_src.o"
    set -- "$@" "$audit_build/faults/$audit_src.o"
done
for audit_object in "$audit_build"/*.o; do
    case "$audit_object" in */axi_local_attempt_v1.o|*/axi_local_epoch_v1.o|*/security.o) continue ;; esac
    set -- "$@" "$audit_object"
done
# shellcheck disable=SC2086
$audit_cc $audit_cppflags $audit_flags -I"$audit_source/src" -I"$audit_source/include" -I"$audit_source/vendor" \
    -x c -c "$audit_root/tests/audit40/security_faults.inc" -o "$audit_build/faults/test.o"
# shellcheck disable=SC2086
$audit_cc $audit_flags "$@" "$audit_build/faults/test.o" $audit_ldflags -o "$audit_build/faults/security_faults" $audit_ldlibs
[ "${AXI_AUDIT_BUILD_ONLY:-0}" = 1 ] && exit 0
# shellcheck disable=SC2086
"$audit_build/faults/security_faults" $audit_modes
