#!/bin/sh
# Test-only I/O redirection, without a product hook or LD_PRELOAD dependency.
set -eu
audit_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
audit_source=${AXI_AUDIT_SOURCE_ROOT:-$audit_root}
audit_build=${AXI_AUDIT_BUILD:-$audit_root/build/audit40-security}
audit_cc=${CC:-cc}
audit_flags=${AXI_AUDIT_CFLAGS:--std=c99 -Wall -Wextra -Werror -O2 -g -D_POSIX_C_SOURCE=200809L}
sh "$audit_root/tests/audit40/security.sh" W21
audit_modes="$*"
mkdir -p "$audit_build/faults"
set --
for audit_src in axi_local_attempt_v1 axi_local_epoch_v1; do
    # shellcheck disable=SC2086
    "$audit_cc" $audit_flags -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
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
"$audit_cc" $audit_flags -I"$audit_source/src" -I"$audit_source/include" -I"$audit_source/vendor" \
    -x c -c "$audit_root/tests/audit40/security_faults.inc" -o "$audit_build/faults/test.o"
# shellcheck disable=SC2086
"$audit_cc" $audit_flags "$@" "$audit_build/faults/test.o" -lm -o "$audit_build/faults/security_faults"
# shellcheck disable=SC2086
"$audit_build/faults/security_faults" $audit_modes
