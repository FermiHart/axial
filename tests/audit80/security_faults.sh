#!/bin/sh
# Compile only the attempt owner with fsync name redirection. No product hook.
set -eu
audit_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
audit_source=${AXI_AUDIT_SOURCE_ROOT:-$audit_root}
audit_build=${AXI_AUDIT_BUILD:-$audit_root/build/audit80-security}
audit_cc=${CC:-cc}
audit_flags=${AXI_AUDIT_CFLAGS:--std=c99 -Wall -Wextra -Werror -O2 -g -D_POSIX_C_SOURCE=200809L}
AXI_AUDIT_BUILD_ONLY=1 sh "$audit_root/tests/audit80/security.sh"
mkdir -p "$audit_build/faults"
# shellcheck disable=SC2086
"$audit_cc" $audit_flags -I"$audit_source/src" -I"$audit_source/include" -I"$audit_source/vendor" \
    -Dfsync=audit80_fsync -c "$audit_source/src/axi_local_attempt_v1.c" \
    -o "$audit_build/faults/axi_local_attempt_v1.o"
set -- "$audit_build/faults/axi_local_attempt_v1.o"
for audit_object in "$audit_build"/*.o; do
    case "$audit_object" in */axi_local_attempt_v1.o|*/security.o) continue ;; esac
    set -- "$@" "$audit_object"
done
# shellcheck disable=SC2086
"$audit_cc" $audit_flags -I"$audit_source/src" -I"$audit_source/include" -I"$audit_source/vendor" \
    -x c -c "$audit_root/tests/audit80/security_faults.inc" -o "$audit_build/faults/test.o"
# shellcheck disable=SC2086
"$audit_cc" $audit_flags "$@" "$audit_build/faults/test.o" -lm -o "$audit_build/faults/security_faults"
[ "${AXI_AUDIT_BUILD_ONLY:-0}" = 1 ] && exit 0
"$audit_build/faults/security_faults"
