#!/bin/sh
set -eu
audit_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
audit_source=${AXI_AUDIT_SOURCE_ROOT:-$audit_root}
audit_build=${AXI_AUDIT_BUILD:-$audit_root/build/audit40-security}
audit_cc=${CC:-cc}
audit_flags=${AXI_AUDIT_CFLAGS:--std=c99 -Wall -Wextra -Werror -O2 -g -D_POSIX_C_SOURCE=200809L}
sh "$audit_root/tests/audit40/security.sh" W21
audit_modes="$*"
mkdir -p "$audit_build/costs"
set --
for audit_src in axi_selective_disclosure_v1 axi_delegation_v1; do
    # shellcheck disable=SC2086
    "$audit_cc" $audit_flags -I"$audit_source/src" -I"$audit_source/include" -I"$audit_source/vendor" \
        -Daxi_sha256=audit_count_hash -c "$audit_source/src/$audit_src.c" -o "$audit_build/costs/$audit_src.o"
    set -- "$@" "$audit_build/costs/$audit_src.o"
done
for audit_object in "$audit_build"/*.o; do
    case "$audit_object" in */axi_selective_disclosure_v1.o|*/axi_delegation_v1.o|*/security.o) continue ;; esac
    set -- "$@" "$audit_object"
done
# shellcheck disable=SC2086
"$audit_cc" $audit_flags -I"$audit_source/src" -I"$audit_source/include" -I"$audit_source/vendor" \
    -x c -c "$audit_root/tests/audit40/security_costs.inc" -o "$audit_build/costs/test.o"
# shellcheck disable=SC2086
"$audit_cc" $audit_flags "$@" "$audit_build/costs/test.o" -lm -o "$audit_build/costs/security_costs"
# shellcheck disable=SC2086
"$audit_build/costs/security_costs" $audit_modes
