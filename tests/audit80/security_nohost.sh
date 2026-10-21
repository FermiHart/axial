#!/bin/sh
# Compile out the host provider without disabling the portable core objects.
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
mkdir -p "$audit_build/nohost"
# shellcheck disable=SC2086
$audit_cc $audit_cppflags $audit_flags -DAXI_LOCAL_AUTHORITY_NO_HOST \
    -I"$audit_source/src" -I"$audit_source/include" -I"$audit_source/vendor" \
    -c "$audit_source/src/axi_local_authority_v1.c" -o "$audit_build/nohost/axi_local_authority_v1.o"
set -- "$audit_build/nohost/axi_local_authority_v1.o"
for audit_object in "$audit_build"/*.o; do
    case "$audit_object" in */axi_local_authority_v1.o|*/security.o) continue ;; esac
    set -- "$@" "$audit_object"
done
# shellcheck disable=SC2086
$audit_cc $audit_cppflags $audit_flags \
    -I"$audit_source/src" -I"$audit_source/include" -I"$audit_source/vendor" \
    -x c -c "$audit_root/tests/audit80/security_nohost.inc" -o "$audit_build/nohost/test.o"
# shellcheck disable=SC2086
$audit_cc $audit_flags "$@" "$audit_build/nohost/test.o" $audit_ldflags -o "$audit_build/nohost/security_nohost" $audit_ldlibs
[ "${AXI_AUDIT_BUILD_ONLY:-0}" = 1 ] && exit 0
"$audit_build/nohost/security_nohost"
