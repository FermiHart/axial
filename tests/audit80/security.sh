#!/bin/sh
# Focused security regressions; supports a pristine source tree for before/after.
set -eu
audit_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
audit_source=${AXI_AUDIT_SOURCE_ROOT:-$audit_root}
audit_build=${AXI_AUDIT_BUILD:-$audit_root/build/audit80-security}
audit_cc=${CC:-cc}
audit_flags=${AXI_AUDIT_CFLAGS:--std=c99 -Wall -Wextra -Werror -O2 -g -D_POSIX_C_SOURCE=200809L}
mkdir -p "$audit_build"
# Header-only edits must also invalidate these standalone test objects.
# POSIX cksum is only a build-cache key; checker identity uses SHA-256.
audit_config=$(
    printf '%s\n' "$audit_cc $audit_flags $audit_source"
    for audit_header in "$audit_source"/src/*.h "$audit_source"/src/*.inc \
        "$audit_source"/src/*.def "$audit_source"/include/axial/*.h \
        "$audit_source"/vendor/*.h; do
        [ -f "$audit_header" ] || continue
        cksum "$audit_header"
    done
)
if [ ! -f "$audit_build/config" ] || [ "$(cat "$audit_build/config")" != "$audit_config" ]; then
    rm -f "$audit_build"/*.o "$audit_build/security"
    printf '%s\n' "$audit_config" > "$audit_build/config"
fi
set -- "$@"
audit_modes="$*"
set --
for audit_src in "$audit_source"/src/*.c "$audit_source/vendor/ed25519.c" "$audit_root/tests/audit80/security.c"; do
    case "$audit_src" in */axi_main.c|*/axi_dossier_main.c) continue ;; esac
    audit_object="$audit_build/$(basename "$audit_src" .c).o"
    if [ ! -f "$audit_object" ] || [ "$audit_src" -nt "$audit_object" ]; then
        # Flags deliberately use shell word splitting, like the public Makefile.
        # shellcheck disable=SC2086
        "$audit_cc" $audit_flags -I"$audit_source/src" -I"$audit_source/include" -I"$audit_source/vendor" -c "$audit_src" -o "$audit_object"
    fi
    set -- "$@" "$audit_object"
done
# shellcheck disable=SC2086
"$audit_cc" $audit_flags "$@" -lm -o "$audit_build/security"
[ "${AXI_AUDIT_BUILD_ONLY:-0}" = 1 ] && exit 0
# shellcheck disable=SC2086
"$audit_build/security" $audit_modes
