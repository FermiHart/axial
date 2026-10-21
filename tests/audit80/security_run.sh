#!/bin/sh
# Execute an already-built authority fixture; never elevate its compiler.
set -eu
if [ "$#" -eq 0 ]; then
    printf '%s\n' 'usage: security_run.sh /absolute/path/security[_faults] [case]' >&2
    exit 2
fi
case "$1" in
    /*/security|/*/security_faults) ;;
    *) printf '%s\n' 'authority runner requires an absolute authority test executable path' >&2; exit 2 ;;
esac
if [ ! -f "$1" ] || [ ! -x "$1" ]; then
    printf 'authority test is not built or executable: %s\n' "$1" >&2
    exit 2
fi
audit_runner=${AUTHORITY_RUNNER:-direct}
# Explicit values cross sudo's environment boundary; do not use sudo -E/env/sh.
ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}
UBSAN_OPTIONS=${UBSAN_OPTIONS:-halt_on_error=1}
export ASAN_OPTIONS UBSAN_OPTIONS
case "$audit_runner" in
    direct)
        if "$@"; then exit 0; else audit_status=$?; fi
        ;;
    sudo)
        if ! command -v sudo >/dev/null 2>&1; then
            printf '%s\n' 'authority gate REFUSED: AUTHORITY_RUNNER=sudo requires sudo -n for the already-built test binaries' >&2
            exit 77
        fi
        if sudo -n ASAN_OPTIONS="$ASAN_OPTIONS" UBSAN_OPTIONS="$UBSAN_OPTIONS" "$@"; then
            exit 0
        else
            audit_status=$?
        fi
        ;;
    *) printf 'unknown AUTHORITY_RUNNER: %s (expected direct or sudo)\n' "$audit_runner" >&2; exit 2 ;;
esac
if [ "$audit_status" -eq 77 ]; then
    printf '%s\n' 'authority gate REFUSED: two real distinct nonzero UIDs and the Linux host provider are required; exit 77 is a failed gate, never a skip/PASS' >&2
else
    printf 'authority gate FAILED (status %s; runner=%s). See the test/sudo diagnostic above; UID setup also requires host setgroups/setgid/setreuid permission.\n' "$audit_status" "$audit_runner" >&2
fi
exit "$audit_status"
