#!/bin/sh
# axial public check — core golden suites only.
# SPDX-License-Identifier: LicenseRef-SPL-1.0
#
#   AXI=build/axi sh tools/check.sh
#
# Suites: lex, parse, canon (via `axi check`), types, bc round-trip,
# run goldens, eff smoke. No network, no internal harnesses.
set -u
cd "$(dirname "$0")/.."

AXI=${AXI:-build/axi}
[ -x "$AXI" ] || { echo "check: $AXI missing — run make dev"; exit 2; }
case "$AXI" in
    /*) AXI_REAL=$AXI ;;
    *) AXI_REAL=$PWD/$AXI ;;
esac
TMPROOT=${AXI_TMPDIR:-build/tmp}
mkdir -p "$TMPROOT" || exit 2
TMPD=$(mktemp -d "$TMPROOT/axi-check.XXXXXX") || exit 2
trap 'rm -rf "$TMPD"' EXIT HUP INT TERM

# Ephemeral test identity (fixed vector, never shipped): seed bytes
# 0x00..0x1f with its matching Ed25519 public key. Octal escapes keep
# this portable to POSIX sh (dash printf has no \xNN). The toolchain
# signs test artifacts and verifies them, like production, but with
# throwaway keys generated fresh on every run.
printf '\000\001\002\003\004\005\006\007\010\011\012\013\014\015\016\017\020\021\022\023\024\025\026\027\030\031\032\033\034\035\036\037' >"$TMPD/test.seed"
printf '03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8' | xxd -r -p >"$TMPD/test.pk"
SEED="$TMPD/test.seed"
PUB="$TMPD/test.pk"

pass=0; fail=0
ok() { pass=$((pass + 1)); printf 'PASS %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1: $2"; }

run_golden_suite() {
    suite=$1
    command=$2
    for source in tests/"$suite"/*.axi; do
        [ -e "$source" ] || continue
        base=${source%.axi}
        actual=$("$AXI_REAL" "$command" "$source" 2>&1)
        actual_rc=$?
        expected=$(cat "$base.out" 2>/dev/null || printf '<missing golden %s.out>' "$base")
        expected_rc=$(cat "$base.rc" 2>/dev/null || printf '0')
        name="$suite/$(basename "$source")"
        if [ "$actual" = "$expected" ] && [ "$actual_rc" = "$expected_rc" ]; then
            ok "$name"
        else
            bad "$name" "rc=$actual_rc want=$expected_rc"
        fi
    done
}

run_golden_suite lex lex
run_golden_suite parse parse
run_golden_suite canon check
run_golden_suite types types
run_golden_suite iface iface

if "$AXI_REAL" selftest >/dev/null 2>&1; then ok hash/vectors; else bad hash/vectors "selftest"; fi

# Bytecode round-trip: asm -> dis -> asm is byte-identical.
for source in tests/bc/*.axs; do
    [ -e "$source" ] || continue
    name=$(basename "$source")
    case "$name" in
    bad-*)
        if ! "$AXI_REAL" asm "$source" -o "$TMPD/bad.axb" --signing-key "$SEED" >/dev/null 2>&1 \
           && [ ! -e "$TMPD/bad.axb" ]; then
            ok "bc/$name"
        else
            bad "bc/$name" "bad input assembled"
        fi
        ;;
    *)
        if "$AXI_REAL" asm "$source" -o "$TMPD/a1.axb" --signing-key "$SEED" >/dev/null 2>&1 \
           && "$AXI_REAL" dis "$TMPD/a1.axb" --trusted-key "$PUB" >"$TMPD/a1.axs" 2>/dev/null \
           && "$AXI_REAL" asm "$TMPD/a1.axs" -o "$TMPD/a2.axb" --signing-key "$SEED" >/dev/null 2>&1 \
           && cmp -s "$TMPD/a1.axb" "$TMPD/a2.axb"; then
            ok "bc/$name"
        else
            bad "bc/$name" "round-trip mismatch"
        fi
        ;;
    esac
done

# Runtime goldens.
for source in tests/run/*.axs; do
    [ -e "$source" ] || continue
    name=$(basename "$source" .axs)
    base=${source%.axs}
    if ! "$AXI_REAL" asm "$source" -o "$TMPD/run.axb" --signing-key "$SEED" >/dev/null 2>&1; then
        bad "run/$name" "asm failed"
        continue
    fi
    # shellcheck disable=SC2046
    actual_raw=$("$AXI_REAL" run "$TMPD/run.axb" $(cat "$base.cmd") --trusted-key "$PUB" 2>&1)
    actual_rc=$?
    actual=$(printf '%s\n' "$actual_raw" | sed "s|$TMPD|<tmp>|g")
    expected=$(cat "$base.out" 2>/dev/null || printf '<missing golden>')
    expected_rc=$(cat "$base.rc" 2>/dev/null || printf '0')
    if [ "$actual" = "$expected" ] && [ "$actual_rc" = "$expected_rc" ]; then
        ok "run/$name"
    else
        bad "run/$name" "rc=$actual_rc want=$expected_rc"
    fi
done

printf 'axial check: %s PASS, %s FAIL\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
