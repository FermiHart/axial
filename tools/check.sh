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

# One portable, deterministic public test identity; no xxd dependency.
. ./tools/test-identity.sh
axi_test_identity "$TMPD" || { echo "check: test identity setup failed"; exit 2; }
SEED="$TMPD/test.seed"
PUB="$TMPD/test.pk"

pass=0; fail=0
ok() { pass=$((pass + 1)); printf 'PASS %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1: $2"; }

run_golden_suite() {
    suite=$1
    command=$2
    set -- tests/"$suite"/*.axi
    [ -e "$1" ] || { bad "$suite" "required suite is empty"; return; }
    for source do
        base=${source%.axi}
        [ -f "$base.out" ] || { bad "$base" "missing golden output"; continue; }
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
set -- tests/bc/*.axs
[ -e "$1" ] || bad bc "required suite is empty"
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
set -- tests/run/*.axs
[ -e "$1" ] || bad run "required suite is empty"
for source in tests/run/*.axs; do
    [ -e "$source" ] || continue
    name=$(basename "$source" .axs)
    base=${source%.axs}
    if [ ! -f "$base.cmd" ] || [ ! -f "$base.out" ]; then
        bad "run/$name" "missing command or golden output"
        continue
    fi
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
