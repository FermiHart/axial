#!/bin/sh
# Real signed-CLI integration, including effect/refusal and replay boundaries.
# SPDX-License-Identifier: LicenseRef-SPL-1.0
set -eu
cd "$(dirname "$0")/../.."
AXI=${AXI:-build/axi}
case "$AXI" in /*) ;; *) AXI=$PWD/$AXI ;; esac
TMPROOT=${AXI_TMPDIR:-build/tmp}
mkdir -p "$TMPROOT"
TMPD=$(mktemp -d "$TMPROOT/axi-audit-cli.XXXXXX")
trap 'rm -rf "$TMPD"' EXIT HUP INT TERM
. ./tools/test-identity.sh
axi_test_identity "$TMPD"
axi_test_recorder_identity "$TMPD"
SEED=$TMPD/test.seed
PK=$TMPD/test.pk
RSEED=$TMPD/recorder.seed
RPK=$TMPD/recorder.pk
pass=0
fail=0
ok() { pass=$((pass + 1)); printf 'PASS cli/%s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL cli/%s\n' "$1"; }
expect_ok() {
    name=$1; shift
    if "$@" >"$TMPD/out" 2>"$TMPD/err"; then ok "$name";
    else bad "$name"; cat "$TMPD/err"; fi
}
expect_value() {
    name=$1; want=$2; shift 2
    if "$@" >"$TMPD/out" 2>"$TMPD/err" && [ "$(cat "$TMPD/out")" = "$want" ]; then
        ok "$name"
    else bad "$name"; cat "$TMPD/out" "$TMPD/err"; fi
}
expect_refused() {
    name=$1; shift
    if "$@" >"$TMPD/out" 2>"$TMPD/err"; then bad "$name";
    elif [ -s "$TMPD/out" ]; then bad "$name/nonempty-success-stream";
    else ok "$name"; fi
}

expect_ok signed-compile "$AXI" compile tests/hello.axi -o "$TMPD/hello.axb" --signing-key "$SEED"
expect_value compiled-result 'u64 42' "$AXI" run "$TMPD/hello.axb" hello 20 22 --trusted-key "$PK"
expect_refused wrong-producer "$AXI" run "$TMPD/hello.axb" hello 20 22 --trusted-key "$RPK"
expect_refused missing-signing-key "$AXI" compile tests/hello.axi -o "$TMPD/unsigned.axb"
if [ ! -e "$TMPD/unsigned.axb" ]; then ok no-unsigned-output; else bad no-unsigned-output; fi
for verb in dis inspect verify check-seal; do
    expect_refused "$verb/missing-trust" "$AXI" "$verb" "$TMPD/hello.axb"
done
expect_refused run/missing-trust "$AXI" run "$TMPD/hello.axb" hello 20 22
cp "$TMPD/hello.axb" "$TMPD/tampered.axb"
printf '\377' | dd of="$TMPD/tampered.axb" bs=1 seek=0 conv=notrunc 2>/dev/null
expect_refused tampered-module "$AXI" verify "$TMPD/tampered.axb" --trusted-key "$PK"

expect_ok green-seal "$AXI" seal tests/seal/green-add2.axs -o "$TMPD/checked.axb" --signing-key "$SEED"
expect_ok check-seal "$AXI" check-seal "$TMPD/checked.axb" --trusted-key "$PK"
expect_value checked-result 'u64 42' "$AXI" run "$TMPD/checked.axb" add2 40 --trusted-key "$PK"
expect_refused unchecked-certificate "$AXI" check-seal "$TMPD/hello.axb" --trusted-key "$PK"
for source in tests/seal/red-*.axs; do
    [ -f "$source" ] || { bad red-seal/empty-suite; continue; }
    label=$(basename "$source" .axs)
    expect_refused "$label" "$AXI" seal "$source" -o "$TMPD/$label.axb" --signing-key "$SEED"
    if [ ! -e "$TMPD/$label.axb" ]; then ok "$label/no-artifact"; else bad "$label/no-artifact"; fi
done

expect_ok assemble-fuel "$AXI" asm tests/fuel/cost.axs -o "$TMPD/fuel.axb" --signing-key "$SEED"
expect_value exact-fuel 'u64 2' "$AXI" run "$TMPD/fuel.axb" main --fuel 3 --trusted-key "$PK"
expect_refused exhausted-fuel "$AXI" run "$TMPD/fuel.axb" main --fuel 2 --trusted-key "$PK"
expect_refused overflowing-fuel "$AXI" run "$TMPD/fuel.axb" main --fuel 18446744073709551616 --trusted-key "$PK"

mkdir "$TMPD/fs"
FSROOT=$(cd "$TMPD/fs" && pwd)
cp tests/eff/data.txt "$FSROOT/data.txt"
expect_ok assemble-fs-read "$AXI" asm tests/eff/fs-read.axs -o "$TMPD/read.axb" --signing-key "$SEED"
expect_value confined-read 'str 24 617869616c2066732e52656164207465737420646174610a' "$AXI" run "$TMPD/read.axb" test_fs_read --cap fs.Read --fs-root "$FSROOT" --trusted-key "$PK"
expect_refused read/no-grant "$AXI" run "$TMPD/read.axb" test_fs_read --fs-root "$FSROOT" --trusted-key "$PK"
expect_ok assemble-fs-write "$AXI" asm tests/eff/fs-write.axs -o "$TMPD/write.axb" --signing-key "$SEED"
expect_refused write/no-grant "$AXI" run "$TMPD/write.axb" test_fs_write --fs-root "$FSROOT" --trusted-key "$PK"
if [ ! -e "$FSROOT/written.txt" ]; then ok no-ungranted-mutation; else bad no-ungranted-mutation; fi
expect_value confined-write 'u64 17' "$AXI" run "$TMPD/write.axb" test_fs_write --cap fs.Write --fs-root "$FSROOT" --trusted-key "$PK" --deadline-ms 2000
if [ "$(cat "$FSROOT/written.txt")" = 'gate test content' ]; then ok written-content; else bad written-content; fi

# Use independent public fixture identities for the producer and recorder.
expect_ok assemble-record "$AXI" asm tests/eff/hello.axs -o "$TMPD/io.axb" --signing-key "$SEED"
expect_value signed-record 'metal na veiau64 13' "$AXI" run "$TMPD/io.axb" main --cap io.Write --trusted-key "$PK" --record "$TMPD/io.axr" --recorder-key "$RSEED"
expect_value signed-replay 'u64 13' "$AXI" replay "$TMPD/io.axr" "$TMPD/io.axb" main --cap io.Write --trusted-key "$PK" --recorder-key "$RPK"
expect_refused replay/wrong-recorder "$AXI" replay "$TMPD/io.axr" "$TMPD/io.axb" main --cap io.Write --trusted-key "$PK" --recorder-key "$PK"
cp "$TMPD/io.axr" "$TMPD/bad.axr"
printf '\377' | dd of="$TMPD/bad.axr" bs=1 seek=0 conv=notrunc 2>/dev/null
expect_refused replay/tampered "$AXI" replay "$TMPD/bad.axr" "$TMPD/io.axb" main --cap io.Write --trusted-key "$PK" --recorder-key "$RPK"
# W20 must reject this configuration before the io.Write side effect.
expect_refused recorder/preflight-distinct-key "$AXI" run "$TMPD/io.axb" main --cap io.Write --trusted-key "$PK" --record "$TMPD/same-key.axr" --recorder-key "$SEED"

printf 'audit CLI: %s PASS, %s FAIL\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
