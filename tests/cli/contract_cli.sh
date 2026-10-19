#!/bin/sh
set -eu

AXI=${1:?usage: contract_cli.sh AXI CONTRACT_GUARD}
GUARD=${2:?usage: contract_cli.sh AXI CONTRACT_GUARD}
TMPROOT=${AXI_TMPDIR:-build/tmp}
mkdir -p "$TMPROOT"
TMP=$(mktemp -d "$TMPROOT/axi-cli-parity.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
STAGE="$TMP/fixture.stage"
FIXTURE="$TMP/fixture"
mkdir "$STAGE"

"$GUARD" cli-fixture "$STAGE"
[ "$(wc -c < "$STAGE/producer.seed")" -eq 32 ]
[ "$(wc -c < "$STAGE/producer.pk")" -eq 32 ]
[ "$(wc -c < "$STAGE/recorder.pk")" -eq 32 ]
mv "$STAGE" "$FIXTURE"

MODULE="$FIXTURE/module.axb"
UNSIGNED="$FIXTURE/unsigned.axb"
PRODUCER_SEED="$FIXTURE/producer.seed"
PRODUCER_PK="$FIXTURE/producer.pk"
WRONG_PK="$FIXTURE/wrong.pk"
REPLAY="$FIXTURE/replay.axr"
RECORDER_PK="$FIXTURE/recorder.pk"
LEGACY_V5="$FIXTURE/legacy-v5.axb"

$AXI asm tests/run/fib.axs -o "$TMP/asm.axb" --signing-key "$PRODUCER_SEED"
$AXI verify "$TMP/asm.axb" --trusted-key "$PRODUCER_PK" >/dev/null
$AXI bind "$TMP/asm.axb" tests/run/fib.axs \
  --trusted-key "$PRODUCER_PK" >/dev/null
[ "$($AXI run "$TMP/asm.axb" fib 10 --trusted-key "$PRODUCER_PK")" = "u64 55" ] || {
  echo "cli-parity: signed asm artifact did not execute through trusted v7" >&2; exit 1
}

$AXI compile tests/hello.axi -o "$TMP/compile.axb" --signing-key "$PRODUCER_SEED"
[ "$($AXI run "$TMP/compile.axb" hello 20 22 --trusted-key "$PRODUCER_PK")" = "u64 42" ] || {
  echo "cli-parity: signed compile artifact did not execute through trusted v7" >&2; exit 1
}

$AXI seal tests/seal/green-add2.axs -o "$TMP/seal.axb" \
  --signing-key "$PRODUCER_SEED" >/dev/null
$AXI asm tests/seal/green-add2.axs -o "$TMP/seal-asm.axb" \
  --signing-key "$PRODUCER_SEED"
if cmp -s "$TMP/seal-asm.axb" "$TMP/seal.axb"; then
  echo "cli-parity: asm artifact is indistinguishable from checked seal" >&2
  exit 1
fi
$AXI check-seal "$TMP/seal.axb" --trusted-key "$PRODUCER_PK" >/dev/null
if $AXI check-seal "$TMP/seal-asm.axb" --trusted-key "$PRODUCER_PK" \
    >"$TMP/refused.out" 2>/dev/null; then
  echo "cli-parity: proof-required admission accepted ordinary asm" >&2
  exit 1
fi
[ ! -s "$TMP/refused.out" ] || {
  echo "cli-parity: unchecked refusal published a success token" >&2
  exit 1
}
[ "$($AXI run "$TMP/seal.axb" add2 40 --trusted-key "$PRODUCER_PK")" = "u64 42" ] || {
  echo "cli-parity: checked seal artifact did not execute through trusted v7" >&2; exit 1
}

if $AXI asm tests/run/fib.axs -o "$TMP/refused.axb" >"$TMP/refused.out" 2>/dev/null; then
  echo "cli-parity: asm accepted no operator signing key" >&2; exit 1
fi
[ ! -e "$TMP/refused.axb" ] || { echo "cli-parity: unsigned writer published output" >&2; exit 1; }

if $AXI dis "$MODULE" >"$TMP/refused.out" 2>/dev/null \
    || $AXI inspect "$MODULE" >"$TMP/refused.out" 2>/dev/null \
    || $AXI run "$MODULE" caller 41 >"$TMP/refused.out" 2>/dev/null \
    || $AXI replay "$REPLAY" "$MODULE" caller 41 \
         >"$TMP/refused.out" 2>/dev/null; then
  echo "cli-parity: a production consumer accepted missing external trust" >&2; exit 1
fi
[ ! -s "$TMP/refused.out" ] || { echo "cli-parity: trust refusal published output" >&2; exit 1; }

if $AXI inspect "$LEGACY_V5" --trusted-key "$PRODUCER_PK" \
  >"$TMP/refused.out" 2>/dev/null; then
  echo "cli-parity: production inspect admitted AXB v5" >&2; exit 1
fi
[ ! -s "$TMP/refused.out" ] || { echo "cli-parity: v5 refusal published output" >&2; exit 1; }

dis=$($AXI dis "$MODULE" --trusted-key "$PRODUCER_PK")
case "$dis" in
  *"  contract 1"*"    fuel 50"*) ;;
  *) echo "cli-parity: dis omitted admitted contract" >&2; exit 1 ;;
esac

inspect=$($AXI inspect "$MODULE" --trusted-key "$PRODUCER_PK")
case "$inspect" in
  *"format 7"*"trusted "*"seal UNCHECKED"*"cell 0 caller"*) ;;
  *) echo "cli-parity: inspect omitted admitted facts" >&2; exit 1 ;;
esac

seal_inspect=$($AXI inspect "$TMP/seal.axb" --trusted-key "$PRODUCER_PK")
case "$seal_inspect" in
  *"format 7"*"seal CHECKED"*"subject "*"checker-protocol "*) ;;
  *) echo "cli-parity: inspect omitted checked-seal evidence" >&2; exit 1 ;;
esac

run=$($AXI run "$MODULE" caller 41 --trusted-key "$PRODUCER_PK")
[ "$run" = "u64 42" ] || {
  echo "cli-parity: run diverged from contract runtime" >&2
  exit 1
}

terminated=$($AXI run "$MODULE" caller --trusted-key "$PRODUCER_PK" -- 41)
[ "$terminated" = "u64 42" ] || {
  echo "cli-parity: -- did not terminate trusted run option parsing" >&2
  exit 1
}

if $AXI run "$MODULE" caller 18446744073709551616 \
  --trusted-key "$PRODUCER_PK" >"$TMP/refused.out" 2>/dev/null; then
  echo "cli-parity: u64 above UINT64_MAX was accepted" >&2
  exit 1
fi
[ ! -s "$TMP/refused.out" ] || {
  echo "cli-parity: numeric range refusal published output" >&2
  exit 1
}

replay=$($AXI replay "$REPLAY" "$MODULE" caller 41 \
  --trusted-key "$PRODUCER_PK" --recorder-key "$RECORDER_PK")
[ "$replay" = "u64 42" ] || {
  echo "cli-parity: replay diverged from bound terminal" >&2
  exit 1
}

terminated_replay=$($AXI replay "$REPLAY" "$MODULE" caller \
  --trusted-key "$PRODUCER_PK" --recorder-key "$RECORDER_PK" -- 41)
[ "$terminated_replay" = "u64 42" ] || {
  echo "cli-parity: -- did not terminate trusted replay option parsing" >&2
  exit 1
}

out="$TMP/refused.out"
if $AXI run "$MODULE" caller 41 --trusted-key "$WRONG_PK" >"$out" 2>/dev/null; then
  echo "cli-parity: wrong producer trust was accepted" >&2
  exit 1
fi
[ ! -s "$out" ] || { echo "cli-parity: wrong trust published output" >&2; exit 1; }

if $AXI replay "$REPLAY" "$MODULE" caller 41 \
  --trusted-key "$PRODUCER_PK" --recorder-key "$WRONG_PK" >"$out" 2>/dev/null; then
  echo "cli-parity: wrong recorder trust was accepted" >&2
  exit 1
fi
[ ! -s "$out" ] || { echo "cli-parity: replay refusal published output" >&2; exit 1; }

if $AXI inspect "$UNSIGNED" --trusted-key "$PRODUCER_PK" >"$out" 2>/dev/null; then
  echo "cli-parity: unsigned v7 was inspected as trusted" >&2
  exit 1
fi
[ ! -s "$out" ] || { echo "cli-parity: unsigned refusal published facts" >&2; exit 1; }

printf '%s\n' "cli-parity: PASS (real CLI trusted run/replay/inspect/dis and fail-atomic refusals)"
