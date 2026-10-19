#!/bin/sh
# MOAT-5 demo: one source, one sealed/signed artifact, one deploy operation.
# SPDX-License-Identifier: LicenseRef-SPL-1.0
set -eu

cd "$(dirname "$0")/.."
AXI=build/axi
TMPROOT=${AXI_TMPDIR:-build/tmp}
mkdir -p "$TMPROOT"
TMPD=$(mktemp -d "$TMPROOT/axi-supply-demo.XXXXXX")
trap 'rm -rf "$TMPD"' EXIT

SRC=scripts/demo-supply-chain.axs
ART="$TMPD/demo.axb"
SEALED="$TMPD/demo.axb.sealed"
KEY_STAGE="$TMPD/keys.stage"
KEYDIR="$TMPD/keys"
mkdir "$KEY_STAGE"
. ./tools/test-identity.sh
axi_test_identity "$KEY_STAGE"
mv "$KEY_STAGE" "$KEYDIR"
KEY="$KEYDIR/test.seed"
PK="$KEYDIR/test.pk"

# 1. source -> signed-v7 bytecode with an explicit raw Ed25519 seed
"$AXI" asm "$SRC" -o "$ART" --signing-key "$KEY"

# 2. seal: every law_* cell must judge true before signed-v7 publication
"$AXI" seal "$SRC" -o "$SEALED" --signing-key "$KEY"

# AXI-CLAIM-REF:AXI-CLAIM-014
# 3. verify: external operator trust admits the producer raw public key
"$AXI" verify "$SEALED" --trusted-key "$PK"

# 4. deploy: copy the single file and run through the same trust anchor
# (in a real deployment this is the only operation)
CP="$TMPD/deployed.axb.sealed"
cp "$SEALED" "$CP"
"$AXI" run "$CP" main --cap io.Write --trusted-key "$PK"

echo "MOAT-5 demo: compile -> signed seal -> trusted verify -> deploy -> run OK"
