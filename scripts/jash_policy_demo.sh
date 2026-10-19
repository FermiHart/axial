#!/bin/sh
# axial — embed API demo with examples/policy.axi.
# SPDX-License-Identifier: LicenseRef-SPL-1.0
#
# Usage: ./scripts/jash_policy_demo.sh
# Exits 0 if every labeled case matches the expected verdict.

set -eu

cd "$(dirname "$0")/.."

AXI=build/axi
POLICY=examples/policy.axi
TMPROOT=${AXI_TMPDIR:-build/tmp}
mkdir -p "$TMPROOT"
TMPD=$(mktemp -d "$TMPROOT/jash-policy-demo.XXXXXX")
MODULE="$TMPD/jash_policy_demo.axb"
DEMO=build/jash_policy_demo
TRUSTED_PK_HEX=03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8
trap 'rm -rf "$TMPD"' EXIT

[ -x "$AXI" ] || { echo "build/axi missing — run make"; exit 2; }

# Compile the policy as a signed module with explicit seed and raw public key.
"$AXI" check "$POLICY"
. ./tools/test-identity.sh
axi_test_identity "$TMPD"
KEY="$TMPD/test.seed"
PK="$TMPD/test.pk"
"$AXI" compile "$POLICY" -o "$MODULE" --signing-key "$KEY"
"$AXI" verify "$MODULE" --trusted-key "$PK" >/dev/null

# Build the embed demo from the project's own TU list.
make "$DEMO" >/dev/null

# Run exactly the contract documented by the C file and check its labels.
out=$("$DEMO" "$MODULE" "$TRUSTED_PK_HEX")

printf '%s\n' "$out"
echo

ok=1
check() {
    label=$1; want=$2
    if echo "$out" | grep -qE "$(printf '%s' "$label" | sed 's/ /[[:space:]]+/g')[[:space:]]+->[[:space:]]+$want"; then
        echo "PASS $label"
    else
        echo "FAIL $label (expected $want)"
        ok=0
    fi
}

check "rm inside workspace"  "ALLOW"
check "rm outside workspace" "DENY"
check "export secret name"   "DENY"
check "export safe name"     "ALLOW"
check "unknown builtin"      "ALLOW"

[ "$ok" = 1 ]
