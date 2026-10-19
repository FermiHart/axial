#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
AXI=${1:-build/axi}
HOSTCC=${HOSTCC:-cc}
CFLAGS=${CFLAGS:--std=c99 -Wall -Wextra -Werror -O1}
TEST_BUILD=${AXI_TEST_BUILD:-build/audit80-frontend}
mkdir -p "$TEST_BUILD"
# Intentional compiler flag splitting. No production keys or network.
"$HOSTCC" $CFLAGS -Isrc tests/audit80/frontend_strings.c \
  src/axi_lex.c src/axi_diag.c src/axi_alloc.c -o "$TEST_BUILD/strings"
"$TEST_BUILD/strings"
python3 tests/audit80/frontend.py "$AXI" all
