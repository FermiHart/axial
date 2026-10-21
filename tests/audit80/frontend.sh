#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
AXI=${1:-build/axi}
HOSTCC=${HOSTCC:-${CC:-cc}}
CPPFLAGS=${CPPFLAGS-}
CFLAGS=${CFLAGS--std=c99 -Wall -Wextra -Werror -O1}
LDFLAGS=${LDFLAGS-}
LDLIBS=${LDLIBS--lm}
PYTHON=${PYTHON:-python3}
TEST_BUILD=${AXI_TEST_BUILD:-build/audit80-frontend}
mkdir -p "$TEST_BUILD"
# Intentional compiler flag splitting. No production keys or network.
$HOSTCC $CPPFLAGS $CFLAGS -Isrc tests/audit80/frontend_strings.c \
  src/axi_lex.c src/axi_numeric.c src/axi_diag.c src/axi_alloc.c \
  src/axi_compile_budget.c src/axi_mem_account.c $LDFLAGS -o "$TEST_BUILD/strings" $LDLIBS
"$TEST_BUILD/strings"
$PYTHON tests/audit80/frontend.py "$AXI" all
