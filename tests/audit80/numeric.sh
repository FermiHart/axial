#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
HOSTCC=${HOSTCC:-${CC:-cc}}
CPPFLAGS=${CPPFLAGS-}
CFLAGS=${CFLAGS--std=c99 -Wall -Wextra -Werror -Wpedantic -O1}
LDFLAGS=${LDFLAGS-}
LDLIBS=${LDLIBS--lm}
PYTHON=${PYTHON:-python3}
TEST_BUILD=${AXI_TEST_BUILD:-build/audit80-numeric}
mkdir -p "$TEST_BUILD"
# Intentional flag splitting. Numeric expectations do not use libc float IO.
$HOSTCC $CPPFLAGS $CFLAGS -Isrc tests/audit80/numeric_driver.c src/axi_numeric.c \
  $LDFLAGS -o "$TEST_BUILD/core" $LDLIBS
$PYTHON tests/audit80/numeric.py "$TEST_BUILD/core"
$HOSTCC $CPPFLAGS $CFLAGS -DAXI_NUMERIC_TEST_LEXER -Isrc \
  tests/audit80/numeric_driver.c src/axi_numeric.c src/axi_lex.c \
  src/axi_diag.c src/axi_alloc.c src/axi_compile_budget.c src/axi_mem_account.c $LDFLAGS -o "$TEST_BUILD/lexer" $LDLIBS
$PYTHON tests/audit80/numeric.py "$TEST_BUILD/lexer" reader
$HOSTCC $CPPFLAGS $CFLAGS -Isrc tests/audit80/numeric_limits.c src/axi_numeric.c \
  src/axi_lex.c src/axi_diag.c src/axi_alloc.c src/axi_compile_budget.c src/axi_mem_account.c $LDFLAGS -o "$TEST_BUILD/limits" $LDLIBS
"$TEST_BUILD/limits"
if [ "$#" -gt 0 ]; then
  $PYTHON tests/audit80/numeric_cli.py "$1"
fi
