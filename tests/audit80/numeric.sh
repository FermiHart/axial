#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
HOSTCC=${HOSTCC:-cc}
CFLAGS=${CFLAGS:--std=c99 -Wall -Wextra -Werror -Wpedantic -O1}
TEST_BUILD=${AXI_TEST_BUILD:-build/audit80-numeric}
mkdir -p "$TEST_BUILD"
# Intentional flag splitting. Numeric expectations do not use libc float IO.
"$HOSTCC" $CFLAGS -Isrc tests/audit80/numeric_driver.c src/axi_numeric.c \
  -o "$TEST_BUILD/core"
python3 tests/audit80/numeric.py "$TEST_BUILD/core"
"$HOSTCC" $CFLAGS -DAXI_NUMERIC_TEST_LEXER -Isrc \
  tests/audit80/numeric_driver.c src/axi_numeric.c src/axi_lex.c \
  src/axi_diag.c src/axi_alloc.c src/axi_compile_budget.c src/axi_mem_account.c -o "$TEST_BUILD/lexer"
python3 tests/audit80/numeric.py "$TEST_BUILD/lexer" reader
if [ "$#" -gt 0 ]; then
  python3 tests/audit80/numeric_cli.py "$1"
fi
