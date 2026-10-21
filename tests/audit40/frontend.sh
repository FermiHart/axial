#!/bin/sh
# Audit40 W01-W10 standalone regression driver. No production keys or network.
set -eu
cd "$(dirname "$0")/../.."
AXI=${1:-build/axi}
HOSTCC=${HOSTCC:-${CC:-cc}}
CPPFLAGS=${CPPFLAGS-}
CFLAGS=${CFLAGS--std=c99 -O1 -Wall -Wextra -Werror}
LDFLAGS=${LDFLAGS-}
LDLIBS=${LDLIBS--lm}
PYTHON=${PYTHON:-python3}
TEST_BUILD=${AXI_TEST_BUILD:-build/audit40-frontend}
mkdir -p "$TEST_BUILD"
SAN_FLAGS=
if [ "${SANITIZE:-0}" = 1 ]; then
    SAN_FLAGS='-g -fsanitize=address,undefined -fno-omit-frame-pointer'
fi

# Intentional flag splitting; no eval and no shell execution from source data.
$HOSTCC $CPPFLAGS $CFLAGS $SAN_FLAGS -Isrc -Iinclude -Ivendor \
    tests/audit40/frontend_diag.c src/axi_lex.c src/axi_numeric.c src/axi_diag.c src/axi_alloc.c \
    src/axi_compile_budget.c src/axi_mem_account.c \
    $LDFLAGS -o "$TEST_BUILD/diag" $LDLIBS
"$TEST_BUILD/diag"
$HOSTCC $CPPFLAGS $CFLAGS $SAN_FLAGS -Isrc \
    tests/audit40/frontend_json.c src/axi_json.c $LDFLAGS -o "$TEST_BUILD/json" $LDLIBS
"$TEST_BUILD/json"
$HOSTCC $CPPFLAGS $CFLAGS $SAN_FLAGS -DAXI_ALLOC_FAILPOINT -DAXI_TEST_ALLOCATION_TRACKING \
    -ffunction-sections -fdata-sections -Isrc -Iinclude -Ivendor \
    tests/audit40/frontend_parser.c src/axi_parse.c src/axi_lex.c src/axi_numeric.c src/axi_diag.c \
    src/axi_alloc.c src/axi_compile_budget.c src/axi_mem_account.c \
    src/axi_cap_table.c -Wl,--gc-sections \
    -Wl,--wrap=calloc -Wl,--wrap=free $LDFLAGS -o "$TEST_BUILD/parser" $LDLIBS
$PYTHON tests/audit40/frontend_parser.py "$TEST_BUILD/parser"
$HOSTCC $CPPFLAGS $CFLAGS $SAN_FLAGS -fshort-enums \
    -DAXI_ALLOC_FAILPOINT -DAXI_TEST_ALLOCATION_TRACKING \
    -ffunction-sections -fdata-sections -Isrc -Iinclude -Ivendor \
    tests/audit40/frontend_parser.c src/axi_parse.c src/axi_lex.c src/axi_numeric.c src/axi_diag.c \
    src/axi_alloc.c src/axi_compile_budget.c src/axi_mem_account.c \
    src/axi_cap_table.c -Wl,--gc-sections \
    -Wl,--wrap=calloc -Wl,--wrap=free $LDFLAGS -o "$TEST_BUILD/parser-short-enums" $LDLIBS
$PYTHON tests/audit40/frontend_parser.py "$TEST_BUILD/parser-short-enums"
$PYTHON tests/audit40/frontend_codegen.py "$AXI" all
