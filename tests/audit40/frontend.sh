#!/bin/sh
# Audit40 W01-W10 standalone regression driver. No production keys or network.
set -eu
cd "$(dirname "$0")/../.."
AXI=${1:-build/axi}
HOSTCC=${HOSTCC:-cc}
CFLAGS=${CFLAGS:--std=c99 -O1 -Wall -Wextra -Werror}
TEST_BUILD=${AXI_TEST_BUILD:-build/audit40-frontend}
mkdir -p "$TEST_BUILD"
SAN_FLAGS=
if [ "${SANITIZE:-0}" = 1 ]; then
    SAN_FLAGS='-g -fsanitize=address,undefined -fno-omit-frame-pointer'
fi

# Intentional flag splitting; no eval and no shell execution from source data.
"$HOSTCC" $CFLAGS $SAN_FLAGS -Isrc -Iinclude -Ivendor \
    tests/audit40/frontend_diag.c src/axi_lex.c src/axi_diag.c src/axi_alloc.c \
    src/axi_compile_budget.c src/axi_mem_account.c \
    -o "$TEST_BUILD/diag"
"$TEST_BUILD/diag"
"$HOSTCC" $CFLAGS $SAN_FLAGS -Isrc \
    tests/audit40/frontend_json.c src/axi_json.c -o "$TEST_BUILD/json"
"$TEST_BUILD/json"
"$HOSTCC" $CFLAGS $SAN_FLAGS -DAXI_ALLOC_FAILPOINT -DAXI_TEST_ALLOCATION_TRACKING \
    -ffunction-sections -fdata-sections -Isrc -Iinclude -Ivendor \
    tests/audit40/frontend_parser.c src/axi_parse.c src/axi_lex.c src/axi_diag.c \
    src/axi_alloc.c src/axi_compile_budget.c src/axi_mem_account.c \
    src/axi_cap_table.c -Wl,--gc-sections \
    -Wl,--wrap=calloc -Wl,--wrap=free -o "$TEST_BUILD/parser"
python3 tests/audit40/frontend_parser.py "$TEST_BUILD/parser"
"$HOSTCC" $CFLAGS $SAN_FLAGS -fshort-enums \
    -DAXI_ALLOC_FAILPOINT -DAXI_TEST_ALLOCATION_TRACKING \
    -ffunction-sections -fdata-sections -Isrc -Iinclude -Ivendor \
    tests/audit40/frontend_parser.c src/axi_parse.c src/axi_lex.c src/axi_diag.c \
    src/axi_alloc.c src/axi_compile_budget.c src/axi_mem_account.c \
    src/axi_cap_table.c -Wl,--gc-sections \
    -Wl,--wrap=calloc -Wl,--wrap=free -o "$TEST_BUILD/parser-short-enums"
python3 tests/audit40/frontend_parser.py "$TEST_BUILD/parser-short-enums"
python3 tests/audit40/frontend_codegen.py "$AXI" all
