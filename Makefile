# axial — public build. SPDX-License-Identifier: LicenseRef-SPL-1.0
#
# Minimal, reproducible host build of the axial language toolchain.
# No network, no dependencies beyond a C99 compiler.
#
#   make dev        — build ./build/axi
#   make demo       — build ./build/jash_policy_demo (embed API demo)
#   make gate-fast  — build + core golden suites
#   make gate       — full local gate (same as gate-fast in the public tree)
#   make clean      — remove build outputs

HOSTCC ?= cc
CFLAGS ?= -std=c99 -Wall -Wextra -Werror -O1 -D_POSIX_C_SOURCE=200809L
LDFLAGS ?=

BUILD := build
AXI   := $(BUILD)/axi

# Product sources. axi_dossier_main.c is a separate tool entry point and
# is excluded from the axi link.
AXI_SRC := $(filter-out src/axi_dossier_main.c,$(wildcard src/*.c)) vendor/ed25519.c
AXI_INC := -Isrc -Iinclude -Ivendor

# Embed demo: same product objects, but the demo's main replaces axi's.
DEMO := $(BUILD)/jash_policy_demo
DEMO_SRC := $(filter-out src/axi_main.c src/axi_dossier_main.c,$(wildcard src/*.c)) vendor/ed25519.c scripts/jash_policy_demo.c

.PHONY: all dev demo gate-fast gate clean

all: dev

dev: $(AXI)

demo: $(DEMO)

$(DEMO): $(DEMO_SRC) | $(BUILD)
	$(HOSTCC) $(CFLAGS) $(AXI_INC) -o $@ $(DEMO_SRC) -lm

$(AXI): $(AXI_SRC) | $(BUILD)
	$(HOSTCC) $(CFLAGS) $(AXI_INC) -o $@ $(AXI_SRC) -lm

$(BUILD):
	mkdir -p $(BUILD)

gate-fast: dev
	AXI=$(abspath $(AXI)) sh tools/check.sh

gate: dev
	AXI=$(abspath $(AXI)) sh tools/check.sh

clean:
	rm -rf $(BUILD)
