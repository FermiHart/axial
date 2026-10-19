# axial — public build. SPDX-License-Identifier: LicenseRef-SPL-1.0
# No network or dependencies beyond a C99 compiler and POSIX build tools.
.DEFAULT_GOAL := all

HOSTCC ?= cc
CPPFLAGS ?=
CFLAGS ?= -std=c99 -Wall -Wextra -Werror -O1 -D_POSIX_C_SOURCE=200809L
LDFLAGS ?=
LDLIBS ?= -lm
BUILD ?= build

AXI := $(BUILD)/axi
DEMO := $(BUILD)/jash_policy_demo
CORE_SRC := $(filter-out src/axi_main.c src/axi_dossier_main.c,$(wildcard src/*.c)) vendor/ed25519.c
CORE_OBJ := $(patsubst %.c,$(BUILD)/%.o,$(CORE_SRC))
AXI_OBJ := $(CORE_OBJ) $(BUILD)/src/axi_main.o
DEMO_OBJ := $(CORE_OBJ) $(BUILD)/scripts/jash_policy_demo.o
AXI_INC := -Isrc -Iinclude -Ivendor
CONFIG := $(BUILD)/.build-config

.PHONY: all dev demo gate-fast gate clean FORCE
all: dev
dev: $(AXI)
demo: $(DEMO)

$(AXI): $(AXI_OBJ)
	$(HOSTCC) $(LDFLAGS) -o $@ $(AXI_OBJ) $(LDLIBS)

$(DEMO): $(DEMO_OBJ)
	$(HOSTCC) $(LDFLAGS) -o $@ $(DEMO_OBJ) $(LDLIBS)

# Keep a content-stable stamp: header edits and changes of compiler/flags
# invalidate their objects, while an unchanged invocation compiles nothing.
$(CONFIG): FORCE | $(BUILD)
	@printf '%s\n' '$(HOSTCC)' '$(CPPFLAGS)' '$(CFLAGS)' '$(LDFLAGS)' '$(LDLIBS)' > $@.tmp
	@cmp -s $@.tmp $@ || mv $@.tmp $@
	@rm -f $@.tmp

$(BUILD)/%.o: %.c $(CONFIG)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(CPPFLAGS) $(CFLAGS) $(AXI_INC) -MMD -MP -c -o $@ $<

$(BUILD):
	mkdir -p $@

gate-fast: dev
	AXI=$(abspath $(AXI)) sh tools/check.sh

gate: gate-fast

clean:
	rm -rf $(BUILD)

-include $(AXI_OBJ:.o=.d) $(DEMO_OBJ:.o=.d)
