# axial — public build. SPDX-License-Identifier: LicenseRef-SPL-1.0
# Build: C99 compiler and POSIX tools. Identity/full audit gates also use Python 3.
.DEFAULT_GOAL := all

HOSTCC ?= cc
PYTHON ?= python3
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
AUDIT_SRC := $(filter-out tests/audit40/frontend_%.c tests/audit40/runtime_bench.c,$(wildcard tests/audit40/*.c))
AUDIT_BIN := $(patsubst tests/audit40/%.c,$(BUILD)/audit40/%,$(AUDIT_SRC))
.SECONDARY: $(patsubst %.c,$(BUILD)/%.o,$(AUDIT_SRC)) $(BUILD)/tests/audit40/runtime_bench.o
AXI_INC := -Isrc -Iinclude -Ivendor
CONFIG := $(BUILD)/.build-config

.PHONY: all dev release demo gate-fast gate-cli gate-audit gate-identity gate-frontend gate-security gate-workers gate bench clean FORCE
all: dev
dev: $(AXI)
release:
	$(MAKE) BUILD='$(BUILD)-release' CFLAGS='$(filter-out -O%,$(CFLAGS)) -O2' dev
demo: $(DEMO)

$(AXI): $(AXI_OBJ)
	$(HOSTCC) $(LDFLAGS) -o $@ $(AXI_OBJ) $(LDLIBS)

$(DEMO): $(DEMO_OBJ)
	$(HOSTCC) $(LDFLAGS) -o $@ $(DEMO_OBJ) $(LDLIBS)

$(BUILD)/audit40/%: $(BUILD)/tests/audit40/%.o $(CORE_OBJ)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

# This test includes the private handle implementation to reach counter
# exhaustion without billions of operations; do not link a second copy.
$(BUILD)/audit40/runtime_handles: $(BUILD)/tests/audit40/runtime_handles.o
	@mkdir -p $(dir $@)
	$(HOSTCC) $(LDFLAGS) -o $@ $< $(LDLIBS)

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

gate-cli: dev
	AXI=$(abspath $(AXI)) sh tests/audit40/cli.sh

gate-audit: $(AUDIT_BIN)
	@set -e; for test in $(AUDIT_BIN); do "$$test"; done

gate-identity:
	$(PYTHON) tools/axi-checker-identity.py --check

gate-frontend: dev
	HOSTCC='$(HOSTCC)' CFLAGS='$(CFLAGS)' AXI_TEST_BUILD='$(BUILD)/audit40-frontend' sh tests/audit40/frontend.sh $(abspath $(AXI))

gate-security:
	CC='$(HOSTCC)' AXI_AUDIT_CFLAGS='$(CFLAGS)' AXI_AUDIT_BUILD='$(abspath $(BUILD))/audit40-security' sh tests/audit40/security_faults.sh
	CC='$(HOSTCC)' AXI_AUDIT_CFLAGS='$(CFLAGS)' AXI_AUDIT_BUILD='$(abspath $(BUILD))/audit40-security' sh tests/audit40/security_costs.sh

gate-workers: $(BUILD)/audit40/runtime
	$< --workers

gate: gate-identity gate-fast gate-cli gate-audit gate-frontend gate-security gate-workers

# Build probes only; measurements are opt-in and have no speed thresholds.
bench: $(BUILD)/audit40/embed $(BUILD)/audit40/seal $(BUILD)/audit40/runtime_bench

clean:
	rm -rf $(BUILD)

-include $(AXI_OBJ:.o=.d) $(DEMO_OBJ:.o=.d) $(patsubst %.c,$(BUILD)/%.d,$(AUDIT_SRC)) $(BUILD)/tests/audit40/runtime_bench.d
