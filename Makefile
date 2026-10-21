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
AUTHORITY_RUNNER ?= direct
TSAN_CFLAGS ?= $(filter-out -O%,$(CFLAGS)) -O1 -g -fsanitize=thread -fno-omit-frame-pointer -fno-pie
TSAN_LDFLAGS ?= $(LDFLAGS) -fsanitize=thread -no-pie

AXI := $(BUILD)/axi
DEMO := $(BUILD)/jash_policy_demo
CORE_SRC := $(filter-out src/axi_main.c src/axi_dossier_main.c,$(wildcard src/*.c)) vendor/ed25519.c
CORE_OBJ := $(patsubst %.c,$(BUILD)/%.o,$(CORE_SRC))
AXI_OBJ := $(CORE_OBJ) $(BUILD)/src/axi_main.o
DEMO_OBJ := $(CORE_OBJ) $(BUILD)/scripts/jash_policy_demo.o
AUDIT_SRC := $(filter-out tests/audit40/frontend_%.c tests/audit40/runtime_bench.c,$(wildcard tests/audit40/*.c))
AUDIT_BIN := $(patsubst tests/audit40/%.c,$(BUILD)/audit40/%,$(AUDIT_SRC))
COMPILER_AUDIT_SRC := $(wildcard tests/audit80/compiler_*.c)
COMPILER_AUDIT_BIN := $(patsubst tests/audit80/%.c,$(BUILD)/audit80/%,$(COMPILER_AUDIT_SRC))
.SECONDARY: $(patsubst %.c,$(BUILD)/%.o,$(AUDIT_SRC)) $(BUILD)/tests/audit40/runtime_bench.o
.SECONDARY: $(patsubst %.c,$(BUILD)/%.o,$(COMPILER_AUDIT_SRC))
AXI_INC := -Isrc -Iinclude -Ivendor
CONFIG := $(BUILD)/.build-config
GATE_ENV = HOSTCC='$(HOSTCC)' CPPFLAGS='$(CPPFLAGS)' CFLAGS='$(CFLAGS)' LDFLAGS='$(LDFLAGS)' LDLIBS='$(LDLIBS)' PYTHON='$(PYTHON)'
AUTHORITY_BUILD := $(abspath $(BUILD))/audit80-security
RUNTIME_CHECKS := runtime_workloads runtime_lifecycle runtime_memory runtime_stack runtime_concurrency runtime_concurrency_uncached runtime_concurrency_software runtime_io_faults runtime_recovery
TSAN_CHECKS := runtime_concurrency runtime_concurrency_uncached runtime_concurrency_software

.PHONY: all dev release demo gate-fast gate-cli gate-audit gate-identity gate-frontend gate-frontend40 gate-frontend80 gate-numeric gate-security gate-authority-build gate-authority gate-workers gate-compiler gate-runtime gate-tsan gate bench clean FORCE
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

$(BUILD)/audit80/compiler_%: $(BUILD)/tests/audit80/compiler_%.o $(CORE_OBJ)
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

gate-frontend: gate-frontend40 gate-frontend80

gate-frontend40: dev
	$(GATE_ENV) AXI_TEST_BUILD='$(abspath $(BUILD))/audit40-frontend' sh tests/audit40/frontend.sh $(abspath $(AXI))

gate-frontend80: dev
	$(GATE_ENV) AXI_TEST_BUILD='$(abspath $(BUILD))/audit80-frontend' sh tests/audit80/frontend.sh $(abspath $(AXI))

gate-numeric: dev
	$(GATE_ENV) AXI_TEST_BUILD='$(abspath $(BUILD))/audit80-numeric' sh tests/audit80/numeric.sh $(abspath $(AXI))

gate-security:
	$(GATE_ENV) AXI_AUDIT_CFLAGS='$(CFLAGS)' AXI_AUDIT_BUILD='$(abspath $(BUILD))/audit40-security' sh tests/audit40/security_faults.sh
	$(GATE_ENV) AXI_AUDIT_CFLAGS='$(CFLAGS)' AXI_AUDIT_BUILD='$(abspath $(BUILD))/audit40-security' sh tests/audit40/security_costs.sh

# All compilation runs as the invoking user. Only the two positive authority
# executables can use the explicit sudo wrapper; the no-provider test is ordinary.
gate-authority-build:
	$(GATE_ENV) AXI_AUDIT_CFLAGS='$(CFLAGS)' AXI_AUDIT_BUILD='$(AUTHORITY_BUILD)' AXI_AUDIT_BUILD_ONLY=1 sh tests/audit80/security.sh
	$(GATE_ENV) AXI_AUDIT_CFLAGS='$(CFLAGS)' AXI_AUDIT_BUILD='$(AUTHORITY_BUILD)' AXI_AUDIT_BUILD_ONLY=1 sh tests/audit80/security_faults.sh
	$(GATE_ENV) AXI_AUDIT_CFLAGS='$(CFLAGS)' AXI_AUDIT_BUILD='$(AUTHORITY_BUILD)' AXI_AUDIT_BUILD_ONLY=1 sh tests/audit80/security_nohost.sh

gate-authority: gate-authority-build
	AUTHORITY_RUNNER='$(AUTHORITY_RUNNER)' sh tests/audit80/security_run.sh '$(AUTHORITY_BUILD)/security'
	AUTHORITY_RUNNER='$(AUTHORITY_RUNNER)' sh tests/audit80/security_run.sh '$(AUTHORITY_BUILD)/faults/security_faults'
	'$(AUTHORITY_BUILD)/nohost/security_nohost'

gate-workers: $(BUILD)/audit40/runtime
	$< --workers

gate-compiler: dev $(COMPILER_AUDIT_BIN)
	@set -e; for test in $(COMPILER_AUDIT_BIN); do "$$test"; done
	$(MAKE) BUILD='$(BUILD)/compiler-fail' CPPFLAGS='$(CPPFLAGS) -DAXI_ALLOC_FAILPOINT' dev '$(BUILD)/compiler-fail/audit80/compiler_manifest'
	$(PYTHON) tests/audit80/compiler_cli.py $(abspath $(AXI)) $(abspath $(BUILD))/compiler-fail/axi
	$(PYTHON) tests/audit80/manifest_faults.py $(abspath $(BUILD))/compiler-fail/audit80/compiler_manifest

gate-runtime:
	$(PYTHON) tools/audit80-runtime-bench.py check --source='$(CURDIR)' --output='$(abspath $(BUILD))/audit80-runtime' --cc='$(HOSTCC)' --cppflags='$(CPPFLAGS)' --cflags='$(CFLAGS)' --ldflags='$(LDFLAGS)' --only $(RUNTIME_CHECKS)

# Separate from ASan/UBSan and benchmarks. A TSan startup failure is a failed
# gate; neither the runner nor CI disables ASLR or retries into a false PASS.
gate-tsan:
	$(PYTHON) tools/audit80-runtime-bench.py check --source='$(CURDIR)' --output='$(abspath $(BUILD))/audit80-tsan' --cc='$(HOSTCC)' --cppflags='$(CPPFLAGS)' --cflags='$(TSAN_CFLAGS)' --ldflags='$(TSAN_LDFLAGS)' --only $(TSAN_CHECKS)

gate: gate-identity gate-fast gate-cli gate-audit gate-frontend gate-numeric gate-security gate-authority gate-workers gate-compiler gate-runtime

# Build probes only; measurements are opt-in and have no speed thresholds.
bench: $(BUILD)/audit40/embed $(BUILD)/audit40/seal $(BUILD)/audit40/runtime_bench

clean:
	rm -rf $(BUILD)

-include $(AXI_OBJ:.o=.d) $(DEMO_OBJ:.o=.d) $(patsubst %.c,$(BUILD)/%.d,$(AUDIT_SRC)) $(BUILD)/tests/audit40/runtime_bench.d
-include $(patsubst %.c,$(BUILD)/%.d,$(COMPILER_AUDIT_SRC))
