CUR_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
PROJECT_DIR := $(realpath $(CUR_DIR)/../)
SGX_MODE ?= HW

C_SRCS := $(wildcard */*.c */*.h)
CXX_SRCS := $(wildcard */*.cc)

C_FORMATTER := $(PROJECT_DIR)/tools/c_formatter

BUILD_DIR := $(PROJECT_DIR)/build

PASS_LOG = $(BUILD_DIR)/test/.pass
FAIL_LOG = $(BUILD_DIR)/test/.fail

# Dependencies: need to be compiled but not to run by any Makefile target
TEST_DEPS := client data_sink naughty_child
# Tests: need to be compiled and run by test-% target
TESTS ?= env empty hello_world malloc mmap file fs_perms getpid spawn sched pipe time timerfd \
	truncate readdir mkdir open stat link symlink chmod chown tls pthread system_info rlimit \
	server server_epoll unix_socket cout hostfs cpuid rdtsc device sleep exit_group \
	ioctl fcntl eventfd emulate_syscall access signal sysinfo prctl rename procfs wait \
	spawn_attribute exec statfs
# Benchmarks: need to be compiled and run by bench-% target
BENCHES := spawn_and_exit_latency pipe_throughput unix_socket_throughput

# Top-level Makefile targets
BUILD_TARGETS := $(TEST_DEPS) $(TESTS) $(BENCHES)
TEST_TARGETS := $(TESTS:%=test-%)
BENCH_TARGETS := $(BENCHES:%=bench-%)
.PHONY: all prebuild build postbuild test clean $(BUILD_TARGETS) $(TEST_TARGETS) $(BENCH_TARGETS) format format-check

# Use echo program instead of built-in echo command in shell. This ensures
# that echo can recognize escaped sequences (with -e argument) regardless of
# the specific shell (e.g., bash, zash, etc.)
ECHO := /bin/echo -e
# Shell escaped sequences for colorful output
CYAN := \033[1;36m
GREEN := \033[1;32m
RED := \033[1;31m
NO_COLOR := \033[0m

#############################################################################
# Build targets
#############################################################################

all: build

build: prebuild $(BUILD_TARGETS) postbuild

prebuild:
	@$(RM) -rf $(BUILD_DIR)/test
	@mkdir -p $(BUILD_DIR)/test
	@cd $(BUILD_DIR)/test && \
		$(BUILD_DIR)/bin/occlum init
	@cp Occlum.json $(BUILD_DIR)/test/

$(BUILD_TARGETS): %:
	@$(ECHO) "$(CYAN)BUILD TEST => $@$(NO_COLOR)"
	@$(MAKE) --no-print-directory -C $@
	@$(ECHO) "$(GREEN)DONE$(NO_COLOR)"

postbuild:
	@cd $(BUILD_DIR)/test && \
		$(BUILD_DIR)/bin/occlum build -f

#############################################################################
# Test targets
#############################################################################

test-glibc:
	@OCCLUM_TEST_GLIBC=1 $(MAKE) test

test: build pretest $(TEST_TARGETS) posttest

pretest:
	@$(RM) $(PASS_LOG) $(FAIL_LOG)
	@cd $(BUILD_DIR)/test && \
		$(BUILD_DIR)/bin/occlum start

$(TEST_TARGETS): test-%: %
	@touch $(PASS_LOG) $(FAIL_LOG)
	@$(ECHO) "$(CYAN)RUN TEST => $<$(NO_COLOR)"
	@# Restart server if test failed
	@$(MAKE) --no-print-directory -C $< test ; \
		if [ $$? -eq 0 ] ; then \
			$(ECHO) "$(GREEN)PASS$(NO_COLOR)" ; \
			$(ECHO) "$< PASS" >> $(PASS_LOG) ; \
		else \
			$(ECHO) "$(RED)FAILED$(NO_COLOR)" ; \
			$(ECHO) "$< FAILED" >> $(FAIL_LOG) ; \
			cd $(BUILD_DIR)/test && \
			$(BUILD_DIR)/bin/occlum start ; \
		fi ;

posttest:
	@cd $(BUILD_DIR)/test && \
		$(BUILD_DIR)/bin/occlum stop
	@PASS_NUM=$(shell wc -l < $(PASS_LOG)); \
		FAIL_NUM=$(shell wc -l < $(FAIL_LOG)); \
		$(ECHO) "\nTotal:" ; \
		$(ECHO) "$(GREEN)PASS: $$PASS_NUM  $(RED)FAILED: $$FAIL_NUM $(NO_COLOR)" ; \
		if [ $$FAIL_NUM -ne 0 ] ; then \
			exit 1; \
		fi ;

#############################################################################
# Benchmark targets
#############################################################################

bench: build $(BENCH_TARGETS)

$(BENCH_TARGETS): bench-%: %
	@$(ECHO) "$(CYAN)RUN BENCH => $<$(NO_COLOR)"
	@$(MAKE) --no-print-directory -C $< test ; \
		if [ $$? -eq 0 ] ; then \
			$(ECHO) "$(GREEN)DONE$(NO_COLOR)" ; \
		else \
			$(ECHO) "$(RED)FAILED$(NO_COLOR)" ; \
		fi ;

#############################################################################
# Misc
#############################################################################

format: $(C_SRCS) $(CXX_SRCS)
	@$(C_FORMATTER) $^

format-check: $(C_SRCS) $(CXX_SRCS)
	@$(C_FORMATTER) --check $^

clean:
	@$(RM) -rf $(BUILD_DIR)/test
