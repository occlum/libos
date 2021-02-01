include ../sgxenv.mk

# An overview of the build process
#
# The target library:
#     libocclum-libos.so
#
# The intermediate libraries:
#     libocclum-libos-core.a
#     libocclum_libos_core_rs.a
#
# Diagram:
#
# +-------------------+
# |LibOS (Enclave)<--------+ libocclum-libos.so
# | +---------------| |
# | |LibOS Core <----------+ libocclum-libos-core.a
# | |  +----------| | |
# | |  |Rust <-------------+ libocclum_libos_core_rs.a
# | |  +----------+ | |      (Rust forbids the use of hypens in library names)
# | |  |C         | | |
# | |  +----------+ | |
# | |  |Assembly  | | |
# | |  +----------+ | |
# | +---------------+ |
# | |Rust SGX SDK <-----+
# | +---------------| | +--+ Dependencies
# | |Intel SGX SDK<-----+
# | +---------------| |
# +-------------------+

# The log level for LibOS
#
# There are five levels:
# 1 - error
# 2 - warn
# 3 - info
# 4 - debug
# 5 - trace
#
# By setting the log level to a specific value (say warn), all log messages
# whose levels are no greater than the value (error and warn <= warn) will
# be printed.
LIBOS_LOG ?= error

LIBOS_SONAME := libocclum-libos.so.$(MAJOR_VER_NUM)

ifneq ($(SGX_MODE), HW)
	LIBOS_CORE_LIB_NAME := occlum-libos-core_sim
	LIBOS_SO_REAL := $(BUILD_DIR)/lib/libocclum-libos_sim.so.$(VERSION_NUM)
else
	LIBOS_CORE_LIB_NAME := occlum-libos-core
	LIBOS_SO_REAL := $(BUILD_DIR)/lib/libocclum-libos.so.$(VERSION_NUM)
endif

LIBOS_CORE_A := $(OBJ_DIR)/libos/lib/lib$(LIBOS_CORE_LIB_NAME).a
LIBOS_CORE_RS_A := $(OBJ_DIR)/libos/lib/libocclum_libos_core_rs.a

# All source code
RUST_SRCS := $(wildcard src/*.rs src/*/*.rs src/*/*/*.rs src/*/*/*/*.rs src/*/*/*/*/*.rs)
RUST_TARGET_DIR := $(OBJ_DIR)/libos/cargo-target
RUST_OUT_DIR := $(OBJ_DIR)/libos/lib
EDL_C_SRCS := $(addprefix $(OBJ_DIR)/libos/,$(SRC_OBJ)/Enclave_t.c $(SRC_OBJ)/Enclave_t.h)
EDL_C_OBJS := $(addprefix $(OBJ_DIR)/libos/,$(SRC_OBJ)/Enclave_t.o)
C_SRCS := $(sort $(wildcard src/*.c src/*/*.c src/*/*/*.c))
CXX_SRCS := $(sort $(wildcard src/*.cpp src/*/*.cpp))
S_SRCS := $(sort $(wildcard src/*.S src/*/*.S src/*/*/*.S))
C_OBJS := $(addprefix $(OBJ_DIR)/libos/,$(C_SRCS:.c=.o))
CXX_OBJS := $(addprefix $(OBJ_DIR)/libos/,$(CXX_SRCS:.cpp=.o))
S_OBJS := $(addprefix $(OBJ_DIR)/libos/,$(S_SRCS:.S=.o))

# Object files for simulation mode are stored in libos/src_sim
ifneq ($(SGX_MODE), HW)
	C_OBJS := $(subst libos/src,libos/src_sim,$(C_OBJS))
	CXX_OBJS := $(subst libos/src,libos/src_sim,$(CXX_OBJS))
	S_OBJS := $(subst libos/src,libos/src_sim,$(S_OBJS))
endif

ALL_BUILD_SUBDIRS := $(sort $(patsubst %/,%,$(dir $(LIBOS_SO_REAL) $(EDL_C_OBJS) $(C_OBJS) $(CXX_OBJS) $(S_OBJS)) $(RUST_TARGET_DIR) $(RUST_OUT_DIR)))

C_COMMON_FLAGS := -fno-stack-protector -I./include/
# SGX GDB support
C_COMMON_FLAGS += -g
C_FLAGS := $(SGX_CFLAGS_T) $(C_COMMON_FLAGS)
CXX_FLAGS := $(SGX_CXXFLAGS_T) $(C_COMMON_FLAGS)

_Other_Link_Flags := -L$(RUST_SGX_SDK_DIR)/compiler-rt/ -L$(BUILD_DIR)/lib -L$(RUST_OUT_DIR)
_Other_Enclave_Libs := -l$(LIBOS_CORE_LIB_NAME) -lsgx_tprotected_fs
ifndef OCCLUM_DISABLE_DCAP
_Other_Enclave_Libs += -lsgx_dcap_tvl
endif
LINK_FLAGS := $(SGX_LFLAGS_T)

.PHONY: all clean format format-c format-rust format-check format-check-c format-check-rust gen_cov_report
all: $(ALL_BUILD_SUBDIRS) $(LIBOS_SO_REAL)

$(ALL_BUILD_SUBDIRS):
	@mkdir -p $@

LIBOS_SO_DEPS := $(LIBOS_CORE_A) $(LIBCOMPILER_RT_PATCH_A)

$(LIBOS_SO_REAL): $(LIBOS_CORE_A) $(LIBCOMPILER_RT_PATCH_A)
ifeq ($(OCCLUM_RELEASE_BUILD), 1)
	@$(CC) $(LIBOS_SO_DEPS) -o $@ $(LINK_FLAGS) -Wl,-soname=$(LIBOS_SONAME)
else
# use whole-archive to include unused symbols of the incremental debug build
	@$(CC) -Wl,-whole-archive $(LIBOS_SO_DEPS) -Wl,-no-whole-archive -o $@ $(LINK_FLAGS) -Wl,-soname=$(LIBOS_SONAME)
endif
	@echo "LINK => $@"

$(LIBOS_CORE_A): $(LIBOS_CORE_RS_A) $(C_OBJS) $(CXX_OBJS) $(S_OBJS) $(EDL_C_OBJS)
	@cp $(LIBOS_CORE_RS_A) $(LIBOS_CORE_A)
	@ar r $@ $(C_OBJS) $(CXX_OBJS) $(S_OBJS) $(EDL_C_OBJS)
	@echo "GEN => $@"

ifneq (, $(shell which sccache))
    RUSTC_WRAPPER := sccache
else
    RUSTC_WRAPPER :=
endif

LIBOS_FEATURES :=

ifndef OCCLUM_DISABLE_DCAP
    LIBOS_FEATURES += dcap
endif

ifneq ($(OCCLUM_COV),)
    LIBOS_FEATURES += cov
    COV_FLAGS += "-Zprofile -Ccodegen-units=1 \
        -Cllvm_args=-inline-threshold=0 -Clink-dead-code \
        -Coverflow-checks=off -Cpanic=abort"
endif

ifeq ($(OCCLUM_UT), 1)
    LIBOS_FEATURES += unit_test
endif
ifneq ($(OCCLUM_RELEASE_BUILD), 1)
    LIBOS_FEATURES += unit_test
endif

$(LIBOS_CORE_RS_A): $(RUST_SRCS)
# Release build is for production use. We enable code coverage only for debug
# build. It also simplifies the implementation as the release and debug build
# have different output paths.
ifeq ($(OCCLUM_RELEASE_BUILD), 1)
	@RUSTC_BOOTSTRAP=1 RUSTC_WRAPPER=$(RUSTC_WRAPPER) cargo build --release --target-dir=$(RUST_TARGET_DIR) -Z unstable-options --out-dir=$(RUST_OUT_DIR) --features "$(LIBOS_FEATURES)"
	@echo "CARGO (release) => $@"
else ifneq ($(OCCLUM_COV),)
	@CARGO_INCREMENTAL=0 RUSTC_BOOTSTRAP=1 RUSTFLAGS=$(COV_FLAGS) cargo build --target-dir=$(RUST_TARGET_DIR) -Z unstable-options --out-dir=$(RUST_OUT_DIR) --features "$(LIBOS_FEATURES)"
	@echo "CARGO (debug) => $@"
else
	@RUSTC_BOOTSTRAP=1 RUSTC_WRAPPER=$(RUSTC_WRAPPER) cargo build --target-dir=$(RUST_TARGET_DIR) -Z unstable-options --out-dir=$(RUST_OUT_DIR) --features "$(LIBOS_FEATURES)"
	@echo "CARGO (debug) => $@"
endif
	@echo "enabled occlum features are$(LIBOS_FEATURES)"

$(OBJ_DIR)/libos/$(SRC_OBJ)/Enclave_t.o: $(OBJ_DIR)/libos/$(SRC_OBJ)/Enclave_t.c
	@$(CC) $(C_FLAGS) -Iinclude/edl -c $< -o $@
	@echo "CC <= $@"

$(OBJ_DIR)/libos/$(SRC_OBJ)/Enclave_t.c: $(SGX_EDGER8R) ../Enclave.edl
	@cd $(OBJ_DIR)/libos/$(SRC_OBJ) && $(SGX_EDGER8R) --trusted $(CUR_DIR)/../Enclave.edl --search-path $(SGX_SDK)/include --search-path $(RUST_SGX_SDK_DIR)/edl
	@echo "GEN <= $@"

$(C_OBJS):$(OBJ_DIR)/libos/$(SRC_OBJ)/%.o: src/%.c
	@$(CC) $(C_FLAGS) -c $< -o $@
	@echo "CC <= $@"

$(CXX_OBJS): $(OBJ_DIR)/libos/$(SRC_OBJ)/%.o: src/%.cpp
	@$(CXX) $(CXX_FLAGS) -c $< -o $@
	@echo "CXX <= $@"

$(S_OBJS):$(OBJ_DIR)/libos/$(SRC_OBJ)/%.o: src/%.S
	@$(CC) $(C_FLAGS) -c $< -o $@
	@echo "AS <= $@"

format: format-c format-rust

format-c: $(C_SRCS) $(CXX_SRCS)
	@$(C_FORMATTER) $^

format-rust: $(RUST_SRCS)
	@$(call format-rust)

format-check: format-check-c format-check-rust

format-check-c: $(C_SRCS) $(CXX_SRCS)
	@$(C_FORMATTER) --check $^

format-check-rust: $(RUST_SRCS)
	@$(call format-check-rust)

COV_TARGET_DIR := $(RUST_TARGET_DIR)/debug/deps
DEPS_DIR := $(shell pwd)/../../deps
LLVM_GCOV := $(DEPS_DIR)/rust-sgx-sdk/samplecode/sgx-cov/enclave/llvm-gcov
ALL_TAG_INFO := all.tag.info
FINAL_INFO := final.info
COV_REPORT := cov_report

gen_cov_report:
	# The path of the rust source code is relative in .d file, so gcov will
	# look for the source code under COV_TARGET_DIR.
	ln -sf $(shell pwd)/src $(COV_TARGET_DIR)/src
	lcov --gcov-tool $(LLVM_GCOV) --rc lcov_branch_coverage=1 --rc lcov_excl_line=assert --exclude 'occlum/deps' --capture --directory ${COV_TARGET_DIR} -o $(ALL_TAG_INFO)
	lcov --gcov-tool $(LLVM_GCOV) --rc lcov_branch_coverage=1 --rc lcov_excl_line=assert --extract $(ALL_TAG_INFO) `find -L $(COV_TARGET_DIR) -name *.rs` -o $(FINAL_INFO)
	genhtml --branch-coverage --demangle-cpp --legend $(FINAL_INFO) -o $(COV_REPORT) --ignore-errors source

clean:
	@-$(RM) -rf $(OBJ_DIR)/libos
	@-$(RM) -f $(LIBOS_SO_REAL)
	@-$(RM) -rf $(ALL_TAG_INFO) $(FINAL_INFO) $(COV_REPORT)
