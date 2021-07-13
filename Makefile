.PHONY: all submodule githooks src test tools install format format-check gen_cov_report clean

all: src

githooks:
	@find .git/hooks -type l -exec rm {} \; && find .githooks -type f -exec ln -sf ../../{} .git/hooks/ \;
	@echo "Add Git hooks that check Rust code format issues before commits and pushes"

OCCLUM_GIT_OPTIONS ?= 
GIT_MIN_VERSION := 2.11.0
GIT_CURRENT_VERSION := $(shell git --version | sed 's/[^0-9.]*//g')
GIT_NEED_PROGRESS := $(shell /bin/echo -e "$(GIT_MIN_VERSION)\n$(GIT_CURRENT_VERSION)" \
			| sort -V | head -n1 | grep -q $(GIT_MIN_VERSION) && echo "true" || echo "false")
# If git version >= min_version, append the `--progress` option to show progress status
ifeq ($(GIT_NEED_PROGRESS), true)
	OCCLUM_GIT_OPTIONS += --progress
else
	OCCLUM_GIT_OPTIONS +=
endif

# Occlum major version
MAJOR_VER_NUM = $(shell grep '\#define OCCLUM_MAJOR_VERSION' ./src/pal/include/occlum_version.h | awk '{print $$3}')
MINOR_VER_NUM = $(shell grep '\#define OCCLUM_MINOR_VERSION' ./src/pal/include/occlum_version.h | awk '{print $$3}')
PATCH_VER_NUM = $(shell grep '\#define OCCLUM_PATCH_VERSION' ./src/pal/include/occlum_version.h | awk '{print $$3}')
VERSION_NUM = $(MAJOR_VER_NUM).$(MINOR_VER_NUM).$(PATCH_VER_NUM)

# Exclude files when install
EXCLUDE_FILES = "libocclum-libos.so.$(MAJOR_VER_NUM)\$$|libocclum-pal.so.$(MAJOR_VER_NUM)\$$|libocclum-pal.so\$$|.a\$$|occlum-protect-integrity.so.*"

SHELL := bash

submodule: githooks
	git submodule init
	git submodule update $(OCCLUM_GIT_OPTIONS)
	@# Try to apply the patches. If failed, check if the patches are already applied
	cd deps/serde-json-sgx && git apply ../serde-json-sgx.patch >/dev/null 2>&1 || git apply ../serde-json-sgx.patch -R --check
	cd deps/ringbuf && git apply ../ringbuf.patch >/dev/null 2>&1 || git apply ../ringbuf.patch -R --check
	cd deps/resolv-conf && git apply ../resolv-conf.patch >/dev/null 2>&1 || git apply ../resolv-conf.patch -R --check

	@# Enclaves used by tools are running in simulation mode by default to run faster.
	@rm -rf build build_sim
	@$(MAKE) SGX_MODE=SIM --no-print-directory -C tools
	@$(MAKE) --no-print-directory -C deps/sefs/sefs-cli clean
	@$(MAKE) --no-print-directory -C deps/sefs/sefs-cli no_sign SGX_MODE=HW
	@cp deps/sefs/sefs-cli/bin/sefs-cli build/bin
	@cp deps/sefs/sefs-cli/lib/libsefs-cli.so build/lib
	@$(MAKE) --no-print-directory -C deps/sefs/sefs-cli SGX_MODE=SIM
	@cp deps/sefs/sefs-cli/bin/sefs-cli_sim build/bin
	@cp deps/sefs/sefs-cli/lib/libsefs-cli_sim.so build/lib
	@cp deps/sefs/sefs-cli/lib/libsefs-cli.signed.so build/lib
	@cp deps/sefs/sefs-cli/enclave/Enclave.config.xml build/sefs-cli.Enclave.xml

src:
	@$(MAKE) --no-print-directory -C src

test:
	@$(MAKE) --no-print-directory -C test test

test-glibc:
	@$(MAKE) --no-print-directory -C test test-glibc

OCCLUM_PREFIX ?= /opt/occlum
install: minimal_sgx_libs
	@# Install both libraries for HW mode and SIM mode
	@$(MAKE) SGX_MODE=HW --no-print-directory -C src
	@$(MAKE) SGX_MODE=SIM --no-print-directory -C src

	@echo "Install libraries ..."
	@mkdir -p $(OCCLUM_PREFIX)/build/bin/
	@cp build/bin/* $(OCCLUM_PREFIX)/build/bin
	@mkdir -p $(OCCLUM_PREFIX)/build/lib/
	@# Don't copy libos library and pal library symbolic files to install dir
	@cd build/lib && cp --no-dereference `ls | grep -Ev $(EXCLUDE_FILES)` $(OCCLUM_PREFIX)/build/lib/ && cd -
	@# Create symbolic for pal library and libos (hardware mode)
	@cd $(OCCLUM_PREFIX)/build/lib && ln -sf libocclum-pal.so.$(VERSION_NUM) libocclum-pal.so.$(MAJOR_VER_NUM) && \
		ln -sf libocclum-pal.so.$(MAJOR_VER_NUM) libocclum-pal.so && \
		ln -sf libocclum-libos.so.$(VERSION_NUM) libocclum-libos.so.$(MAJOR_VER_NUM) && ln -sf libocclum-libos.so.$(MAJOR_VER_NUM) libocclum-libos.so

	@echo "Install headers and miscs ..."
	@mkdir -p $(OCCLUM_PREFIX)/include/
	@cp -r src/pal/include/*.h $(OCCLUM_PREFIX)/include
	@chmod 444 $(OCCLUM_PREFIX)/include/*.h
	@mkdir -p $(OCCLUM_PREFIX)/etc/template/
	@cp etc/template/* $(OCCLUM_PREFIX)/etc/template
	@chmod 444 $(OCCLUM_PREFIX)/etc/template/*
	@cp build/sefs-cli.Enclave.xml $(OCCLUM_PREFIX)/build
	@chmod 644 $(OCCLUM_PREFIX)/build/sefs-cli.Enclave.xml

	@echo "Installation is done."

SGX_SDK=/opt/intel/sgxsdk
# Install minimum sgx-sdk set to support Occlum cmd execution in non-customized sgx-sdk environment
minimal_sgx_libs: $(SGX_SDK)/lib64/libsgx_uae_service_sim.so $(SGX_SDK)/lib64/libsgx_quote_ex_sim.so
	@echo "Install needed sgx-sdk tools ..."
	@mkdir -p $(OCCLUM_PREFIX)/sgxsdk-tools/lib64
	@cp $(SGX_SDK)/lib64/{libsgx_ptrace.so,libsgx_uae_service_sim.so,libsgx_quote_ex_sim.so} $(OCCLUM_PREFIX)/sgxsdk-tools/lib64
	@mkdir -p $(OCCLUM_PREFIX)/sgxsdk-tools/lib64/gdb-sgx-plugin
	@cd $(SGX_SDK)/lib64/gdb-sgx-plugin/ && cp $$(ls -A | grep -v __pycache__) $(OCCLUM_PREFIX)/sgxsdk-tools/lib64/gdb-sgx-plugin
	@cd $(SGX_SDK) && cp -a --parents {bin/sgx-gdb,bin/x64/sgx_sign} $(OCCLUM_PREFIX)/sgxsdk-tools/
	@mkdir -p $(OCCLUM_PREFIX)/sgxsdk-tools/sdk_libs && cd $(OCCLUM_PREFIX)/sgxsdk-tools/sdk_libs && \
		ln -sf ../lib64/libsgx_uae_service_sim.so libsgx_uae_service_sim.so && \
		ln -sf ../lib64/libsgx_quote_ex_sim.so libsgx_quote_ex_sim.so
	@# Delete SGX_LIBRARY_PATH env in sgx-gdb which are defined in etc/environment
	@sed -i '/^SGX_LIBRARY_PATH=/d' $(OCCLUM_PREFIX)/sgxsdk-tools/bin/sgx-gdb
	@cp etc/environment $(OCCLUM_PREFIX)/sgxsdk-tools/

format:
	@$(MAKE) --no-print-directory -C test format
	@$(MAKE) --no-print-directory -C tools format
	@$(MAKE) --no-print-directory -C src format

format-check:
	@$(MAKE) --no-print-directory -C test format-check
	@$(MAKE) --no-print-directory -C tools format-check
	@$(MAKE) --no-print-directory -C src format-check

gen_cov_report:
	@$(MAKE) --no-print-directory -C src gen_cov_report

clean:
	@$(MAKE) --no-print-directory -C src clean
	@$(MAKE) --no-print-directory -C test clean
	@$(MAKE) SGX_MODE=SIM --no-print-directory -C src clean
	@$(MAKE) SGX_MODE=SIM --no-print-directory -C test clean
	@$(MAKE) --no-print-directory -C tools/installer/rpm clean
