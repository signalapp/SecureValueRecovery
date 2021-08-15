sgxsd_srcdir = sgxsd_enclave
includedir = include
patchdir = patches
builddir = build
targetdir = $(builddir)/target
resourcedir = ../service/kbupd/res

RUSTC ?= rustc
CARGO ?= cargo
RUSTUP ?= rustup
BINDGEN ?= $(builddir)/bin/bindgen-0.51.1
DOCKER ?= docker
INSTALL ?= install

RUSTUP_TOOLCHAIN_UNSTABLE ?= nightly

FEATURES ?=

PROST_GIT_REV      = 9c5d46e72acc07a9c4305ffba79d253e0f603a27
RING_GIT_REV       = 323204d618ea9d339e40b7bf6f0517051a44e28a
SERDE_JSON_GIT_REV = d79b0c67f62e168d4872bb8694377ffd97b8949f
SNOW_GIT_REV       = d8d00a37c8e39b2557d23a26cc4f722595b4f2d9
WEBPKI_GIT_REV     = 3c92126b95c6ffbe20f3c8f420f4e4fe804954bd

INSTALL_PROGRAM = $(INSTALL) -m 755 $(INSTALL_PROGRAM_FLAGS)
INSTALL_DATA    = $(INSTALL) -m 644

DESTDIR ?=

CFLAGS = \
	-m64 -O2 -ggdb -march=skylake -pipe -fPIC \
	-D_FORTIFY_SOURCE=2 -std=c11 -D_DEFAULT_SOURCE \
	-fstack-protector-strong -fcf-protection \
	-Wall -Werror=all -Wextra -Wno-unused-parameter -Wno-missing-field-initializers \
	-I$(includedir) -I$(includedir)/bearssl -I$(SGX_INCLUDEDIR)

LDFLAGS =

ENCLAVE_RUSTFLAGS = -C opt-level=2 -C debuginfo=1 -C codegen-units=1 -C panic=abort -C llvm-args=-max-jump-table-size=1 -C llvm-args=-disable-tail-duplicate -C no-redzone

BINDGENFLAGS =
CARGOBUILDFLAGS =
export CARGO_TARGET_DIR = $(CURDIR)/$(targetdir)
export CARGO_HOME = $(CURDIR)/$(builddir)/cargo

TEST_CFLAGS += $(CFLAGS) \
	-DUNIT_TESTING -fsanitize=address -static-libasan -fsanitize=undefined -static-libubsan

##
## rust
##

RUST_DEPS_DIR = $(builddir)/rust_deps
RUST_DEPS_DIRS = \
	$(RUST_DEPS_DIR)/prost-$(PROST_GIT_REV) \
	$(RUST_DEPS_DIR)/ring-$(RING_GIT_REV) \
	$(RUST_DEPS_DIR)/serde_json-$(SERDE_JSON_GIT_REV) \
	$(RUST_DEPS_DIR)/snow-$(SNOW_GIT_REV) \
	$(RUST_DEPS_DIR)/webpki-$(WEBPKI_GIT_REV)

##
## sgxsd
##

TEST_SGXSD_TARGET := $(builddir)/sgxsd-enclave-test

BEARSSL_SOURCES := \
	   $(sgxsd_srcdir)/bearssl/gcm.c $(sgxsd_srcdir)/bearssl/ghash_pclmul.c \
	   $(sgxsd_srcdir)/bearssl/sha2small.c $(sgxsd_srcdir)/bearssl/dec32be.c $(sgxsd_srcdir)/bearssl/enc32be.c \
	   $(sgxsd_srcdir)/bearssl/aes_x86ni_ctr.c $(sgxsd_srcdir)/bearssl/aes_x86ni.c
BEARSSL_OBJECTS := $(addprefix $(builddir)/,$(BEARSSL_SOURCES:.c=.o))

SGXSD_SOURCES   := $(sgxsd_srcdir)/sgxsd-enclave.c $(sgxsd_srcdir)/curve25519-donna-c64.c $(BEARSSL_SOURCES) \
		   $(sgxsd_srcdir)/sgx-tcrypto-stub.c
SGXSD_OBJECTS   := $(addprefix $(builddir)/,$(SGXSD_SOURCES:.c=.o))

TEST_SGXSD_SOURCES := $(sgxsd_srcdir)/sgxsd-enclave.c $(sgxsd_srcdir)/curve25519-donna-c64.c $(sgxsd_srcdir)/sgxsd-enclave-test.c $(sgxsd_srcdir)/cmockery.c
TEST_SGXSD_OBJECTS := $(addprefix $(builddir)/test/,$(TEST_SGXSD_SOURCES:.c=.o))

TEST_LDFLAGS += $(TEST_CFLAGS)

##
## kbupd
##

KBUPD_ENCLAVE_NAME		:= libkbupd_enclave.hardened
KBUPD_ENCLAVE_TARGET		:= $(builddir)/libkbupd_enclave.unstripped.so
KBUPD_ENCLAVE_RUST_STATICLIB	:= $(targetdir)/release/libkbupd_enclave.a

##
## targets
##

.PHONY: default docker-install all unstripped hardened unsigned llvm-bolt doc check test test-asan benchmark clippy bindgen protobuf debug sign install edger8r distclean clean docker

.SUFFIXES:
.SUFFIXES: .c .o

default: docker-install

include sgx_enclave.mk

docker-install: docker install

all: $(KBUPD_ENCLAVE_TARGET) $(builddir)/$(KBUPD_ENCLAVE_NAME).unstripped.so $(builddir)/$(KBUPD_ENCLAVE_NAME).unsigned.so $(builddir)/$(KBUPD_ENCLAVE_NAME).debug.so $(builddir)/$(KBUPD_ENCLAVE_NAME).signdata $(builddir)/$(KBUPD_ENCLAVE_NAME).mrenclave

unstripped: $(KBUPD_ENCLAVE_TARGET)

hardened: $(builddir)/$(KBUPD_ENCLAVE_NAME).unstripped.so

unsigned: $(builddir)/$(KBUPD_ENCLAVE_NAME).unsigned.so

llvm-bolt: $(LLVM_BOLT)

doc: $(RUST_DEPS_DIRS)
	env -u CFLAGS RUSTFLAGS="$(ENCLAVE_RUSTFLAGS)" \
		$(CARGO) doc --package=kbupd_enclave --release --document-private-items --lib

check: $(RUST_DEPS_DIRS)
	$(CARGO) check --all --exclude=kbupd_enclave
	$(CARGO) check --manifest-path=kbupd_enclave/Cargo.toml --lib --tests --features test,$(if $(FEATURES),$(FEATURES))

test: $(TEST_SGXSD_TARGET) $(RUST_DEPS_DIRS)
	ASAN_OPTIONS="detect_leaks=0:$(ASAN_OPTIONS)" ./$(TEST_SGXSD_TARGET)
	env -u CFLAGS \
	RUST_BACKTRACE=full \
	RUST_TEST_THREADS=1 \
		$(CARGO) test --all --exclude=kbupd_enclave -- --test-threads=1
	env -u CFLAGS \
	RUST_BACKTRACE=full \
	RUST_TEST_THREADS=1 \
		$(CARGO) test --manifest-path=kbupd_enclave/Cargo.toml --lib --bins --features test,$(if $(FEATURES),$(FEATURES)) -- --test-threads=1

test-asan: $(TEST_SGXSD_TARGET) $(RUST_DEPS_DIRS)
	./$(TEST_SGXSD_TARGET)
	env -u CFLAGS \
	RUST_BACKTRACE=full \
	RUSTFLAGS="-Z sanitizer=address" RUST_TEST_THREADS=1 \
	ASAN_OPTIONS="detect_odr_violation=1:detect_stack_use_after_return=true:check_initialization_order=true:strict_init_order=true:halt_on_error=false:$(ASAN_OPTIONS)" \
	LSAN_OPTIONS="suppressions=$(CURDIR)/kbupd_enclave/lsan-ignore-test.txt:$(LSAN_OPTIONS)" \
		$(RUSTUP) run $(RUSTUP_TOOLCHAIN_UNSTABLE) \
		$(CARGO) test --all --exclude=kbupd_enclave -- --test-threads=1
	env -u CFLAGS \
	RUST_BACKTRACE=full \
	RUSTFLAGS="-Z sanitizer=address" RUST_TEST_THREADS=1 \
	ASAN_OPTIONS="detect_odr_violation=1:detect_stack_use_after_return=true:check_initialization_order=true:strict_init_order=true:halt_on_error=false:$(ASAN_OPTIONS)" \
	LSAN_OPTIONS="suppressions=$(CURDIR)/kbupd_enclave/lsan-ignore-test.txt:$(LSAN_OPTIONS)" \
		$(RUSTUP) run $(RUSTUP_TOOLCHAIN_UNSTABLE) \
		$(CARGO) test --manifest-path=kbupd_enclave/Cargo.toml --lib --bins --tests --features test,$(if $(FEATURES),$(FEATURES)) -- --test-threads=1

clippy: $(RUST_DEPS_DIRS)
	$(CARGO) clippy --all --exclude=kbupd_enclave
	$(CARGO) clippy --manifest-path=kbupd_enclave/Cargo.toml --features test,$(if $(FEATURES),$(FEATURES))

benchmark: $(RUST_DEPS_DIRS)
	$(CARGO) bench --all

bindgen: $(BINDGEN) | $(SGX_INCLUDEDIR)
	$(BINDGEN) --no-include-path-detection -o sgx_ffi/src/bindgen_wrapper.rs \
		--rust-target 1.33 --use-core --ctypes-prefix libc --with-derive-default --with-derive-eq --no-prepend-enum-name \
		sgx_ffi/src/bindgen_wrapper.h -- \
		$(filter-out -fvisibility=hidden,$(filter-out -std=%,$(CFLAGS) $(ENCLAVE_CFLAGS)))
	$(BINDGEN) --no-include-path-detection -o sgxsd_ffi/src/bindgen_wrapper.rs \
		--rust-target 1.33 --use-core --ctypes-prefix libc --with-derive-default --with-derive-eq --no-prepend-enum-name \
		sgxsd_ffi/src/bindgen_wrapper.h -- \
		$(filter-out -fvisibility=hidden,$(filter-out -std=%,$(CFLAGS) $(ENCLAVE_CFLAGS)))
	$(BINDGEN) --no-include-path-detection -o kbupd_enclave/src/ffi/bindgen_wrapper.rs \
		--rust-target 1.33 --use-core --ctypes-prefix libc --with-derive-default --with-derive-eq --no-prepend-enum-name \
		kbupd_enclave/src/ffi/bindgen_wrapper.h -- \
		$(filter-out -fvisibility=hidden,$(filter-out -std=%,$(CFLAGS) $(ENCLAVE_CFLAGS)))

$(builddir)/bin/bindgen-%:
	$(CARGO) install --locked --force --version $* --bin bindgen bindgen
	mkdir -p $(builddir)/bin
	cp $(builddir)/cargo/bin/bindgen $@

protobuf: | $(targetdir)/debug/prostc
	mkdir -p kbupd_enclave/src/protobufs
	OUT_DIR=kbupd_enclave/src/protobufs $(targetdir)/debug/prostc kbupd_enclave/src/protobufs.proto kbupd_enclave/src/ $(includedir)/
	mv kbupd_enclave/src/protobufs/protobufs.rs kbupd_enclave/src/protobufs/mod.rs
	cd kbupd_enclave/src/protobufs; for file in protobufs.*.rs; do newfile=$${file#protobufs.}; mv $$file $$newfile; echo "pub mod $${newfile%.rs};" >> mod.rs; done


debug: $(builddir)/$(KBUPD_ENCLAVE_NAME).unsigned.so $(builddir)/$(KBUPD_ENCLAVE_NAME).debug.so

sign: $(builddir)/$(KBUPD_ENCLAVE_NAME).signed.so $(builddir)/$(KBUPD_ENCLAVE_NAME).test.signed.so

install:
	$(INSTALL_DATA) $(builddir)/$(KBUPD_ENCLAVE_NAME).debug.so \
			$(resourcedir)/enclave/$$(cat $(builddir)/$(KBUPD_ENCLAVE_NAME).mrenclave).so
	if [ -e $(builddir)/$(KBUPD_ENCLAVE_NAME).signed.so ]; then \
		cp $(builddir)/$(KBUPD_ENCLAVE_NAME).signed.so \
		   $(resourcedir)/enclave/$$(cat $(builddir)/$(KBUPD_ENCLAVE_NAME).mrenclave).so; \
	fi

edger8r: $(includedir)/kbupd_enclave.edl | $(SGX_EDGER8R)
	 $(SGX_EDGER8R) --untrusted --untrusted-dir $(includedir) \
			--trusted --trusted-dir $(includedir) \
			--search-path $(SGX_INCLUDEDIR) \
			--search-path $(includedir) \
			$(includedir)/kbupd_enclave.edl

distclean: clean

clean:
	rm -f	$(builddir)/$(KBUPD_ENCLAVE_NAME).debug.signdata \
		$(builddir)/$(KBUPD_ENCLAVE_NAME).debug.key \
		$(builddir)/$(KBUPD_ENCLAVE_NAME).debug.pub \
		$(builddir)/$(KBUPD_ENCLAVE_NAME).debug.sig \
		$(builddir)/$(KBUPD_ENCLAVE_NAME).test.sig \
		$(builddir)/$(KBUPD_ENCLAVE_NAME).test.signdata \
		$(builddir)/$(KBUPD_ENCLAVE_NAME).sig \
		$(builddir)/$(KBUPD_ENCLAVE_NAME).signdata \
		$(builddir)/$(KBUPD_ENCLAVE_NAME).mrenclave \
		$(builddir)/*.o \
		$(builddir)/*.a \
		$(builddir)/*.so \
		$(SGXSD_OBJECTS) $(TEST_SGXSD_TARGET) $(TEST_SGXSD_OBJECTS) \
		debian/debhelper-build-stamp \
		debian/kbupd-enclave.substvars \
		debian/files \
		debian/*.deb
	-rm -r	$(targetdir)/release/ \
		$(targetdir)/debug/ \
		$(builddir)/bolt/build \
		$(builddir)/cargo/bin \
		$(RUST_DEPS_DIR) \
		$(SGX_SDK_SOURCE_DIR) \
		debian/.debhelper/ \
		debian/kbupd-enclave/
	-$(CARGO) clean --release

## rust

.PHONY: FORCE
FORCE:

$(targetdir)/debug/prostc: FORCE $(RUST_DEPS_DIRS)
	env -u CFLAGS $(CARGO) build --manifest-path=prostc/Cargo.toml --bin=prostc
$(targetdir)/release/lib%.a: FORCE $(RUST_DEPS_DIRS)
	env CFLAGS="-mno-red-zone" RUSTFLAGS="$(ENCLAVE_RUSTFLAGS)" \
		$(CARGO) build -vv --release --manifest-path=$*/Cargo.toml --lib $(if $(FEATURES),--features $(FEATURES))

$(RUST_DEPS_DIR)/prost-$(PROST_GIT_REV):
	mkdir -p $(RUST_DEPS_DIR)/unpack
	wget -O - https://github.com/signalapp/prost/archive/$(PROST_GIT_REV).tar.gz \
		| tar -xzf - -C $(RUST_DEPS_DIR)/unpack/
	mv $(RUST_DEPS_DIR)/unpack/prost-$(PROST_GIT_REV) $(RUST_DEPS_DIR)/

$(RUST_DEPS_DIR)/ring-$(RING_GIT_REV):
	mkdir -p $(RUST_DEPS_DIR)/unpack
	wget -O - https://github.com/signalapp/ring/archive/$(RING_GIT_REV).tar.gz \
		| tar -xzf - -C $(RUST_DEPS_DIR)/unpack/
	mkdir $(RUST_DEPS_DIR)/unpack/ring-$(RING_GIT_REV)/.git # hack to get ring to generate asm in its build.rs
	mv $(RUST_DEPS_DIR)/unpack/ring-$(RING_GIT_REV) $(RUST_DEPS_DIR)/

$(RUST_DEPS_DIR)/serde_json-$(SERDE_JSON_GIT_REV):
	mkdir -p $(RUST_DEPS_DIR)/unpack
	wget -O - https://github.com/signalapp/serde_json/archive/$(SERDE_JSON_GIT_REV).tar.gz \
		| tar -xzf - -C $(RUST_DEPS_DIR)/unpack/
	mv $(RUST_DEPS_DIR)/unpack/serde_json-$(SERDE_JSON_GIT_REV) $(RUST_DEPS_DIR)/

$(RUST_DEPS_DIR)/snow-$(SNOW_GIT_REV):
	mkdir -p $(RUST_DEPS_DIR)/unpack
	wget -O - https://github.com/signalapp/snow/archive/$(SNOW_GIT_REV).tar.gz \
		| tar -xzf - -C $(RUST_DEPS_DIR)/unpack/
	mv $(RUST_DEPS_DIR)/unpack/snow-$(SNOW_GIT_REV) $(RUST_DEPS_DIR)/

$(RUST_DEPS_DIR)/webpki-$(WEBPKI_GIT_REV):
	mkdir -p $(RUST_DEPS_DIR)/unpack
	wget -O - https://github.com/briansmith/webpki/archive/$(WEBPKI_GIT_REV).tar.gz \
		| tar -xzf - -C $(RUST_DEPS_DIR)/unpack/
	mv $(RUST_DEPS_DIR)/unpack/webpki-$(WEBPKI_GIT_REV) $(RUST_DEPS_DIR)/

## sgxsd

$(BEARSSL_OBJECTS): $(wildcard $(includedir)/bearssl/%.h)
$(SGXSD_OBJECTS): $(builddir)/%.o: %.c $(includedir)/sgxsd.h $(includedir)/sgxsd-enclave.h | $(SGX_INCLUDEDIR)
	@mkdir -p $(dir $@)
	$(CC) -o $@ $(CFLAGS) $(ENCLAVE_CFLAGS) -c $<

$(TEST_SGXSD_TARGET): $(TEST_SGXSD_OBJECTS)
	$(CC) -o $@ $(TEST_SGXSD_OBJECTS) $(TEST_LDFLAGS)
$(TEST_SGXSD_OBJECTS): $(builddir)/test/%.o: %.c $(includedir)/sgxsd.h $(includedir)/sgxsd-enclave.h $(includedir)/cmockery.h | $(SGX_INCLUDEDIR)
	@mkdir -p $(dir $@)
	$(CC) -o $@ $(CFLAGS) $(TEST_CFLAGS) -c $<

## kbupd

$(includedir)/kbupd_enclave_t.h $(includedir)/kbupd_enclave_u.h: $(includedir)/sgxsd.edl

$(builddir)/kbupd_enclave_t.o: $(includedir)/kbupd_enclave_t.c
	$(CC) -o $@ $(CFLAGS) $(ENCLAVE_CFLAGS) -c $<

$(builddir)/kbupd_enclave_u.o: $(includedir)/kbupd_enclave_u.c
	$(CC) -o $@ $(CFLAGS) -c $<

$(builddir)/libkbupd_enclave_u.a: $(builddir)/kbupd_enclave_u.o
	$(AR) r $@ $<

$(KBUPD_ENCLAVE_TARGET): $(SGXSD_OBJECTS) $(KBUPD_ENCLAVE_RUST_STATICLIB)
$(KBUPD_ENCLAVE_TARGET): LDFLAGS := -L$(dir $(KBUPD_ENCLAVE_RUST_STATICLIB))
$(KBUPD_ENCLAVE_TARGET): LDLIBS := -lkbupd_enclave

## Reproducible enclave build via debian package

MAKETARGET ?= bindgen debuild sign

docker: DOCKER_EXTRA=$(shell [ -L build ] && P=$$(readlink build) && echo -v $$P/:$$P )
docker:
	$(DOCKER) build --build-arg UID=$$(id -u) --build-arg GID=$$(id -g) \
	  -t kbupd-enclave-builder ./docker
	$(DOCKER) run -it --rm --user $$(id -u):$$(id -g) --cap-add SYS_PTRACE \
		-v `pwd`/:/home/rust/src $(DOCKER_EXTRA) \
		--env MAKEFLAGS="$(MAKEFLAGS)" \
		kbupd-enclave-builder \
		sh -c "cd src; make $(MAKETARGET)"

.PHONY: debuild
debuild:
	env -u LANG LC_ALL=C debuild --preserve-envvar=PATH --no-lintian --build=binary -uc -us -j1
	mv ../*.buildinfo debian/buildinfo
	mv ../*.deb debian/

.PHONY: debuild-kbupd-enclave-build
debuild-kbupd-enclave-build: all

.PHONY: debuild-kbupd-enclave-install
debuild-kbupd-enclave-install: $(builddir)/$(KBUPD_ENCLAVE_NAME).unsigned.so
	mkdir -p $(DESTDIR)/usr/lib/kbupd/enclave/
	$(INSTALL_DATA) $(builddir)/$(KBUPD_ENCLAVE_NAME).unsigned.so $(DESTDIR)/usr/lib/kbupd/enclave/

.PHONY: debuild-kbupd-enclave-test
debuild-kbupd-enclave-test:
	echo "not running tests in debuild" 1>&2

.PHONY: tar
tar:
	tar -cjf $(builddir)/$(KBUPD_ENCLAVE_NAME).build.tar.bz2 \
		$(LLVM_BOLT) \
		--anchored --exclude-vcs \
		--exclude='$(builddir)/bolt' \
		--exclude='$(builddir)/cargo/registry/cache' \
		--exclude='$(builddir)/cargo/registry/index' \
		--exclude='$(builddir)/cargo/git/db' \
		--exclude='*.git' \
		--no-wildcards-match-slash \
		--exclude='$(builddir)/*.tar.bz2' \
		--verbose --totals \
		'$(builddir)/'
