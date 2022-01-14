enclave_includedir = ../enclave/include
enclave_libdir = ../enclave/lib
builddir = build
targetdir = $(builddir)/target

CARGO ?= cargo
BINDGEN ?= bindgen
DOCKER ?= docker
INSTALL ?= install

VERSION = $(shell cargo pkgid --package kbupd | cut -d\# -f2)

INSTALL_PROGRAM = $(INSTALL) -m 755 $(INSTALL_PROGRAM_FLAGS)
INSTALL_DATA    = $(INSTALL) -m 644

DESTDIR ?=

export CARGO_TARGET_DIR = $(CURDIR)/$(targetdir)
export CARGO_HOME = $(CURDIR)/$(builddir)/cargo

##
## targets
##

.PHONY: default all all-debug kbupd kbupd-debug kbupd-config kbupd-config-debug kbupctl kbupctl-debug kbuptlsd kbuptlsd-debug kbupd-api-client kbupd-api-client-debug doc check test clippy bindgen distclean clean docker tar
.PHONY: FORCE

.SUFFIXES:
.SUFFIXES: .c .o

default: docker tar

all: kbupd kbupd-config kbuptlsd

all-debug: kbupd-debug kbupd-config-debug kbuptlsd-debug

kbupd:
	$(CARGO) build --package=kbupd --bins --release

kbupd-debug:
	$(CARGO) build --package=kbupd --bins

kbupd-config:
	$(CARGO) build --package=kbupd_config --bins --release

kbupd-config-debug:
	$(CARGO) build --package=kbupd_config --bins

kbupctl:
	$(CARGO) build --package=kbupd --bin=kbupctl --release

kbupctl-debug:
	$(CARGO) build --package=kbupd --bin=kbupctl

kbuptlsd:
	$(CARGO) build --package=kbuptlsd --bins --release

kbuptlsd-debug:
	$(CARGO) build --package=kbuptlsd --bins

kbupd-api-client:
	$(CARGO) build --package=kbupd_api_client --bins --release

kbupd-api-client-debug:
	$(CARGO) build --package=kbupd_api_client --bins

doc:
	$(CARGO) doc --package=kbupd --release --document-private-items --lib

check:
	$(CARGO) check --package=kbupd --lib --bins --tests

test:
	RUST_BACKTRACE=1 $(CARGO) test --all --exclude=kbuptlsd
	$(CARGO) test --package=kbuptlsd

clippy:
	$(CARGO) clippy --package=kbupd

bindgen:
	$(BINDGEN) -o sgx_sdk_ffi/src/bindgen_wrapper.rs \
		--rust-target 1.33 --with-derive-default --with-derive-eq --no-prepend-enum-name \
		sgx_sdk_ffi/src/bindgen_wrapper.h  --rustfmt-configuration-file /dev/null
	$(BINDGEN) -o kbupd/src/enclave/ffi/bindgen_wrapper.rs \
		--rust-target 1.33 --with-derive-default --with-derive-eq --no-prepend-enum-name \
		kbupd/src/enclave/ffi/bindgen_wrapper.h --rustfmt-configuration-file /dev/null \
		--blacklist-type sgx_report_t --blacklist-type sgx_target_info_t \
		--raw-line "use sgx_sdk_ffi::{SgxReport as sgx_report_t, SgxTargetInfo as sgx_target_info_t};" \
		-- -I../enclave/include

distclean: clean
	rm -r $(builddir)/

clean:
	-rm -r	$(targetdir)/release/ \
		$(targetdir)/debug/ \
		$(builddir)/tar/
	-rm	$(builddir)/*.tar.gz
	-$(CARGO) clean --release

## Docker build env

MAKETARGET ?= all

docker: DOCKER_EXTRA=$(shell [ -L build ] && P=$$(readlink build) && echo -v $$P/:$$P )
docker:
	$(DOCKER) build --build-arg UID=$$(id -u) --build-arg GID=$$(id -g) \
	  -t kbupd-builder ./docker
	$(DOCKER) run --rm --user $$(id -u):$$(id -g) \
	  --env "MAKEFLAGS=$(MAKEFLAGS)" \
	  -v `pwd`/:/home/rust/src $(DOCKER_EXTRA) kbupd-builder \
	  sh -c "cd src; make $(MAKETARGET)"

## tar package

tar: $(builddir)/kbupd-$(VERSION)-bin-staging.tar.gz $(builddir)/kbupd-$(VERSION)-bin-production.tar.gz

$(builddir)/kbupd-$(VERSION)-bin-%.tar.gz: FORCE
	$(targetdir)/release/kbupd-config validate frontend config/frontend.$*.yml
	$(targetdir)/release/kbupd-config validate frontend config/frontend.$*-ias-v4.yml
	$(targetdir)/release/kbupd-config validate replica  $(wildcard config/replica-*.$*.yml)
	-rm -rf $(builddir)/tar/
	mkdir -p $(builddir)/tar/enclave/
	$(INSTALL_PROGRAM) $(targetdir)/release/kbupd		$(builddir)/tar/
	$(INSTALL_PROGRAM) $(targetdir)/release/kbupd-config	$(builddir)/tar/
	$(INSTALL_PROGRAM) $(targetdir)/release/kbupctl		$(builddir)/tar/
	$(INSTALL_PROGRAM) $(targetdir)/release/kbuptlsd	$(builddir)/tar/
	$(INSTALL_DATA) $(wildcard kbupd/res/enclave/*.so)	$(builddir)/tar/enclave/
	$(INSTALL_DATA) config/frontend.$*.yml			$(builddir)/tar/
	$(INSTALL_DATA) config/frontend.$*-ias-v4.yml			$(builddir)/tar/
	$(INSTALL_DATA) $(wildcard config/replica-*.$*.yml)	$(builddir)/tar/
	$(INSTALL_DATA) config/peer_ca_cert.$*.pem		$(builddir)/tar/
	tar -czf						$(builddir)/kbupd-$(VERSION)-bin-$*.tar.gz -C $(builddir)/tar .
