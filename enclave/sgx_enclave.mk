SGX_MODE ?= HW
export SGX_MODE
USE_OPT_LIBS ?= 0
export USE_OPT_LIBS

##
## linux sdk
##

SGX_DIR ?= $$HOME/linux-sgx
SGX_LIBDIR ?= $(SGX_DIR)/lib
SGX_INCLUDEDIR ?= $(SGX_DIR)/include
SGX_BINDIR ?= $(SGX_DIR)/bin
SGX_EDGER8R ?= $(SGX_BINDIR)/sgx_edger8r
SGX_SIGN ?= $(SGX_BINDIR)/sgx_sign
export SGX_LIBDIR
export SGX_INCLUDEDIR

##
## edger8r
##

%_t.c: %.edl %_t.h
	mv $*_t.h $*_t.h.bak
	 $(SGX_EDGER8R) --trusted --trusted-dir $(dir $@) --search-path $(SGX_INCLUDEDIR) --search-path $(includedir) $<; RES=$$?; mv $*_t.h.bak $*_t.h; exit $$RES
%_t.h: %.edl
	 $(SGX_EDGER8R) --trusted --trusted-dir $(dir $@) --search-path $(SGX_INCLUDEDIR) --search-path $(includedir) --header-only $<

%_u.c: %.edl %_u.h
	mv $*_u.h $*_u.h.bak
	$(SGX_EDGER8R) --untrusted --untrusted-dir $(dir $@) --search-path $(SGX_INCLUDEDIR) --search-path $(includedir) $<; RES=$$?; mv $*_u.h.bak $*_u.h; exit $$RES
%_u.h: %.edl
	 $(SGX_EDGER8R) --untrusted --untrusted-dir $(dir $@) --search-path $(SGX_INCLUDEDIR) --search-path $(includedir) --header-only $<

LLVM_BOLT ?= llvm-bolt

##
## pyxed/Intel Xed
##
PYXED_DIR = $(builddir)/pyxed
PYXED_PYTHONPATH = $(builddir)/pyxed/build/instdir/lib/python3.7/site-packages

PYXED_GIT = https://github.com/huku-/pyxed
PYXED_GIT_REV = b197cfe675533bd4720ff890002ee98ae52ceb3f

$(PYXED_PYTHONPATH):
	rm -rf $(PYXED_DIR)
	mkdir -p $(PYXED_DIR)
	git init $(PYXED_DIR)
	git -C $(PYXED_DIR) remote add origin $(PYXED_GIT)
	git -C $(PYXED_DIR) fetch --depth 1 $(PYXED_GIT) $(PYXED_GIT_REV)
	git -C $(PYXED_DIR) checkout FETCH_HEAD
	git -C $(PYXED_DIR) submodule update --init --recursive --depth 1
	awk '/^static PyMethodDef methods\[\] =$$/ {ARG=4}; { if (ARG>0) {ARG=ARG-1} else {print} }' < $(PYXED_DIR)/pyxed.c > $(PYXED_DIR)/pyxed.c.new
	mv $(PYXED_DIR)/pyxed.c.new $(PYXED_DIR)/pyxed.c #XXX Hack remove after pyxed bugfix.
	mkdir -p $(PYXED_DIR)/build/instdir
	( cd $(PYXED_DIR); python3 setup.py install --prefix build/instdir )

##
## linking
##

ENCLAVE_CFLAGS = -fvisibility=hidden -fPIC -I$(SGX_INCLUDEDIR)/tlibc -fno-jump-tables -mno-red-zone -fno-builtin -ffreestanding

ENCLAVE_LDFLAGS = \
	-Wl,-z,relro,-z,now,-z,noexecstack \
	-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(builddir) -L$(SGX_LIBDIR) \
	-Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lselib -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-allow-shlib-undefined \
	-Wl,-eenclave_entry -Wl,--export-dynamic -Wl,--build-id=none \
	-Wl,--defsym,__ImageBase=0 -Wl,--emit-relocs

$(builddir)/lib%.unstripped.so: CFLAGS += $(ENCLAVE_CFLAGS)
$(builddir)/lib%.unstripped.so: $(builddir)/%_t.o
	$(CC) $(LDFLAGS) -o $@ $(filter %.o,$^) $(LDLIBS) \
		$(ENCLAVE_LDFLAGS) -Wl,--version-script=lib$*.lds -Wl,-soname,lib$*.so

$(builddir)/%.hardened.unstripped.so: $(builddir)/%.unstripped.so
	$(LLVM_BOLT) -trap-old-code -use-gnu-stack -update-debug-sections -update-end -v=2 \
		-skip-funcs=$(shell cat bolt_skip_funcs.txt) \
		-eliminate-unreachable=0 -strip-rep-ret=0 -simplify-conditional-tail-calls=0 \
		-align-macro-fusion=none \
		-insert-lfences \
		-o $@ $<

$(builddir)/%.hardened.unsigned.so: $(builddir)/%.hardened.unstripped.so $(PYXED_PYTHONPATH)
	objdump -w -j .text --no-show-raw-insn -d $(builddir)/$*.unstripped.so | \
	  bin/funcs_with_memindjmp > $(builddir)/funcs_with_memindjmp
	objdump -w -j .text -d $< | \
	  PYTHONPATH=$(PYXED_PYTHONPATH) python3 bin/lvi_checker $(builddir)/funcs_with_memindjmp
	objdump -j .text --no-show-raw-insn -d $< | \
	  egrep '^\s+[0-9a-f]+:\s+(cpuid|getsec|rdpmc|sgdt|sidt|sldt|str|vmcall|vmfunc|rdtscp?|int[0-9a-z]*|iret|syscall|sysenter)\s+' | \
	  wc -l | grep -q '^0$$'
	strip --strip-all $< -o $@
$(builddir)/%.unsigned.so: $(builddir)/%.unstripped.so
	strip --strip-all $< -o $@

##
## signing
##

%.debug.key:
	openssl genrsa -out $@ -3 3072
%.pub: %.key
	openssl rsa -out $@ -in $< -pubout

%.hardened.config.xml: %.config.xml
	cp $< $@
%.debug.config.xml: %.config.xml
	sed -e 's@<DisableDebug>1</DisableDebug>@<DisableDebug>0</DisableDebug>@' $< > $@
$(builddir)/%.debug.signdata: $(builddir)/%.unstripped.so %.debug.config.xml
	$(SGX_SIGN) gendata -out $@ -enclave $(builddir)/$*.unstripped.so -config $*.debug.config.xml
$(builddir)/%.debug.so: $(builddir)/%.unstripped.so $(builddir)/%.debug.signdata %.debug.config.xml %.debug.pub $(builddir)/%.debug.sig
	$(SGX_SIGN) catsig \
		-out $@ \
		-enclave $(builddir)/$*.unstripped.so \
		-unsigned $(builddir)/$*.debug.signdata \
		-config $*.debug.config.xml \
		-key $*.debug.pub \
		-sig $(builddir)/$*.debug.sig

%.hardened.key: %.key
	cp $< $@
%.hardened.test.key: %.key
	cp $< $@

$(builddir)/%.test.unsigned.so: $(builddir)/%.unsigned.so
	cp $< $@

$(builddir)/%.signdata: $(builddir)/%.unsigned.so %.config.xml
	$(SGX_SIGN) gendata -out $@ -enclave $(builddir)/$*.unsigned.so -config $*.config.xml
$(builddir)/%.mrenclave: $(builddir)/%.signdata
	perl -e 'undef $$/; print unpack("x188 H64", <>);' $< > $@
	@echo mrenclave: $$(cat $@)
$(builddir)/%.sig: $(builddir)/%.signdata %.key
	openssl dgst -sha256 -out $@ -sign $*.key $(builddir)/$*.signdata
$(builddir)/%.signed.so: $(builddir)/%.unsigned.so $(builddir)/%.signdata %.config.xml %.pub $(builddir)/%.sig
	$(SGX_SIGN) catsig \
		-out $@ \
		-enclave $(builddir)/$*.unsigned.so \
		-unsigned $(builddir)/$*.signdata \
		-config $*.config.xml \
		-key $*.pub \
		-sig $(builddir)/$*.sig
