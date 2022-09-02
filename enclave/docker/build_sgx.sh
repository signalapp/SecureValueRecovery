#!/bin/bash
source deps.mk
set -e
set -x

SGX_DIR=linux-sgx
SGX_SDK_SOURCE_DIR=$SGX_DIR/linux-sgx-$SGX_SDK_SOURCE_GIT_REV
SGX_SDK_SOURCE_INCLUDEDIR=$SGX_SDK_SOURCE_DIR/common/inc
SGX_SDK_SOURCE_LIBDIR=$SGX_SDK_SOURCE_DIR/build/linux
SGX_INCLUDEDIR=$SGX_SDK_SOURCE_DIR/include
PATCHDIR=linux-sgx-patches
SGX_SDK_SOURCE_UNPACK_DIR=$SGX_DIR/unpack/linux-sgx-$SGX_SDK_SOURCE_GIT_REV
SGX_DCAP_SOURCE_UNPACK_DIR=$SGX_DIR/unpack/SGXDataCenterAttestationPrimitives-$SGX_DCAP_SOURCE_GIT_REV

mkdir -p $SGX_DIR/unpack/
wget -O - https://github.com/intel/linux-sgx/archive/$SGX_SDK_SOURCE_GIT_REV.tar.gz | tar -xzf - -C $SGX_DIR/unpack/
wget -O - https://github.com/intel/SGXDataCenterAttestationPrimitives/archive/$SGX_DCAP_SOURCE_GIT_REV.tar.gz | tar -xzf - -C $SGX_DIR/unpack/
mv $SGX_DCAP_SOURCE_UNPACK_DIR $SGX_SDK_SOURCE_UNPACK_DIR/external/dcap_sources
patch -d $SGX_SDK_SOURCE_UNPACK_DIR -p 1 -T < $PATCHDIR/linux-sgx-rep-stringops.patch
patch -d $SGX_SDK_SOURCE_UNPACK_DIR -p 1 -T < $PATCHDIR/linux-sgx-rep-bcmp.patch
mv $SGX_SDK_SOURCE_UNPACK_DIR $SGX_SDK_SOURCE_DIR
env -u LDFLAGS -u CPPFLAGS CFLAGS='-D_TLIBC_USE_REP_STRING_ -fno-jump-tables -mno-red-zone -mindirect-branch-register -Wno-error=implicit-fallthrough' make -C $SGX_SDK_SOURCE_DIR/sdk simulation selib signtool edger8r trts tstdc

mkdir -p $SGX_DIR/lib $SGX_DIR/bin
for lib in trts tstdc trts_sim; do
  ar mD $SGX_SDK_SOURCE_LIBDIR/libsgx_$lib.a $(ar t $SGX_SDK_SOURCE_LIBDIR/libsgx_$lib.a | env -u LANG LC_ALL=C sort)
  cp $SGX_SDK_SOURCE_LIBDIR/libsgx_$lib.a $SGX_DIR/lib/
done

ar mD $SGX_SDK_SOURCE_DIR/sdk/selib/linux/libselib.a $(ar t $SGX_SDK_SOURCE_DIR/sdk/selib/linux/libselib.a | env -u LANG LC_ALL=C sort)
cp $SGX_SDK_SOURCE_DIR/sdk/selib/linux/libselib.a $SGX_DIR/lib/


for bin in sgx_edger8r sgx_sign; do
  cp $SGX_SDK_SOURCE_LIBDIR/$bin $SGX_DIR/bin
done

cp -rf $SGX_SDK_SOURCE_INCLUDEDIR $SGX_DIR/include
rm -rf $SGX_DIR/unpack $SGX_SDK_SOURCE_DIR
