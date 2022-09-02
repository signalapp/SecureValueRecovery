#!/bin/bash

set -e
set -x

BOLT_DIR=bolt
BOLT_GIT_REV=130d2c758964950cf713bddef123104b41642161
BOLT_LLVM_GIT_REV=f137ed238db11440f03083b1c88b7ffc0f4af65e
BOLT_SRC_DIR=$BOLT_DIR/bolt-$BOLT_GIT_REV
BOLT_LLVM_SRC_DIR=$BOLT_DIR/llvm-$BOLT_LLVM_GIT_REV
mkdir -p bin $BOLT_DIR $BOLT_SRC_DIR
wget -O - https://github.com/llvm-mirror/llvm/archive/$BOLT_LLVM_GIT_REV.tar.gz | tar -xzf -  -C $BOLT_DIR
wget -O - https://github.com/signalapp/BOLT/archive/$BOLT_GIT_REV.tar.gz | tar -xzf - -C $BOLT_LLVM_SRC_DIR/tools
mv $BOLT_LLVM_SRC_DIR/tools/BOLT-$BOLT_GIT_REV $BOLT_LLVM_SRC_DIR/tools/llvm-bolt
patch -d $BOLT_LLVM_SRC_DIR -p 1 -T < $BOLT_LLVM_SRC_DIR/tools/llvm-bolt/llvm.patch
mkdir -p $BOLT_DIR/build
(cd $BOLT_DIR/build &&
    cmake -G Ninja ../../$BOLT_LLVM_SRC_DIR -DLLVM_TARGETS_TO_BUILD="X86" -DCMAKE_BUILD_TYPE=Release &&
    ninja)
strip -o bin/llvm-bolt $BOLT_DIR/build/bin/llvm-bolt
rm -rf $BOLT_DIR
