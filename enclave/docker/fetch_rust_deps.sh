#!/bin/bash
source deps.mk
set -e
set -x

RUST_DEPS_DIR=rust_deps
mkdir -p $RUST_DEPS_DIR/unpack
wget -O - https://github.com/signalapp/prost/archive/$PROST_GIT_REV.tar.gz | tar -xzf - -C $RUST_DEPS_DIR/unpack/
mv $RUST_DEPS_DIR/unpack/prost-$PROST_GIT_REV $RUST_DEPS_DIR/
wget -O - https://github.com/signalapp/ring/archive/$RING_GIT_REV.tar.gz | tar -xzf - -C $RUST_DEPS_DIR/unpack/
mkdir $RUST_DEPS_DIR/unpack/ring-$RING_GIT_REV/.git
mv $RUST_DEPS_DIR/unpack/ring-$RING_GIT_REV $RUST_DEPS_DIR/
wget -O - https://github.com/signalapp/serde_json/archive/$SERDE_JSON_GIT_REV.tar.gz | tar -xzf - -C $RUST_DEPS_DIR/unpack/
mv $RUST_DEPS_DIR/unpack/serde_json-$SERDE_JSON_GIT_REV $RUST_DEPS_DIR/
wget -O - https://github.com/signalapp/snow/archive/$SNOW_GIT_REV.tar.gz | tar -xzf - -C $RUST_DEPS_DIR/unpack/
mv $RUST_DEPS_DIR/unpack/snow-$SNOW_GIT_REV $RUST_DEPS_DIR/
wget -O - https://github.com/briansmith/webpki/archive/$WEBPKI_GIT_REV.tar.gz | tar -xzf - -C $RUST_DEPS_DIR/unpack/
mv $RUST_DEPS_DIR/unpack/webpki-$WEBPKI_GIT_REV $RUST_DEPS_DIR/
rmdir $RUST_DEPS_DIR/unpack

mkdir -p src/build
ln -s $(pwd)/rust_deps src/build/rust_deps
