FROM amd64/debian:buster-20191014

COPY apt.conf sources.list /etc/apt/

RUN    apt-get update \
    && apt-get install -V -y --no-install-recommends --allow-downgrades \
               build-essential ca-certificates curl git cmake ninja-build \
               devscripts debhelper fakeroot libwww-perl gawk gnupg \
               ocaml-native-compilers ocamlbuild automake autoconf libtool wget python pkg-config \
               libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev \
               llvm-dev libclang-dev clang python3-distutils python3-dev \
    && rm -rf /var/lib/apt/lists/*

ARG UID=0
ARG GID=0

#Create a user to map the host user to.
RUN    groupadd rust \
    && useradd -m -g rust -s /bin/bash rust \
    && mkdir -p /tmp/docker \
    && chown -R rust.rust /tmp/docker

USER rust
ENV HOME /home/rust
ENV USER rust
ENV SHELL /bin/bash

WORKDIR /home/rust

COPY build_bolt.sh /home/rust/
RUN bash build_bolt.sh

COPY deps.mk fetch_rust_deps.sh /home/rust/
RUN bash fetch_rust_deps.sh

COPY deps.mk build_sgx.sh /home/rust/
ADD linux-sgx-patches /home/rust/linux-sgx-patches/
RUN bash ~/build_sgx.sh

ARG TOOLCHAIN=1.40.0
COPY rustup-init.sha256 /tmp/docker/
RUN    curl -f https://static.rust-lang.org/rustup/archive/1.20.2/x86_64-unknown-linux-gnu/rustup-init -o /tmp/rustup-init \
    && [ `sha256sum /tmp/rustup-init|cut -d' ' -f1` = `cut -d' ' -f1</tmp/docker/rustup-init.sha256` ] \
    && chmod a+x /tmp/rustup-init \
    && /tmp/rustup-init -y --profile minimal --component rustfmt clippy --default-toolchain "${TOOLCHAIN}" \
    && rm -rf /tmp/rustup-init /tmp/docker

ENV PATH="/home/rust/.cargo/bin:/home/rust/bin:${PATH}"
RUN cargo install --locked --force --version 0.51.1 --bin bindgen bindgen

CMD [ "/bin/bash" ]
