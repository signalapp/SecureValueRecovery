# Secure Value Recovery Service (Beta)

## Building the SGX enclave (optional)

### Building reproducibly with Docker

#### Prerequisites:
- GNU Make
- Docker (able to run debian image)

`````
$ make -C <repository_root>/enclave
`````

The default docker-install target will create a reproducible build environment image using
`enclave/docker/Dockerfile`, build the enclave inside a container based on the image, and
install the resulting enclave into `service/kbupd/res/enclave/`. The Dockerfile will
download a stock dated-snapshot debian Docker image. The Debian project builds their
docker images reproducibly, based on the a snapshot of the debian repos on the date of the
build from the [Debian Snapshot Project](https://snapshot.debian.org/). Make will then be
run inside the newly built Docker Debian image as in the [Building with
Debian](#building-with-debian) section below:

NB: the installed enclave will be signed with the SGX debug flag enabled by an
automatically generated signing key. Due to Intel SGX licensing requirements, a debug
enclave can currently only be run with SGX debugging enabled, allowing inspection of its
encrypted memory, and invalidating its security properties. To use an enclave in
production, provide the Intel-whitelisted signing key as
`enclave/libkbupd_enclave.hardened.key` before building. Alternatively, the generated
`enclave/build/libkbupd_enclave.hardened.signdata` file can be signed and saved as
`enclave/build/libkbupd_enclave.sig` with corresponding public key at
`enclave/libkbupd_enclave.pub`, and signed using `make sign install`.

### Building with Debian

#### Prerequisites:
- GNU Make
- cmake
- ninja-build
- gcc
- ocaml-native-compilers
- ocamlbuild
- automake/autoconf/libtool/pkg-config
- libssl-dev
- libcurl4-openssl-dev
- protobuf-compiler
- libprotobuf-dev
- llvm-dev
- libclang-dev
- clang
- git
- devscripts/debhelper/fakeroot
- rust 1.37.0 toolchain from rustup
- [Intel SGX SDK v2.17 SDK](https://github.com/intel/linux-sgx/tree/sgx_2.17) build dependencies

`````
$ make -C <repository_root>/enclave debuild install
`````

`debuild` is a debian tool used to build debian packages after it sanitizes the
environment and installs build dependences. The primary advantage of using debian
packaging tools in this case is to leverage the [Reproducible
Builds](https://wiki.debian.org/ReproducibleBuilds) project. While building a debian
package, `debuild` will record the names and versions of all detected build dependencies
into a *.buildinfo file, for future reproducibility debugging.

The `debuild` target also builds parts needed from the Intel SGX SDK v2.17 after cloning it
from github.

The `install` target copies the enclave to `service/kbupd/res/enclave/`, which should
potentially be checked in to be used with the service.

The `sign` target may also be used as described in [Building reproducibly with
Docker](#building-reproducibly-with-docker) to produce a release-mode enclave.

### Building without Docker or Debian:

#### Prerequisites:
- GNU Make
- cmake
- ninja-build
- gcc
- ocaml-native-compilers
- ocamlbuild
- automake/autoconf/libtool/pkg-config
- libssl-dev
- libcurl4-openssl-dev
- protobuf-compiler
- libprotobuf-dev
- llvm-dev
- libclang-dev
- clang
- git
- rust 1.37.0 toolchain from rustup
- [Intel SGX SDK v2.17 SDK](https://github.com/intel/linux-sgx/tree/sgx_2.17) build dependencies

`````
$ make -C <repository_root>/enclave all install
`````

The `all` target will probably fail to reproduce the same binary as above, but doesn't
require Docker or Debian Linux.

The `sign` target may also be used as described in [Building reproducibly with
Docker](#building-reproducibly-with-docker) to produce a release-mode enclave.

## Building the service

### Building with Docker

#### Prerequisites:
- GNU Make
- Docker (able to run ubuntu image)

`````
$ make -C <repository_root>/service docker
`````

### Building without Docker

#### Prerequisites:
- GNU Make
- a C compiler
- rust toolchain (i.e. rustc, cargo)
- libsgx-enclave-common [from source](https://github.com/intel/linux-sgx/tree/master#install-the-intelr-sgx-psw) or [prebuilt](https://download.01.org/intel-sgx/sgx_repo/ubuntu/pool/main/libs/libsgx-enclave-common/)
- libssl-dev (OpenSSL)
- libseccomp-dev
- pkg-config
- protobuf-compiler
- [Intel SGX SDK SDK](https://github.com/intel/linux-sgx) headers (common/inc/sgx*.h) installed in a system include directory

`````
$ make -C <repository_root>/service all
`````

## Running the service

### Runtime requirements:
- libsgx-enclave-common >= 2.17.100.3 [from source](https://github.com/intel/linux-sgx/tree/master#install-the-intelr-sgx-psw) or [prebuilt](https://download.01.org/intel-sgx/sgx_repo/ubuntu/pool/main/libs/libsgx-enclave-common/)
- linux-sgx-driver >= 2.17 [from source](https://github.com/intel/linux-sgx-driver) or [prebuilt](https://download.01.org/intel-sgx/sgx-linux/2.17/distro/ubuntu18.04-server/)
- libssl1.1 (OpenSSL)
- libseccomp2
- libprotobuf10

`````
$ service/build/target/release/kbupd help
`````
