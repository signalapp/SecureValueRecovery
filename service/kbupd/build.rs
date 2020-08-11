//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

fn main() {
    println!("cargo:rustc-link-search=native=./lib");
    println!("cargo:rustc-link-lib=static=kbupd_enclave_u");
    println!("cargo:rustc-link-lib=dylib=sgx_uae_service");
    println!("cargo:rustc-link-lib=dylib=sgx_urts");
    println!("cargo:rustc-link-lib=dylib=sgx_enclave_common");

    let mut cc = cc::Build::new();
    cc.file("c_src/kbupd_enclave_u.c").include("c_src").compile("kbupd_enclave_u");

    let mut protoc = prost_build::Config::new();
    protoc
        .extern_path(".protobufs.kbupd_client", "kbupd_client")
        .compile_protos(&["src/kbupd.proto"], &["src/", "../kbupd_client/src/"])
        .expect("error compiling protobufs");
}
