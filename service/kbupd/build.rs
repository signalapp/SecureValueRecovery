/*
 * Copyright (C) 2019 Open Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

fn main() {
    println!("cargo:rustc-link-search=native=./lib");
    println!("cargo:rustc-link-lib=static=kbupd_enclave_u");
    println!("cargo:rustc-link-lib=dylib=sgx_uae_service");
    println!("cargo:rustc-link-lib=dylib=sgx_urts");
    println!("cargo:rustc-link-lib=dylib=sgx_enclave_common");

    let mut cc = cc::Build::new();
    cc.file("c_src/kbupd_enclave_u.c")
      .include("c_src")
      .compile("kbupd_enclave_u");

    let mut protoc = prost_build::Config::new();
    protoc.extern_path(".protobufs.kbupd_client", "kbupd_client")
          .compile_protos(&["src/kbupd.proto"], &["src/", "../kbupd_client/src/"])
          .expect("error compiling protobufs");
}
