//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::env;

fn main() {
    if let None = env::var_os("CARGO_FEATURE_TEST") {
        println!("cargo:rustc-env=RUSTC_BOOTSTRAP=1");
    }
}
