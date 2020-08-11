//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

fn main() {
    prost_build::compile_protos(&["src/kbupd_client.proto"], &["src/"]).expect("error compiling protobufs");
}
