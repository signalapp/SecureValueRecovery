//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

pub mod kbupd {
    use kbupd_client;
    include!(concat!(env!("OUT_DIR"), "/protobufs.kbupd.rs"));
}
