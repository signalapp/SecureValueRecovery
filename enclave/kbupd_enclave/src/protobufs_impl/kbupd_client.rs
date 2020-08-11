//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use sgx_ffi::util::clear;

use crate::protobufs::kbupd_client::*;

//
// BackupRequest impls
//

impl Drop for BackupRequest {
    fn drop(&mut self) {
        if let Some(data) = &mut self.data {
            clear(data);
        }
        if let Some(pin) = &mut self.pin {
            clear(pin);
        }
    }
}

//
// RestoreRequest impls
//

impl Drop for RestoreRequest {
    fn drop(&mut self) {
        if let Some(pin) = &mut self.pin {
            clear(pin);
        }
    }
}

//
// RestoreResponse impls
//

impl Drop for RestoreResponse {
    fn drop(&mut self) {
        if let Some(data) = &mut self.data {
            clear(data);
        }
    }
}
