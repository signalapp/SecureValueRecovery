//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use crate::prelude::*;

use std::mem;

use sgx_ffi::util::{clear, SecretValue};

use crate::protobufs::raft::*;

//
// LogEntry impls
//

impl LogEntry {
    pub fn new(term: TermId, data: SecretValue<Vec<u8>>) -> Self {
        Self {
            term,
            data: data.into_inner(),
        }
    }

    pub fn into_data(mut self) -> SecretValue<Vec<u8>> {
        SecretValue::new(mem::replace(&mut self.data, Vec::new()))
    }
}

impl Drop for LogEntry {
    fn drop(&mut self) {
        clear(&mut self.data);
    }
}
