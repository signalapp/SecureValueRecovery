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
