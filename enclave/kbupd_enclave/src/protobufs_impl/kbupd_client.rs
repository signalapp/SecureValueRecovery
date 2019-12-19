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

use sgx_ffi::util::{clear};

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
