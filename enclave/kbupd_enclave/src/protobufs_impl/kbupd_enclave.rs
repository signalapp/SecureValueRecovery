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

use std::fmt;

use sgx_ffi::util::{clear};

use crate::protobufs::kbupd::*;
use crate::protobufs::kbupd_enclave::*;
use crate::util::*;

//
// SecretBytes impls
//

impl Drop for SecretBytes {
    fn drop(&mut self) {
        clear(&mut self.data);
    }
}

//
// FrontendRequestTransaction impls
//

impl FrontendRequestTransaction {
    pub fn backup_id(&self) -> Option<&BackupId> {
        match &self.transaction {
            Some(frontend_request_transaction::Transaction::Backup(backup))   => Some(&backup.backup_id),
            Some(frontend_request_transaction::Transaction::Restore(restore)) => Some(&restore.backup_id),
            Some(frontend_request_transaction::Transaction::Create(create))   => Some(&create.backup_id),
            Some(frontend_request_transaction::Transaction::Delete(delete))   => Some(&delete.backup_id),
            None => None
        }
    }
}

//
// PeerConnectRequest impls
//

impl fmt::Display for PeerConnectRequest {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        fmt::Debug::fmt(self, fmt)
    }
}

//
// XferRequest impls
//

impl fmt::Display for XferRequest {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let Self { chunk_size, full_range, node_ids, group_id } = self;
        fmt.debug_struct("XferRequest")
           .field("chunk_size", chunk_size)
           .field("full_range", &DisplayAsDebug(full_range))
           .field("node_ids",   &ListDisplay(node_ids.iter().map(|node_id| ToHex(node_id))))
           .field("group_id",   &DisplayAsDebug(group_id))
           .finish()
    }
}
