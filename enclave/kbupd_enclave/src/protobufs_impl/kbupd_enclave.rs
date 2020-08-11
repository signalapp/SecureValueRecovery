//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::fmt;

use sgx_ffi::util::clear;

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
            Some(frontend_request_transaction::Transaction::Backup(backup)) => Some(&backup.backup_id),
            Some(frontend_request_transaction::Transaction::Restore(restore)) => Some(&restore.backup_id),
            Some(frontend_request_transaction::Transaction::Create(create)) => Some(&create.backup_id),
            Some(frontend_request_transaction::Transaction::Delete(delete)) => Some(&delete.backup_id),
            None => None,
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
        let Self {
            chunk_size,
            full_range,
            node_ids,
            group_id,
        } = self;
        fmt.debug_struct("XferRequest")
            .field("chunk_size", chunk_size)
            .field("full_range", &DisplayAsDebug(full_range))
            .field("node_ids", &ListDisplay(node_ids.iter().map(|node_id| ToHex(node_id))))
            .field("group_id", &DisplayAsDebug(group_id))
            .finish()
    }
}
