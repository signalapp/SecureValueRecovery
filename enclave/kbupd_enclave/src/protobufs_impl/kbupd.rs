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

use std::cmp::*;
use std::fmt;
use std::ops::*;
use crate::prelude::*;


use crate::util::*;
use crate::protobufs::kbupd::*;
use crate::protobufs::kbupd_enclave;
use crate::protobufs::kbupd_client;

//
// ServiceId impls
//

impl fmt::Display for ServiceId {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { id } = self;
        write!(fmt, "{}", ToHex(id))
    }
}

//
// BackupId impls
//

impl BackupId {
    pub const LENGTH: usize = 32;
    pub fn valid_len() -> u32 {
        32
    }

    pub fn try_from_slice<T>(slice: T) -> Result<Self, ()>
    where T: AsRef<[u8]>,
    {
        let slice: &[u8] = slice.as_ref();
        if slice.len() == Self::LENGTH {
            let id = slice.to_vec();
            Ok(Self { id })
        } else {
            Err(())
        }
    }
    pub fn try_to_array(&self) -> Result<[u8; Self::LENGTH], ()> {
        let mut array = [0; Self::LENGTH];
        if self.id.len() == array.len() {
            array.copy_from_slice(&self.id);
            Ok(array)
        } else {
            Err(())
        }
    }
}

impl From<[u8; 32]> for BackupId {
    fn from(from: [u8; 32]) -> Self {
        Self { id: from.to_vec() }
    }
}

impl AsRef<[u8]> for BackupId {
    fn as_ref(&self) -> &[u8] {
        &self.id
    }
}

impl Deref for BackupId {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.id
    }
}

impl Eq for BackupId {}
impl PartialOrd for BackupId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}
impl Ord for BackupId {
    fn cmp(&self, other: &Self) -> Ordering { self.id.cmp(&other.id) }
}

impl fmt::Display for BackupId {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { id } = self;
        write!(fmt, "{}", ToHex(id))
    }
}

//
// PartitionKeyRangePB
//

impl fmt::Display for PartitionKeyRangePb {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { first, last } = self;
        write!(fmt, "{}-{}", ToHex(first), ToHex(last))
    }
}

//
// UntrustedTransactionRequest
//

impl fmt::Display for UntrustedTransactionRequest {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, fmt)
    }
}

//
// EnclaveFrontendRequestTransaction
//

impl enclave_frontend_request_transaction::Transaction {
    pub fn from_reply(backup_id: BackupId, reply_data: &kbupd_enclave::transaction_reply::Data) -> Self {
        use enclave_frontend_request_transaction::{Transaction};
        use kbupd_enclave::transaction_reply::{Data as ReplyData};
        use kbupd_enclave::*;

        match reply_data {
            ReplyData::CreateBackupReply(CreateBackupReply { .. }) =>
                Transaction::Create(EnclaveCreateBackupTransaction { backup_id }),

            ReplyData::ClientResponse(kbupd_client::Response { backup: Some(backup_response), .. }) =>
                Transaction::Backup(EnclaveBackupTransaction {
                    backup_id,
                    status: backup_response.status.unwrap_or_default(),
                }),

            ReplyData::ClientResponse(kbupd_client::Response { restore: Some(restore_response), .. }) =>
                Transaction::Restore(EnclaveRestoreTransaction {
                    backup_id,
                    status: restore_response.status.unwrap_or_default(),
                }),

            ReplyData::ClientResponse(kbupd_client::Response { delete: Some(_), .. }) |
            ReplyData::DeleteBackupReply(DeleteBackupReply { .. }) =>
                Transaction::Delete(EnclaveDeleteBackupTransaction { backup_id }),

            ReplyData::WrongPartition(TransactionErrorWrongPartition { new_partition, .. }) =>
                Transaction::WrongPartition(EnclaveTransactionErrorWrongPartition {
                    new_partition_unknown: new_partition.is_none(),
                }),

            ReplyData::XferInProgress(TransactionErrorXferInProgress {}) =>
                Transaction::XferInProgress(EnclaveTransactionErrorXferInProgress {}),

            ReplyData::ClientResponse(kbupd_client::Response { backup: None, restore: None, delete: None }) |
            ReplyData::InvalidRequest(TransactionErrorInvalidRequest {}) =>
                Transaction::InvalidRequest(EnclaveTransactionErrorInvalidRequest {}),

            ReplyData::NotLeader(TransactionErrorNotLeader { .. }) |
            ReplyData::ServiceIdMismatch(TransactionErrorServiceIdMismatch {}) |
            ReplyData::InternalError(TransactionErrorInternalError {}) =>
                Transaction::InternalError(EnclaveTransactionErrorInternalError {}),
        }
    }
}


//
// EnclaveFrontendConfig
//

impl fmt::Display for EnclaveFrontendConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, fmt)
    }
}

//
// EnclaveReplicaConfig
//

impl fmt::Display for EnclaveReplicaConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, fmt)
    }
}

//
// SourcePartitionConfig
//

impl fmt::Display for SourcePartitionConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { range, node_ids } = self;
        fmt.debug_struct("SourcePartitionConfig")
           .field("range",    &DisplayAsDebug(range))
           .field("node_ids", &ListDisplay(node_ids.iter().map(|node_id| ToHex(node_id))))
           .finish()
    }
}
