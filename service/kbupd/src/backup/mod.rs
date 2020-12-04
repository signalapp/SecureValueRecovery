//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

pub mod manager;
pub mod request_manager;

use futures::prelude::*;
use kbupd_api::entities::BackupId;
use kbupd_api::entities::*;

use crate::enclave::error::*;
use crate::protobufs::kbupd::*;

pub trait BackupEnclave: Send {
    fn create_backup(
        &self,
        enclave_name: String,
        backup_id: BackupId,
    ) -> Box<dyn Future<Item = CreateBackupReply, Error = EnclaveTransactionError> + Send>;
    fn get_attestation(
        &self,
        enclave_name: String,
        request: RemoteAttestationRequest,
    ) -> Box<dyn Future<Item = RemoteAttestationResponse, Error = RemoteAttestationError> + Send>;
    fn put_backup_request(
        &self,
        enclave_name: String,
        backup_id: BackupId,
        request: KeyBackupRequest,
    ) -> Box<dyn Future<Item = KeyBackupResponse, Error = KeyBackupError> + Send>;
    fn delete_backups(
        &self,
        backup_id: BackupId,
    ) -> Box<dyn Future<Item = (), Error = EnclaveTransactionError> + Send>;
}
