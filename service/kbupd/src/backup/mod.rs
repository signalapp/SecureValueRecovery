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

pub mod manager;
pub mod request_manager;

use futures::prelude::*;
use kbupd_api::entities::*;
use kbupd_api::entities::{BackupId};

use crate::enclave::error::*;
use crate::protobufs::kbupd::*;

pub trait BackupEnclave: Send {
    fn create_backup(&self, enclave_name: String, backup_id: BackupId) -> Box<dyn Future<Item = CreateBackupReply, Error = EnclaveTransactionError> + Send>;
    fn get_attestation(&self, enclave_name: String, request: RemoteAttestationRequest) -> Box<dyn Future<Item = RemoteAttestationResponse, Error = RemoteAttestationError> + Send>;
    fn put_backup_request(&self, enclave_name: String, backup_id: BackupId, request: KeyBackupRequest) -> Box<dyn Future<Item = KeyBackupResponse, Error = KeyBackupError> + Send>;
}
