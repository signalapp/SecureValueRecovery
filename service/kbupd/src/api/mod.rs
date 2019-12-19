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

pub mod auth;
pub mod listener;
pub mod service;

use futures::prelude::*;
use kbupd_api::entities::*;

use crate::*;

#[cfg_attr(test, mockers_derive::mocked(BackupManagerMock))]
pub trait BackupManager {
    type User;
    fn get_token(&self, enclave_name: String, user: &Self::User) -> Box<dyn Future<Item = GetTokenResponse, Error = EnclaveTransactionError> + Send>;
    fn get_attestation(&self, enclave_name: String, user: &Self::User, request: RemoteAttestationRequest) -> Box<dyn Future<Item = RemoteAttestationResponse, Error = RemoteAttestationError> + Send>;
    fn put_backup_request(&self, enclave_name: String, user: &Self::User, request: KeyBackupRequest) -> Box<dyn Future<Item = KeyBackupResponse, Error = KeyBackupError> + Send>;
}

#[cfg(test)]
impl<User> Clone for BackupManagerMock<User> {
    fn clone(&self) -> Self {
        use mockers::Mock;
        Self::new(self.mock_id, self.scenario.clone())
    }
}
