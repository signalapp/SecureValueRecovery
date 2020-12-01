//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

pub mod auth;
pub mod listener;
pub mod service;

use futures::prelude::*;
use kbupd_api::entities::*;

use crate::*;

#[cfg_attr(test, mockers_derive::mocked(BackupManagerMock))]
pub trait BackupManager {
    type User;
    fn get_token(
        &self,
        enclave_name: String,
        user: &Self::User,
    ) -> Box<dyn Future<Item = GetTokenResponse, Error = EnclaveTransactionError> + Send>;
    fn get_attestation(
        &self,
        enclave_name: String,
        user: &Self::User,
        request: RemoteAttestationRequest,
    ) -> Box<dyn Future<Item = RemoteAttestationResponse, Error = RemoteAttestationError> + Send>;
    fn put_backup_request(
        &self,
        enclave_name: String,
        user: &Self::User,
        request: KeyBackupRequest,
    ) -> Box<dyn Future<Item = KeyBackupResponse, Error = KeyBackupError> + Send>;
    fn delete_backups(
        &self,
        user: &Self::User,
    ) -> Box<dyn Future<Item = (), Error = EnclaveTransactionError> + Send>;
}

#[cfg(test)]
impl<User> Clone for BackupManagerMock<User> {
    fn clone(&self) -> Self {
        use mockers::Mock;
        Self::new(self.mock_id, self.scenario.clone())
    }
}
