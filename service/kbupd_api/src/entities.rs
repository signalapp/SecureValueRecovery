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

#![allow(non_snake_case)]

use std::array::{TryFromSliceError};
use std::convert::{TryFrom, TryInto};
use std::ops::{Deref};

use kbupd_util::base64;
use serde_derive::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[serde(transparent)]
pub struct BackupId(#[serde(with = "base64::SerdeFixedLengthBase64")] [u8; 32]);

#[derive(Deserialize, Serialize)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PingResponse {
}

#[derive(Deserialize, Serialize)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetTokenResponse {
    pub backupId: BackupId,

    #[serde(with = "base64::SerdeFixedLengthBase64")]
    pub token: [u8; 32],

    pub tries: u16,
}

#[derive(Deserialize, Serialize)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteAttestationRequest {
    #[serde(with = "base64::SerdeFixedLengthBase64")]
    pub clientPublic: [u8; 32],
}

#[derive(Deserialize, Serialize)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteAttestationResponse {
    #[serde(with = "base64::SerdeFixedLengthBase64")]
    pub serverEphemeralPublic: [u8; 32],

    #[serde(with = "base64::SerdeFixedLengthBase64")]
    pub serverStaticPublic: [u8; 32],

    #[serde(with = "base64")]
    pub quote: Vec<u8>,

    #[serde(with = "base64::SerdeFixedLengthBase64")]
    pub iv: [u8; 12],

    #[serde(with = "base64")]
    pub ciphertext: Vec<u8>,

    #[serde(with = "base64::SerdeFixedLengthBase64")]
    pub tag: [u8; 16],

    #[serde(with = "base64")]
    pub signature: Vec<u8>,

    pub certificates: String,

    pub signatureBody: String,
}

#[derive(Deserialize, Serialize)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyBackupRequest {
    #[serde(with = "base64")]
    pub requestId: Vec<u8>,

    #[serde(with = "base64::SerdeFixedLengthBase64")]
    pub iv: [u8; 12],

    #[serde(with = "base64")]
    pub data: Vec<u8>,

    #[serde(with = "base64::SerdeFixedLengthBase64")]
    pub mac: [u8; 16],

    pub r#type: KeyBackupRequestType,
}

#[derive(Deserialize, Serialize)]
#[derive(Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum KeyBackupRequestType {
    Backup,
    Restore,
    Delete,
}

#[derive(Deserialize, Serialize)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyBackupResponse {
    #[serde(with = "base64::SerdeFixedLengthBase64")]
    pub iv: [u8; 12],

    #[serde(with = "base64")]
    pub data: Vec<u8>,

    #[serde(with = "base64::SerdeFixedLengthBase64")]
    pub mac: [u8; 16],
}

//
// BackupId impls
//

impl Deref for BackupId {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&[u8]> for BackupId {
    type Error = TryFromSliceError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl From<BackupId> for [u8; 32] {
    fn from(value: BackupId) -> Self {
        value.0
    }
}

impl From<[u8; 32]> for BackupId {
    fn from(value: [u8; 32]) -> Self {
        BackupId(value)
    }
}
