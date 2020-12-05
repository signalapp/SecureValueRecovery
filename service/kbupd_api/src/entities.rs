//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#![allow(non_snake_case)]

use std::array::TryFromSliceError;
use std::convert::{TryFrom, TryInto};
use std::ops::Deref;

use kbupd_util::base64;
use serde_derive::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[serde(transparent)]
pub struct BackupId(#[serde(with = "base64::SerdeFixedLengthBase64")] [u8; 32]);

#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub struct PingResponse {}

#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub struct GetTokenResponse {
    pub backupId: BackupId,

    #[serde(with = "base64::SerdeFixedLengthBase64")]
    pub token: [u8; 32],

    pub tries: u16,
}

#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub struct RemoteAttestationRequest {
    #[serde(with = "base64::SerdeFixedLengthBase64")]
    pub clientPublic: [u8; 32],
}

#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
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

#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
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

#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum KeyBackupRequestType {
    Backup,
    Restore,
    Delete,
}

#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
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
