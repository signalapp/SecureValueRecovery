//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#![allow(non_snake_case)]

use kbupd_util::hex;
use serde_derive::Deserialize;

use crate::metrics::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicaConfig {
    pub attestation: ReplicaAttestationConfig,

    pub control: ReplicaControlConfig,

    pub metrics: Option<MetricsConfig>,

    pub enclave: ReplicaEnclaveConfig,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ReplicaAttestationConfig {
    pub host: String,

    #[serde(with = "hex::SerdeFixedLengthHex")]
    pub spid: [u8; 16],

    #[serde(default)]
    pub acceptGroupOutOfDate: bool,

    #[serde(default)]
    pub disabled: bool,

    pub apiKey: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicaControlConfig {
    pub listenHostPort: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicaEnclaveConfig {
    pub mrenclave: String,

    pub debug: bool,

    pub listenHostPort: String,

    pub maxConnections: u32,

    pub storageSize: u32,

    pub maxBackupDataLength: u32,

    pub raftLogSize: u64,

    pub electionTimeoutMs: u64,

    pub electionHeartbeats: u32,

    pub replicationChunkSize: u32,

    pub transferChunkSize: u32,

    pub attestationExpiryCommitIntervalMs: u64,

    pub maxFrontendCount: u32,

    #[serde(default)]
    pub replicas: Vec<ReplicaPeerConfig>,

    pub sourcePartition: Option<ReplicaSourcePartitionConfig>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ReplicaSourcePartitionConfig {
    #[serde(with = "hex::SerdeFixedLengthHex")]
    pub firstBackupId: [u8; 32],

    #[serde(with = "hex::SerdeFixedLengthHex")]
    pub lastBackupId: [u8; 32],

    pub replicas: Vec<ReplicaPeerConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicaPeerConfig {
    pub hostPort: String,
}
