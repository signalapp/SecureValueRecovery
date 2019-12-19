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

use std::path::{PathBuf};

use kbupd_util::hex;
use serde_derive::{Deserialize};

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

    pub tlsConfigPath: PathBuf,

    #[serde(default)]
    pub acceptGroupOutOfDate: bool,

    #[serde(default)]
    pub disabled: bool,
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

#[derive(Deserialize)]
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
