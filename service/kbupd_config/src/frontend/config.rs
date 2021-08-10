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
pub struct FrontendConfig {
    pub api: FrontendApiConfig,

    pub attestation: FrontendAttestationConfig,

    pub control: FrontendControlConfig,

    pub metrics: Option<MetricsConfig>,

    pub enclaves: Vec<FrontendEnclaveConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendApiConfig {
    pub listenHostPort: String,

    #[serde(with = "hex")]
    pub userAuthenticationTokenSharedSecret: Vec<u8>,

    #[serde(with = "hex")]
    pub backupIdSecret: Vec<u8>,

    pub denyBackup: bool,

    #[serde(default)]
    pub limits: FrontendApiRateLimitsConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendApiRateLimitsConfig {
    pub token: FrontendRateLimitConfig,

    pub attestation: FrontendRateLimitConfig,

    pub backup: FrontendRateLimitConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendRateLimitConfig {
    pub bucketSize: u64,

    pub leakRatePerMinute: f64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendAttestationConfig {
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
pub struct FrontendControlConfig {
    pub listenHostPort: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendEnclaveConfig {
    pub name: String,

    pub mrenclave: String,

    pub debug: bool,

    pub electionTimeoutMs: u64,

    pub pendingRequestCount: u32,

    pub pendingRequestTtlMs: u64,

    pub maxBackupDataLength: u32,

    pub partitions: Vec<FrontendPartitionConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendPartitionConfig {
    pub range: Option<FrontendPartitionRangeConfig>,

    pub replicas: Vec<FrontendPartitionReplicaConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendPartitionRangeConfig {
    #[serde(with = "hex::SerdeFixedLengthHex")]
    pub firstBackupId: [u8; 32],

    #[serde(with = "hex::SerdeFixedLengthHex")]
    pub lastBackupId: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendPartitionReplicaConfig {
    pub hostPort: String,
}

//
// FrontendApiRateLimitsConfig impls
//

impl Default for FrontendApiRateLimitsConfig {
    fn default() -> Self {
        Self {
            token:       FrontendRateLimitConfig {
                bucketSize:        10,
                leakRatePerMinute: 10.0,
            },
            attestation: FrontendRateLimitConfig {
                bucketSize:        10,
                leakRatePerMinute: 10.0,
            },
            backup:      FrontendRateLimitConfig {
                bucketSize:        10,
                leakRatePerMinute: 10.0,
            },
        }
    }
}
