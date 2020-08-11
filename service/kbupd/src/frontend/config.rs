//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#![allow(non_snake_case)]

use kbupd_config::frontend::*;

use crate::limits::leaky_bucket::LeakyBucketParameters;
use crate::protobufs::kbupd::{BackupId, PartitionKeyRangePb};

//
// FrontendRateLimitConfig impls
//

impl From<FrontendRateLimitConfig> for LeakyBucketParameters {
    fn from(config: FrontendRateLimitConfig) -> Self {
        Self {
            size:      config.bucketSize,
            leak_rate: config.leakRatePerMinute / 60.0,
        }
    }
}

//
// PartitionKeyRangePb impls
//

impl From<&FrontendPartitionRangeConfig> for PartitionKeyRangePb {
    fn from(range: &FrontendPartitionRangeConfig) -> Self {
        Self {
            first: BackupId {
                id: range.firstBackupId.to_vec(),
            },
            last:  BackupId {
                id: range.lastBackupId.to_vec(),
            },
        }
    }
}
