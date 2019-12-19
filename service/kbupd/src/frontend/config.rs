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

use kbupd_config::frontend::*;

use crate::limits::leaky_bucket::{LeakyBucketParameters};
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
            first: BackupId { id: range.firstBackupId.to_vec() },
            last:  BackupId { id: range.lastBackupId.to_vec() },
        }
    }
}
