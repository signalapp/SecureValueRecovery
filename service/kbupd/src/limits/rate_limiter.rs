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

use std::collections::{HashMap};
use std::time::{Instant};

use failure::{Fail};

use super::leaky_bucket::*;
use crate::metrics::*;

pub struct RateLimiter {
    parameters: LeakyBucketParameters,
    meter:      Meter,
    buckets:    HashMap<String, LeakyBucket>,
}

#[derive(Debug, Fail)]
pub enum RateLimitError {
    #[fail(display = "{}", _0)]
    Exceeded(#[cause] RateLimitExceededError),
    #[fail(display = "internal error")]
    InternalError,
}

#[derive(Clone, Debug, Fail)]
#[fail(display = "rate limit exceeded for {}, {}", key, amount)]
pub struct RateLimitExceededError {
    pub key:       String,
    pub amount:    u64,
    pub leak_rate: f64,
}

impl RateLimiter {
    pub fn new(name: &str, parameters: LeakyBucketParameters) -> Self {
        Self {
            parameters,
            meter:   METRICS.metric(&metric_name(&[&metric_name!(""), name, "exceeded"])),
            buckets: Default::default(),
        }
    }

    pub fn validate(&mut self, key: &str, amount: u64) -> Result<(), RateLimitError> {
        let bucket = Self::bucket_mut(key, &mut self.buckets, &self.parameters);

        match bucket.add(amount, Instant::now(), &self.parameters) {
            Ok(())  => Ok(()),
            Err(()) => {
                self.meter.mark();
                Err(RateLimitError::Exceeded(RateLimitExceededError {
                    key:       key.to_string(),
                    amount,
                    leak_rate: self.parameters.leak_rate,
                }))
            }
        }
    }

    fn bucket_mut<'a>(key: &str, buckets: &'a mut HashMap<String, LeakyBucket>, parameters: &LeakyBucketParameters) -> &'a mut LeakyBucket {
        if buckets.contains_key(key) {
            buckets.get_mut(key).unwrap_or_else(|| unreachable!())
        } else {
            buckets.entry(key.to_string())
                   .or_insert_with(|| LeakyBucket::new(Instant::now(), parameters))
        }
    }
}

//
// RateLimitError impls
//

impl From<futures::Canceled> for RateLimitError {
    fn from(futures::Canceled: futures::Canceled) -> Self {
        RateLimitError::InternalError
    }
}
