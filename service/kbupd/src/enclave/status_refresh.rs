//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::time::*;

use futures::prelude::*;
use tokio::timer;

use crate::*;

pub struct EnclaveStatusRefreshTask {
    interval:           Duration,
    enclave_manager_tx: EnclaveManagerSender,
}

impl EnclaveStatusRefreshTask {
    pub fn new(interval: Duration, enclave_manager_tx: EnclaveManagerSender) -> Self {
        Self {
            interval,
            enclave_manager_tx,
        }
    }

    fn refresh_status(self) -> Result<Self, ()> {
        self.enclave_manager_tx
            .cast(move |enclave_manager: &mut EnclaveManager| enclave_manager.refresh_status(false))?;
        Ok(self)
    }

    pub fn into_future(self) -> impl Future<Item = (), Error = ()> {
        let interval_timer_stream = timer::Interval::new_interval(self.interval).map_err(|error: timer::Error| {
            error!("tokio timer error: {}", error);
        });

        let interval_timer = interval_timer_stream.fold(self, |state: Self, _now: Instant| state.refresh_status());

        interval_timer.map(|_state: Self| {
            error!("tokio timer terminated");
        })
    }
}
