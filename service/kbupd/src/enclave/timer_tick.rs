//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::time::*;

use futures::prelude::*;
use tokio::timer;

use crate::protobufs::kbupd::*;
use crate::*;

pub struct EnclaveTimerTickTask {
    interval:           Duration,
    enclave_name:       String,
    enclave_manager_tx: EnclaveManagerSender,
}

impl EnclaveTimerTickTask {
    pub fn new(interval: Duration, enclave_name: String, enclave_manager_tx: EnclaveManagerSender) -> Self {
        Self {
            interval,
            enclave_name,
            enclave_manager_tx,
        }
    }

    fn tick(self) -> Result<Self, ()> {
        let enclave_name = self.enclave_name.clone();
        let message = UntrustedMessage {
            inner: Some(untrusted_message::Inner::TimerTickSignal(TimerTickSignal {
                now_secs: SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            })),
        };
        self.enclave_manager_tx
            .cast(move |enclave_manager: &mut EnclaveManager| enclave_manager.untrusted_message(enclave_name, message))?;
        Ok(self)
    }

    pub fn into_future(self) -> impl Future<Item = (), Error = ()> {
        let interval_timer_stream = timer::Interval::new_interval(self.interval).map_err(|error: timer::Error| {
            error!("tokio timer error: {}", error);
        });

        let interval_timer = interval_timer_stream.fold(self, |state: Self, _now: Instant| state.tick());

        interval_timer.map(|_state: Self| {
            error!("tokio timer terminated");
        })
    }
}
