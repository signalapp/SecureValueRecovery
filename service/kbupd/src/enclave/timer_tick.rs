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

use std::time::*;

use futures::prelude::*;
use tokio::timer;

use crate::*;
use crate::protobufs::kbupd::*;

pub struct EnclaveTimerTickTask {
    interval:           Duration,
    enclave_name:       String,
    enclave_manager_tx: EnclaveManagerSender,
}

impl EnclaveTimerTickTask {
    pub fn new(interval:           Duration,
               enclave_name:       String,
               enclave_manager_tx: EnclaveManagerSender)
               -> Self
    {
        Self {
            interval,
            enclave_name,
            enclave_manager_tx,
        }
    }

    fn tick(self) -> Result<Self, ()> {
        let enclave_name = self.enclave_name.clone();
        let message      = UntrustedMessage {
            inner: Some(untrusted_message::Inner::TimerTickSignal(TimerTickSignal {
                now_secs: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs(),
            })),
        };
        self.enclave_manager_tx.cast(move |enclave_manager: &mut EnclaveManager| {
            enclave_manager.untrusted_message(enclave_name, message)
        })?;
        Ok(self)
    }

    pub fn into_future(self) -> impl Future<Item = (), Error = ()> {
        let interval_timer_stream = timer::Interval::new_interval(self.interval).map_err(|error: timer::Error| {
            error!("tokio timer error: {}", error);
        });

        let interval_timer = interval_timer_stream.fold(self, |state: Self, _now: Instant| {
            state.tick()
        });

        interval_timer.map(|_state: Self| {
            error!("tokio timer terminated");
        })
    }
}
