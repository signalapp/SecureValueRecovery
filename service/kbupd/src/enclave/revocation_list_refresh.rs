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
use crate::intel_client::*;

pub struct RevocationListRefreshTask {
    interval:           Duration,
    intel_client:       IntelClient,
    enclave_manager_tx: EnclaveManagerSender,
}

impl RevocationListRefreshTask {
    pub fn new(interval:           Duration,
               intel_client:       IntelClient,
               enclave_manager_tx: EnclaveManagerSender)
               -> Self
    {
        Self {
            interval,
            intel_client,
            enclave_manager_tx,
        }
    }

    fn refresh_revocation_list(self) -> impl Future<Item = Self, Error = ()> {
        let gid = self.enclave_manager_tx.call(|enclave_manager: &mut EnclaveManager, reply_tx| {
            enclave_manager.get_sgx_gid(reply_tx)
        });

        let intel_client    = self.intel_client.clone();
        let revocation_list = gid.and_then(move |gid: u32| {
            info!("fetching signature revocation list for gid: {:08x}", gid);
            intel_client.get_signature_revocation_list(gid)
        });

        let sent_revocation_list = revocation_list.then(|revocation_list_result: Result<SignatureRevocationList, failure::Error>| {
            match revocation_list_result {
                Ok(revocation_list) => {
                    self.enclave_manager_tx.cast(move |enclave_manager: &mut EnclaveManager| {
                        enclave_manager.set_signature_revocation_list(revocation_list)
                    })?;
                }
                Err(error) => {
                    warn!("error fetching revocation list from IAS: {:?}", error);
                }
            }
            Ok(self)
        });

        sent_revocation_list
    }

    pub fn into_future(self) -> impl Future<Item = (), Error = ()> {
        let interval_timer_stream = timer::Interval::new_interval(self.interval).map_err(|error: timer::Error| {
            error!("tokio timer error: {}", error);
        });

        let interval_timer = interval_timer_stream.fold(self, |state: Self, _now: Instant| {
            state.refresh_revocation_list()
        });

        interval_timer.map(|_state: Self| {
            error!("tokio timer terminated");
        })
    }
}
