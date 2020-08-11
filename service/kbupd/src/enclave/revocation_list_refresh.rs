//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::time::*;

use futures::prelude::*;
use ias_client::*;
use tokio::timer;

use crate::intel_client::*;
use crate::*;

pub struct RevocationListRefreshTask {
    interval:           Duration,
    intel_client:       KbupdIasClient,
    enclave_manager_tx: EnclaveManagerSender,
}

impl RevocationListRefreshTask {
    pub fn new(interval: Duration, intel_client: KbupdIasClient, enclave_manager_tx: EnclaveManagerSender) -> Self {
        Self {
            interval,
            intel_client,
            enclave_manager_tx,
        }
    }

    fn refresh_revocation_list(self) -> impl Future<Item = Self, Error = ()> {
        let gid = self
            .enclave_manager_tx
            .call(|enclave_manager: &mut EnclaveManager, reply_tx| enclave_manager.get_sgx_gid(reply_tx));

        let intel_client = self.intel_client.clone();
        let revocation_list = gid.and_then(move |gid: u32| {
            info!("fetching signature revocation list for gid: {:08x}", gid);
            intel_client.get_signature_revocation_list(gid)
        });

        let sent_revocation_list = revocation_list.then(|revocation_list_result: Result<SignatureRevocationList, failure::Error>| {
            match revocation_list_result {
                Ok(revocation_list) => {
                    self.enclave_manager_tx
                        .cast(move |enclave_manager: &mut EnclaveManager| enclave_manager.set_signature_revocation_list(revocation_list))?;
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

        let interval_timer = interval_timer_stream.fold(self, |state: Self, _now: Instant| state.refresh_revocation_list());

        interval_timer.map(|_state: Self| {
            error!("tokio timer terminated");
        })
    }
}
