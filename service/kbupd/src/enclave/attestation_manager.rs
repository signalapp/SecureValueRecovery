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

use futures::future;
use futures::prelude::*;
use futures::sync::oneshot;
use ias_client::*;

use crate::*;
use crate::intel_client::*;
use crate::metrics::*;
use crate::protobufs::kbupd::*;

lazy_static::lazy_static! {
    static ref GET_ATTESTATION_ATTEMPT_METER: Meter = METRICS.metric(&metric_name!("get_attestation", "attempts"));
    static ref GET_ATTESTATION_OK_METER:      Meter = METRICS.metric(&metric_name!("get_attestation", "ok"));
    static ref GET_ATTESTATION_ERROR_METER:   Meter = METRICS.metric(&metric_name!("get_attestation", "error"));
}

pub struct AttestationManager {
    enclave_tx:   EnclaveManagerSender,
    intel_client: Option<KbupdIasClient>,
    requests:     HashMap<Vec<u8>, oneshot::Sender<util::Never>>,
}

impl AttestationManager {
    pub fn new(enclave_tx:   EnclaveManagerSender,
               intel_client: Option<KbupdIasClient>)
               -> Self
    {
        Self {
            enclave_tx,
            intel_client,
            requests: HashMap::new(),
        }
    }

    pub fn get_attestation(&mut self, enclave_name: String, request: GetAttestationRequest) {
        if let Some(intel_client) = &self.intel_client {
            GET_ATTESTATION_ATTEMPT_METER.mark();

            let (cancel_tx, cancel_rx) = oneshot::channel();

            // XXX race window after cancellation?
            self.requests.insert(request.request_id.clone(), cancel_tx);

            let enclave_tx   = self.enclave_tx.clone();
            let request_id   = request.request_id.clone();
            let request_id_2 = request.request_id;
            let signed_quote = intel_client.get_quote_signature(request.sgx_quote, true);
            let replied_future = signed_quote.then(move |reply: Result<SignedQuote, GetQuoteSignatureError>| {
                match reply {
                    Ok(_)  => GET_ATTESTATION_OK_METER.mark(),
                    Err(_) => GET_ATTESTATION_ERROR_METER.mark(),
                }
                // XXX clean up cancel_tx
                enclave_tx.cast(move |enclave_manager: &mut EnclaveManager| {
                    enclave_manager.get_attestation_reply(enclave_name, request_id, reply)
                })
            });
            let replied_future = replied_future.select2(cancel_rx).then(move |result: Result<future::Either<_, _>, future::Either<_, _>>| {
                match result {
                    Ok(future::Either::A(((), _cancel_rx))) | Err(future::Either::A(((), _cancel_rx))) => (),
                    Ok(future::Either::B((_, _replied_future))) | Err(future::Either::B((oneshot::Canceled, _replied_future))) => {
                        debug!("canceled fetching attestation for {}", util::ToHex(&request_id_2));
                    }
                }
                Ok(())
            });
            tokio::spawn(replied_future);
        } else {
            let _ignore = self.enclave_tx.cast(move |enclave_manager: &mut EnclaveManager| {
                enclave_manager.get_attestation_reply(enclave_name, request.request_id, Ok(SignedQuote {
                    quote:        request.sgx_quote,
                    body:         Default::default(),
                    signature:    Default::default(),
                    certificates: Default::default(),
                }))
            });
        }
    }
}
