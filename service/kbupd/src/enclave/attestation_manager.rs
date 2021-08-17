//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::collections::HashMap;

use futures::future;
use futures::prelude::*;
use futures::sync::oneshot;
use ias_client::*;
use kbupd_macro::lazy_init;
use std::time::Duration;
use tokio::timer::Timeout;

use crate::intel_client::*;
use crate::metrics::*;
use crate::protobufs::kbupd::*;
use crate::*;

lazy_init! {
    fn init_metrics() {
        static ref GET_ATTESTATION_ATTEMPT_METER: Meter = METRICS.metric(&metric_name!("get_attestation", "attempts"));
        static ref GET_ATTESTATION_OK_METER:      Meter = METRICS.metric(&metric_name!("get_attestation", "ok"));
        static ref GET_ATTESTATION_ERROR_METER:   Meter = METRICS.metric(&metric_name!("get_attestation", "error"));
    }
}

pub struct AttestationManager {
    enclave_tx:   EnclaveManagerSender,
    intel_client: Option<KbupdIasClient>,
    requests:     HashMap<Vec<u8>, oneshot::Sender<util::Never>>,
}

impl AttestationManager {
    pub fn new(enclave_tx: EnclaveManagerSender, intel_client: Option<KbupdIasClient>) -> Self {
        init_metrics();

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

            let enclave_tx = self.enclave_tx.clone();
            let request_id = request.request_id.clone();
            let request_id_2 = request.request_id;
            let signed_quote =
                Timeout::new(intel_client.get_quote_signature(request.sgx_quote, true), Duration::from_secs(30)).map_err(|e| match e {
                    e if e.is_inner() => e.into_inner().unwrap(),
                    e if e.is_elapsed() => GetQuoteSignatureError::FetchError(failure::format_err!("request timed out")),
                    e if e.is_timer() => GetQuoteSignatureError::FetchError(failure::Error::from_boxed_compat(Box::new(e.into_timer().unwrap()))),
                    _ => GetQuoteSignatureError::FetchError(failure::format_err!("unknown error")),
                });
            let replied_future = signed_quote.then(move |reply: Result<SignedQuote, GetQuoteSignatureError>| {
                match reply {
                    Ok(_) => GET_ATTESTATION_OK_METER.mark(),
                    Err(_) => GET_ATTESTATION_ERROR_METER.mark(),
                }
                // XXX clean up cancel_tx
                enclave_tx.cast(move |enclave_manager: &mut EnclaveManager| {
                    enclave_manager.get_attestation_reply(enclave_name, request_id, reply)
                })
            });
            let replied_future =
                replied_future
                    .select2(cancel_rx)
                    .then(move |result: Result<future::Either<_, _>, future::Either<_, _>>| {
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
                enclave_manager.get_attestation_reply(
                    enclave_name,
                    request.request_id,
                    Ok(SignedQuote {
                        quote:        request.sgx_quote,
                        body:         Default::default(),
                        signature:    Default::default(),
                        certificates: Default::default(),
                    }),
                )
            });
        }
    }
}
