//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::collections::HashMap;
use std::sync::mpsc;

use failure::{Fail, ResultExt};
use futures::prelude::*;
use futures::sync::oneshot;
use ias_client::*;
use kbupd_api::entities::BackupId;
use kbupd_api::entities::*;

use crate::enclave::enclave::Enclave;
use crate::peer::manager::*;
use crate::protobufs::kbupd::*;
use crate::*;

use super::ffi::sgxsd::*;

type EnclaveManagerCallback = Box<dyn FnOnce(&mut EnclaveManager) -> Result<(), failure::Error> + Send>;

#[derive(Clone)]
pub struct EnclaveManagerSender(mpsc::Sender<EnclaveManagerCallback>);
impl EnclaveManagerSender {
    pub fn cast<F, FErr>(&self, fun: F) -> Result<(), ()>
    where
        F: FnOnce(&mut EnclaveManager) -> Result<(), FErr> + Send + 'static,
        failure::Error: From<FErr>,
    {
        self.0
            .send(Box::new(move |manager: &mut EnclaveManager| Ok(fun(manager)?)))
            .map_err(|_| ())
    }

    pub fn call<F, FErr, T, E>(&self, fun: F) -> impl Future<Item = T, Error = E>
    where
        T: Send + 'static,
        E: From<futures::Canceled> + Send + 'static,
        F: FnOnce(&mut EnclaveManager, oneshot::Sender<Result<T, E>>) -> Result<(), FErr> + Send + 'static,
        failure::Error: From<FErr>,
    {
        let (tx, rx) = oneshot::channel();
        let _ignore = self.cast(move |manager: &mut EnclaveManager| fun(manager, tx));
        rx.from_err().and_then(|result: Result<T, E>| result)
    }
}

pub struct EnclaveManagerChannel {
    tx: EnclaveManagerSender,
    rx: mpsc::Receiver<EnclaveManagerCallback>,
}
impl EnclaveManagerChannel {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        let tx = EnclaveManagerSender(tx);
        Self { tx, rx }
    }

    pub fn sender(&self) -> &EnclaveManagerSender {
        &self.tx
    }
}

pub struct EnclaveManager {
    channel:  EnclaveManagerChannel,
    stopped:  bool,
    enclaves: HashMap<String, Enclave>,
}

impl EnclaveManager {
    pub fn new(channel: EnclaveManagerChannel, enclaves: impl IntoIterator<Item = Enclave>) -> Self {
        Self {
            channel,
            stopped: false,
            enclaves: enclaves
                .into_iter()
                .map(|enclave: Enclave| (enclave.name().to_string(), enclave))
                .collect(),
        }
    }

    pub fn run(&mut self) -> Result<(), failure::Error> {
        self.stopped = false;
        while let Ok(fun) = self.channel.rx.recv() {
            fun(self)?;
            if self.stopped {
                break;
            }
        }
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), failure::Error> {
        self.stopped = true;
        Ok(())
    }

    pub fn get_next_quotes(&self, reply_tx: oneshot::Sender<Result<Vec<(String, SgxQuote)>, failure::Error>>) -> Result<(), EnclaveError> {
        let mut quotes: Vec<(String, SgxQuote)> = Vec::with_capacity(self.enclaves.len());
        for (enclave_name, enclave) in self.enclaves.iter() {
            let quote = match enclave.get_next_quote() {
                Ok(quote) => quote,
                Err(error) => {
                    let context = error.clone().context(format!("error fetching quote for enclave {}", enclave_name));
                    let _ignore = reply_tx.send(Err(context.into()));
                    return Err(error);
                }
            };
            quotes.push((enclave_name.clone(), quote));
        }
        let _ignore = reply_tx.send(Ok(quotes));
        Ok(())
    }

    pub fn start_replica_group(
        &mut self,
        enclave_name: &str,
        start_replica_group_request: StartReplicaGroupRequest,
    ) -> Result<(), EnclaveError>
    {
        if let Some(enclave) = self.enclaves.get_mut(enclave_name) {
            enclave.start_replica_group(start_replica_group_request)?;
            self.refresh_status(false)?;
        }
        Ok(())
    }

    pub fn set_current_quote(&mut self, enclave_name: String, signed_quote: SignedQuote) -> Result<(), EnclaveError> {
        if let Some(enclave) = self.enclaves.get_mut(&enclave_name) {
            enclave.set_current_quote(Some(signed_quote))
        } else {
            Ok(())
        }
    }

    pub fn untrusted_message(&mut self, enclave_name: impl AsRef<str>, message: UntrustedMessage) -> Result<(), EnclaveError> {
        if let Some(enclave) = self.enclaves.get_mut(enclave_name.as_ref()) {
            enclave.enqueue_message(message);
            enclave.run_to_completion()?;
        }
        Ok(())
    }

    pub fn get_attestation_reply(
        &mut self,
        enclave_name: String,
        request_id: Vec<u8>,
        result: Result<SignedQuote, GetQuoteSignatureError>,
    ) -> Result<(), EnclaveError>
    {
        match result {
            Ok(signed_quote) => {
                let reply = GetAttestationReply {
                    request_id,
                    ias_report: IasReport {
                        body:         signed_quote.body,
                        signature:    signed_quote.signature,
                        certificates: signed_quote.certificates,
                    },
                };
                if let Some(enclave) = self.enclaves.get_mut(&enclave_name) {
                    enclave.enqueue_message(UntrustedMessage {
                        inner: Some(untrusted_message::Inner::GetAttestationReply(reply)),
                    });
                    enclave.run_to_completion()?;
                }
            }
            Err(error) => {
                warn!("error fetching attestation for {}: {:?}", util::ToHex(&request_id), error);
            }
        }
        Ok(())
    }

    pub fn xfer(
        &mut self,
        enclave_name: String,
        request: XferControlCommand,
        reply_tx: oneshot::Sender<Result<XferControlReply, failure::Error>>,
    ) -> Result<(), EnclaveError>
    {
        if let Some(enclave) = self.enclaves.get_mut(&enclave_name) {
            let xfer_request_data = untrusted_xfer_request::Data::XferControlCommand(request as i32);
            enclave.xfer_request(xfer_request_data, move |reply: UntrustedXferReply| {
                let _ignore = reply_tx.send(Ok(XferControlReply {
                    status: reply.status.into(),
                }));
            })
        } else {
            let _ignore = reply_tx.send(Err(failure::format_err!("enclave not found")));
            Ok(())
        }
    }

    pub fn transaction(
        &mut self,
        enclave_name: String,
        request_data: untrusted_transaction_request::Data,
        reply_tx: oneshot::Sender<Result<untrusted_transaction_reply::Data, EnclaveTransactionError>>,
    ) -> Result<(), EnclaveError>
    {
        if let Some(enclave) = self.enclaves.get_mut(&enclave_name) {
            enclave.transaction_request(request_data, move |reply_data: untrusted_transaction_reply::Data| {
                let _ignore = reply_tx.send(Ok(reply_data));
            })
        } else {
            let _ignore = reply_tx.send(Err(EnclaveTransactionError::EnclaveNotFound));
            Ok(())
        }
    }

    pub fn remote_attestation(
        &mut self,
        enclave_name: String,
        request: RemoteAttestationRequest,
        reply_tx: oneshot::Sender<Result<RemoteAttestationResponse, RemoteAttestationError>>,
    ) -> Result<(), EnclaveError>
    {
        if let Some(enclave) = self.enclaves.get_mut(&enclave_name) {
            let result = enclave.negotiate_client(&request);
            if let Err(error) = &result {
                // XXX stop on some enclave errors here
                if let KeyBackupError::EnclaveError(_) = KeyBackupError::from(error.clone()) {
                    error!("remote attestation error: {}", error);
                }
            }
            let _ignore = reply_tx.send(result.map_err(|error| error.into()));
            Ok(())
        } else {
            let _ignore = reply_tx.send(Err(RemoteAttestationError::EnclaveNotFound));
            Ok(())
        }
    }

    pub fn key_backup(
        &mut self,
        enclave_name: String,
        backup_id: BackupId,
        request: KeyBackupRequest,
        reply_tx: oneshot::Sender<Result<KeyBackupResponse, KeyBackupError>>,
    ) -> Result<(), EnclaveError>
    {
        if let Some(enclave) = self.enclaves.get_mut(&enclave_name) {
            enclave.start_sgxsd_server()?;
            let result = enclave.client_request(backup_id, request, reply_tx);
            if let Err(error) = &result {
                // XXX stop on some enclave errors here
                if let KeyBackupError::EnclaveError(_) = KeyBackupError::from(error.clone()) {
                    error!("client request error: {}", error);
                }
            }
            enclave.run_to_completion()
        } else {
            let _ignore = reply_tx.send(Err(KeyBackupError::EnclaveNotFound));
            Ok(())
        }
    }

    pub fn refresh_status(&mut self, memory_status: bool) -> Result<(), EnclaveError> {
        for (_enclave_name, enclave) in &mut self.enclaves {
            enclave.enqueue_message(UntrustedMessage {
                inner: Some(untrusted_message::Inner::GetEnclaveStatusRequest(GetEnclaveStatusRequest {
                    memory_status,
                })),
            });
            enclave.run_to_completion()?;
        }
        Ok(())
    }

    pub fn get_status(
        &mut self,
        request: GetStatusControlRequest,
        reply_tx: oneshot::Sender<Result<GetStatusControlReply, failure::Error>>,
    ) -> Result<(), EnclaveError>
    {
        let mut enclaves = Vec::with_capacity(self.enclaves.len());
        for (enclave_name, enclave) in &mut self.enclaves {
            enclave.enqueue_message(UntrustedMessage {
                inner: Some(untrusted_message::Inner::GetEnclaveStatusRequest(GetEnclaveStatusRequest {
                    memory_status: request.memory_status,
                })),
            });
            enclave.run_to_completion()?;

            if let Some(node_id) = enclave.node_id() {
                let config = if let Some(config) = enclave.replica_config() {
                    Some(enclave_status::Config::ReplicaConfig(config.clone()))
                } else if let Some(config) = enclave.frontend_config() {
                    Some(enclave_status::Config::FrontendConfig(config.clone()))
                } else {
                    None
                };
                let status = enclave.status().map(|status: &get_enclave_status_reply::Inner| match status {
                    get_enclave_status_reply::Inner::FrontendStatus(status) => enclave_status::Status::FrontendStatus(status.clone()),
                    get_enclave_status_reply::Inner::ReplicaStatus(status) => enclave_status::Status::ReplicaStatus(status.clone()),
                });
                enclaves.push(EnclaveStatus {
                    name: enclave_name.clone(),
                    node_id: node_id.to_vec(),
                    config,
                    status,
                });
            }
        }
        let _ignore = reply_tx.send(Ok(GetStatusControlReply { enclaves }));
        Ok(())
    }

    pub fn get_peer_manager(
        &mut self,
        enclave_name: String,
        reply_tx: oneshot::Sender<Result<Option<PeerManagerSender>, futures::Canceled>>,
    ) -> Result<(), EnclaveError>
    {
        let peer_manager_tx = (self.enclaves.get(&enclave_name)).map(|enclave: &Enclave| enclave.peer_manager().clone());
        let _ignore = reply_tx.send(Ok(peer_manager_tx));
        Ok(())
    }

    pub fn get_sgx_gid(&mut self, reply_tx: oneshot::Sender<Result<u32, failure::Error>>) -> Result<(), EnclaveError> {
        let gid_result = sgx_sdk_ffi::get_gid().context("error fetching sgx gid");

        let _ignore = reply_tx.send(gid_result.map_err(failure::Error::from));
        Ok(())
    }

    pub fn set_signature_revocation_list(&mut self, sig_rl: SignatureRevocationList) -> Result<(), EnclaveError> {
        for (_enclave_name, enclave) in &mut self.enclaves {
            enclave.set_signature_revocation_list(sig_rl.clone());
        }
        Ok(())
    }
}

impl backup::BackupEnclave for EnclaveManagerSender {
    fn create_backup(
        &self,
        enclave_name: String,
        backup_id: BackupId,
    ) -> Box<dyn Future<Item = CreateBackupReply, Error = EnclaveTransactionError> + Send>
    {
        let request = untrusted_transaction_request::Data::CreateBackupRequest(CreateBackupRequest {
            backup_id: protobufs::kbupd::BackupId { id: backup_id.to_vec() },
        });
        let reply_data = self.call(move |manager: &mut EnclaveManager, reply_tx| manager.transaction(enclave_name, request, reply_tx));
        let reply = reply_data.and_then(|reply_data: untrusted_transaction_reply::Data| {
            if let untrusted_transaction_reply::Data::CreateBackupReply(create_backup_reply) = reply_data {
                Ok(create_backup_reply)
            } else {
                Err(EnclaveTransactionError::InternalError)
            }
        });
        Box::new(reply)
    }

    fn get_attestation(
        &self,
        enclave_name: String,
        request: RemoteAttestationRequest,
    ) -> Box<dyn Future<Item = RemoteAttestationResponse, Error = RemoteAttestationError> + Send>
    {
        let reply = self.call(move |manager: &mut EnclaveManager, reply_tx| manager.remote_attestation(enclave_name, request, reply_tx));
        Box::new(reply)
    }

    fn put_backup_request(
        &self,
        enclave_name: String,
        backup_id: BackupId,
        request: KeyBackupRequest,
    ) -> Box<dyn Future<Item = KeyBackupResponse, Error = KeyBackupError> + Send>
    {
        let reply = self.call(move |manager: &mut EnclaveManager, reply_tx| manager.key_backup(enclave_name, backup_id, request, reply_tx));
        Box::new(reply)
    }

    fn delete_backups(
        &self,
        backup_id: BackupId
    ) -> Box<dyn Future<Item=(), Error=EnclaveTransactionError> + Send>
    {
        let status_request = GetStatusControlRequest {
            memory_status: false
        };

        let sender = self.clone();

        let delete_future = self.call(move |manager: &mut EnclaveManager, reply_tx| manager.get_status(status_request, reply_tx))
            .map_err(|_| EnclaveTransactionError::InternalError)
            .and_then(move |status| {
                let mut delete_futures = Vec::new();

                for enclave in status.enclaves {
                    let delete_request = untrusted_transaction_request::Data::DeleteBackupRequest(DeleteBackupRequest {
                        backup_id: protobufs::kbupd::BackupId { id: backup_id.to_vec() },
                    });

                    delete_futures.push(sender.call(|manager: &mut EnclaveManager, reply_tx| manager.transaction(enclave.name, delete_request, reply_tx)).and_then(|reply: untrusted_transaction_reply::Data| {
                        if let untrusted_transaction_reply::Data::DeleteBackupReply(delete_backup_reply) = reply {
                            Ok(delete_backup_reply)
                        } else {
                            Err(EnclaveTransactionError::InternalError)
                        }
                    }));
                }

                tokio::prelude::future::join_all(delete_futures)
            })
            .map(|_| ());

        Box::new(delete_future)
    }
}
