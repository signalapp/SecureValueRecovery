//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use crate::enclave::attestation_manager::AttestationManager;
use std::array::TryFromSliceError;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::fmt::{Debug, Display};
use std::marker::PhantomData;
use std::ops::Deref;

use futures::sync::oneshot;
use ias_client::*;
use kbupd_api::entities::BackupId;
use kbupd_api::entities::*;
use kbupd_macro::lazy_init;
use sgx_sdk_ffi::*;

use crate::metrics::*;
use crate::peer::manager::*;
use crate::protobufs::kbupd::*;
use crate::*;

use super::ffi::ecalls;
use super::ffi::sgxsd::*;

pub struct Enclave {
    enclave_name:    String,
    enclave_id:      SgxEnclaveId,
    node_id:         Option<NodeId>,
    frontend_config: Option<EnclaveFrontendConfig>,
    replica_config:  Option<EnclaveReplicaConfig>,
    status:          Option<GetEnclaveStatusReply>,
    sgx_spid:        [u8; 16],
    sgx_sig_rl:      SignatureRevocationList,
    signed_quote:    Option<SignedQuote>,
    server_handle:   Option<SgxsdServerHandle>,
    send_queue:      Vec<UntrustedMessage>,
    peer_manager_tx: actor::Sender<PeerManager>,
    attestation_tx:  actor::Sender<AttestationManager>,
    txn_requests:    PendingRequestMap<Box<dyn FnOnce(untrusted_transaction_reply::Data) + Send>>,
    xfer_requests:   PendingRequestMap<Box<dyn FnOnce(UntrustedXferReply) + Send>>,
    _unsend:         PhantomData<*mut u8>,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct NodeId([u8; 32]);

pub use super::ffi::sgxsd::SgxQuote;
use std::time::{SystemTime, UNIX_EPOCH};

//
// private defs
//

struct PendingRequestMap<V> {
    last_request_id: u64,
    requests:        HashMap<u64, V>,
}

lazy_init! {
    fn init_metrics() {
        static ref MEMORY_USED_GAUGE:                Gauge = METRICS.metric(&metric_name!("memory",   "used"));
        static ref MEMORY_CHUNKS_GAUGE:              Gauge = METRICS.metric(&metric_name!("memory",   "chunks"));
        static ref REPLICA_MIN_ATTESTATION_GAUGE:    Gauge = METRICS.metric(&metric_name!("replica",  "attestation", "min_timestamp"));
        static ref REPLICA_ATTESTATION_AGE_GAUGE:    Gauge = METRICS.metric(&metric_name!("replica",  "attestation", "min_age"));
        static ref REPLICA_TERM_GAUGE:               Gauge = METRICS.metric(&metric_name!("replica",  "term"));
        static ref REPLICA_LOG_PREV_GAUGE:           Gauge = METRICS.metric(&metric_name!("replica",  "log", "prev"));
        static ref REPLICA_LOG_APPLIED_METER:        Meter = METRICS.metric(&metric_name!("replica",  "log", "applied"));
        static ref REPLICA_LOG_COMMITTED_METER:      Meter = METRICS.metric(&metric_name!("replica",  "log", "committed"));
        static ref REPLICA_LOG_APPENDED_METER:       Meter = METRICS.metric(&metric_name!("replica",  "log", "appended"));

        static ref REPLICA_BACKUPS_COUNT_GAUGE:      Gauge = METRICS.metric(&metric_name!("replica",  "backups", "count"));
        static ref REPLICA_BACKUPS_CREATE_METER:     Meter = METRICS.metric(&metric_name!("replica",  "backups", "create"));
        static ref REPLICA_BACKUPS_BACKUP_METER:     Meter = METRICS.metric(&metric_name!("replica",  "backups", "backup"));
        static ref REPLICA_BACKUPS_RESTORE_METER:    Meter = METRICS.metric(&metric_name!("replica",  "backups", "restore"));
        static ref REPLICA_BACKUPS_DELETE_METER:     Meter = METRICS.metric(&metric_name!("replica",  "backups", "delete"));
        static ref REPLICA_BACKUPS_XFER_IN_PROGRESS_METER: Meter = METRICS.metric(&metric_name!("replica",  "backups", "xfer_in_progress"));
        static ref REPLICA_BACKUPS_WRONG_PARTITION_METER:  Meter = METRICS.metric(&metric_name!("replica",  "backups", "wrong_partition"));
        static ref REPLICA_BACKUPS_INVALID_REQUEST_METER:  Meter = METRICS.metric(&metric_name!("replica",  "backups", "invalid_request"));
        static ref REPLICA_BACKUPS_INTERNAL_ERROR_METER:   Meter = METRICS.metric(&metric_name!("replica",  "backups", "internal_error"));

        static ref FRONTEND_REQUESTS_INFLIGHT_GAUGE: Gauge = METRICS.metric(&metric_name!("frontend", "requests", "inflight"));
        static ref FRONTEND_REQUESTS_UNSENT_GAUGE:   Gauge = METRICS.metric(&metric_name!("frontend", "requests", "unsent"));
    }
}

//
// Enclave impls
//

impl Enclave {
    pub fn new(
        enclave_name: String,
        enclave_path: &str,
        enclave_debug: bool,
        sgx_spid: [u8; 16],
        peer_manager_tx: actor::Sender<PeerManager>,
        attestation_tx: actor::Sender<AttestationManager>,
    ) -> Result<Self, EnclaveError>
    {
        init_metrics();

        let enclave_id = create_enclave(enclave_path, enclave_debug).sgxsd_context("sgx_create_enclave")?;

        Ok(Self {
            enclave_name,
            enclave_id,
            node_id: Default::default(),
            frontend_config: Default::default(),
            replica_config: Default::default(),
            status: Default::default(),
            sgx_spid,
            sgx_sig_rl: Default::default(),
            signed_quote: Default::default(),
            server_handle: Default::default(),
            send_queue: Default::default(),
            peer_manager_tx,
            attestation_tx,
            txn_requests: Default::default(),
            xfer_requests: Default::default(),
            _unsend: Default::default(),
        })
    }

    pub fn name(&self) -> &str {
        &self.enclave_name
    }

    pub fn peer_manager(&self) -> &actor::Sender<PeerManager> {
        &self.peer_manager_tx
    }

    pub fn start_replica(&mut self, start_message: StartReplicaRequest) -> Result<NodeId, EnclaveError> {
        let config = start_message.config.clone();
        self.send_queue.push(UntrustedMessage {
            inner: Some(untrusted_message::Inner::StartReplicaRequest(start_message)),
        });
        self.run_to_completion()?;
        self.replica_config = Some(config);
        self.node_id()
            .ok_or(EnclaveError::InternalError("enclave did not reply to start request"))
    }

    pub fn start_replica_group(&mut self, start_message: StartReplicaGroupRequest) -> Result<(), EnclaveError> {
        self.send_queue.push(UntrustedMessage {
            inner: Some(untrusted_message::Inner::StartReplicaGroupRequest(start_message)),
        });
        self.run_to_completion()
    }

    pub fn start_frontend(
        &mut self,
        start_message: StartFrontendRequest,
        pending_requests_table_order: u8,
    ) -> Result<NodeId, EnclaveError>
    {
        sgxsd_node_init(self.enclave_id, pending_requests_table_order)?;

        let config = start_message.config.clone();
        self.send_queue.push(UntrustedMessage {
            inner: Some(untrusted_message::Inner::StartFrontendRequest(start_message)),
        });
        self.run_to_completion()?;
        self.frontend_config = Some(config);
        self.node_id()
            .ok_or(EnclaveError::InternalError("enclave did not reply to start request"))
    }

    pub fn node_id(&self) -> Option<NodeId> {
        self.node_id
    }

    pub fn status(&self) -> Option<&get_enclave_status_reply::Inner> {
        self.status
            .as_ref()
            .and_then(|status: &GetEnclaveStatusReply| status.inner.as_ref())
    }

    pub fn replica_config(&self) -> Option<&EnclaveReplicaConfig> {
        self.replica_config.as_ref()
    }

    pub fn frontend_config(&self) -> Option<&EnclaveFrontendConfig> {
        self.frontend_config.as_ref()
    }

    pub fn set_signature_revocation_list(&mut self, sig_rl: SignatureRevocationList) {
        if *self.sgx_sig_rl != *sig_rl {
            info!("new signature revocation list of {} bytes", sig_rl.len());
        }
        self.sgx_sig_rl = sig_rl;
    }

    pub fn get_next_quote(&self) -> Result<SgxQuote, EnclaveError> {
        Ok(sgxsd_get_next_quote(self.enclave_id, &self.sgx_spid, &self.sgx_sig_rl)?)
    }

    pub fn set_current_quote(&mut self, signed_quote: Option<SignedQuote>) -> Result<(), EnclaveError> {
        sgxsd_set_current_quote(self.enclave_id)?;
        self.signed_quote = signed_quote;
        Ok(())
    }

    pub fn negotiate_client(&self, request: &RemoteAttestationRequest) -> Result<RemoteAttestationResponse, EnclaveError> {
        let sgxsd_request = SgxsdRequestNegotiationRequest {
            client_pubkey: SgxsdCurve25519PublicKey { x: request.clientPublic },
        };
        let sgxsd_resp = sgxsd_negotiate_request(self.enclave_id, &sgxsd_request)?;
        Ok(RemoteAttestationResponse {
            serverStaticPublic:    sgxsd_resp.server_static_pubkey.x,
            serverEphemeralPublic: sgxsd_resp.server_ephemeral_pubkey.x,

            iv:         sgxsd_resp.encrypted_pending_request_id.iv.data,
            tag:        sgxsd_resp.encrypted_pending_request_id.mac.data,
            ciphertext: sgxsd_resp.encrypted_pending_request_id.data.to_vec(),

            quote:         self
                .signed_quote
                .as_ref()
                .map(|signed_quote| signed_quote.quote.clone())
                .unwrap_or_default(),
            certificates:  self
                .signed_quote
                .as_ref()
                .map(|signed_quote| util::pem::encode("CERTIFICATE", signed_quote.certificates.iter().map(|certificate| &certificate[..])))
                .unwrap_or_default(),
            signature:     self
                .signed_quote
                .as_ref()
                .map(|signed_quote| signed_quote.signature.clone())
                .unwrap_or_default(),
            signatureBody: self
                .signed_quote
                .as_ref()
                .map(|signed_quote| String::from_utf8_lossy(&signed_quote.body).to_string())
                .unwrap_or_default(),
        })
    }

    pub fn start_sgxsd_server(&mut self) -> Result<SgxsdServerHandle, EnclaveError> {
        if let Some(server_handle) = self.server_handle {
            Ok(server_handle)
        } else {
            let server_handle: SgxsdServerHandle = 0;

            let enclave_messages = sgxsd_server_start(self.enclave_id, server_handle)?;
            self.server_handle = Some(server_handle);
            self.handle_enclave_messages(enclave_messages);

            Ok(server_handle)
        }
    }

    pub fn client_request(
        &mut self,
        backup_id: BackupId,
        request: KeyBackupRequest,
        reply_tx: oneshot::Sender<Result<KeyBackupResponse, KeyBackupError>>,
    ) -> Result<(), EnclaveError>
    {
        let server_handle = self.start_sgxsd_server()?;

        let request_type = match request.r#type {
            KeyBackupRequestType::Backup => KBUPD_REQUEST_TYPE_BACKUP,
            KeyBackupRequestType::Restore => KBUPD_REQUEST_TYPE_RESTORE,
            KeyBackupRequestType::Delete => KBUPD_REQUEST_TYPE_DELETE,
        };

        let args = SgxsdServerCallArgs {
            request_type,
            backup_id: backup_id.into(),
        };

        let mut sgxsd_message_header = SgxsdMessageHeader {
            iv:                 SgxsdAesGcmIv { data: request.iv },
            mac:                SgxsdAesGcmMac { data: request.mac },
            pending_request_id: Default::default(),
        };

        Some(&request.requestId[..])
            .and_then(decode_field(&mut sgxsd_message_header.pending_request_id.data))
            .and_then(decode_field(&mut sgxsd_message_header.pending_request_id.iv.data))
            .and_then(decode_field(&mut sgxsd_message_header.pending_request_id.mac.data));

        let sgxsd_reply_fun = move |result: SgxsdResult<MessageReply>| {
            let reply = result
                .map(|sgxsd_reply: MessageReply| KeyBackupResponse {
                    iv:   sgxsd_reply.iv.data,
                    mac:  sgxsd_reply.mac.data,
                    data: sgxsd_reply.data,
                })
                .map_err(|error: SgxsdError| error.into());
            let _ignore = reply_tx.send(reply);
        };

        let enclave_messages = sgxsd_server_call(
            self.enclave_id,
            args,
            &sgxsd_message_header,
            &request.data,
            sgxsd_reply_fun,
            server_handle,
        )?;
        self.handle_enclave_messages(enclave_messages);
        Ok(())
    }

    pub fn transaction_request(
        &mut self,
        data: untrusted_transaction_request::Data,
        reply_fun: impl FnOnce(untrusted_transaction_reply::Data) + Send + 'static,
    ) -> Result<(), EnclaveError>
    {
        let request_id = self.txn_requests.push(Box::new(reply_fun));
        self.enqueue_message(UntrustedMessage {
            inner: Some(untrusted_message::Inner::UntrustedTransactionRequest(UntrustedTransactionRequest {
                request_id,
                data: Some(data),
            })),
        });
        self.run_to_completion()
    }

    pub fn xfer_request(
        &mut self,
        data: untrusted_xfer_request::Data,
        reply_fun: impl FnOnce(UntrustedXferReply) + Send + 'static,
    ) -> Result<(), EnclaveError>
    {
        let request_id = self.xfer_requests.push(Box::new(reply_fun));
        self.enqueue_message(UntrustedMessage {
            inner: Some(untrusted_message::Inner::UntrustedXferRequest(UntrustedXferRequest {
                request_id,
                data: Some(data),
            })),
        });
        self.run_to_completion()
    }

    pub fn enqueue_message(&mut self, message: UntrustedMessage) {
        self.send_queue.push(message);
    }

    pub fn run_to_completion(&mut self) -> Result<(), EnclaveError> {
        if self.send_queue.is_empty() {
            self.send_queue.push(Default::default());
        }
        loop {
            let messages = std::mem::replace(&mut self.send_queue, Default::default());
            if messages.is_empty() {
                return Ok(());
            }

            let enclave_messages = ecalls::kbupd_send(self.enclave_id, messages)?;
            self.handle_enclave_messages(enclave_messages);
        }
    }

    pub fn handle_enclave_messages(&mut self, enclave_messages: impl IntoIterator<Item = EnclaveMessage>) {
        let enclave_message_inners = enclave_messages.into_iter().filter_map(|enclave_message| enclave_message.inner);
        for enclave_message_inner in enclave_message_inners {
            self.handle_enclave_message(enclave_message_inner);
        }
    }

    pub fn handle_enclave_message(&mut self, enclave_message: enclave_message::Inner) {
        match enclave_message {
            enclave_message::Inner::StartFrontendReply(reply) => {
                match NodeId::try_from(&reply.node_id[..]) {
                    Ok(node_id) => {
                        info!("started frontend {}", &node_id);
                        self.node_id = Some(node_id);
                    }
                    Err(_) => {
                        error!("invalid frontend node id: {}", util::ToHex(&reply.node_id));
                    }
                };
            }
            enclave_message::Inner::StartReplicaReply(reply) => match NodeId::try_from(&reply.node_id[..]) {
                Ok(node_id) => {
                    info!("started replica {}", &node_id);
                    self.node_id = Some(node_id);
                }
                Err(_) => {
                    error!("invalid replica node id: {}", util::ToHex(&reply.node_id));
                }
            },
            enclave_message::Inner::StartReplicaGroupReply(reply) => {
                if let Some(service_id) = &reply.service_id {
                    info!("started service {}", util::ToHex(&service_id.id));
                }
                if let Some(group_id) = &reply.group_id {
                    info!("started partition {}", util::ToHex(group_id));
                }
            }
            enclave_message::Inner::SendMessageRequest(request) => {
                let _ignore = self
                    .peer_manager_tx
                    .cast(|peer_manager: &mut PeerManager| peer_manager.send_message(request));
            }
            enclave_message::Inner::GetQeInfoRequest(request) => self.handle_get_qe_info_request(request),
            enclave_message::Inner::GetQuoteRequest(request) => self.handle_get_quote_request(request),
            enclave_message::Inner::GetAttestationRequest(request) => self.handle_get_attestation_request(request),
            enclave_message::Inner::UntrustedTransactionReply(reply) => self.handle_untrusted_transaction_reply(reply),
            enclave_message::Inner::UntrustedXferReply(reply) => self.handle_untrusted_xfer_reply(reply),
            enclave_message::Inner::GetEnclaveStatusReply(reply) => self.handle_get_enclave_status_reply(reply),
            enclave_message::Inner::EnclaveLogSignal(enclave_log) => {
                let level = match EnclaveLogLevel::from_i32(enclave_log.level) {
                    Some(EnclaveLogLevel::Error) => log::Level::Error,
                    Some(EnclaveLogLevel::Warn) => log::Level::Warn,
                    Some(EnclaveLogLevel::Info) => log::Level::Info,
                    Some(EnclaveLogLevel::Debug) => log::Level::Debug,
                    None => log::Level::Error,
                };
                log::logger().log(
                    &log::RecordBuilder::new()
                        .args(format_args!("{}", String::from_utf8_lossy(&enclave_log.message)))
                        .level(level)
                        .target("kbupd_enclave")
                        .module_path(std::str::from_utf8(&enclave_log.module).ok())
                        .file(std::str::from_utf8(&enclave_log.file).ok())
                        .line(Some(enclave_log.line))
                        .build(),
                )
            }
            enclave_message::Inner::EnclaveTransactionSignal(enclave_txn) => self.handle_enclave_transaction_signal(enclave_txn),
        }
    }

    fn handle_get_qe_info_request(&mut self, _request: GetQeInfoRequest) {
        match get_qe_target_info() {
            Ok(qe_target_info) => {
                self.send_queue.push(UntrustedMessage {
                    inner: Some(untrusted_message::Inner::GetQeInfoReply(GetQeInfoReply {
                        mrenclave:   qe_target_info.mr_enclave.m.to_vec(),
                        flags:       qe_target_info.attributes.flags,
                        xfrm:        qe_target_info.attributes.xfrm,
                        misc_select: qe_target_info.misc_select,
                        config_svn:  u32::from(qe_target_info.config_svn),
                        config_id:   qe_target_info.config_id.to_vec(),
                    })),
                });
            }
            Err(err) => {
                warn!("sgx get_qe_target_info error: {:?}", err);
            }
        }
    }

    fn handle_get_quote_request(&mut self, request: GetQuoteRequest) {
        let sgx_report = match SgxReport::new(&request.sgx_report) {
            Ok(sgx_report) => sgx_report,
            Err(()) => {
                error!("sgx get_quote incorrect report length: {}", request.sgx_report.len());
                return;
            }
        };
        match get_quote(sgx_report, &self.sgx_spid, &self.sgx_sig_rl) {
            Ok(sgx_quote) => {
                self.send_queue.push(UntrustedMessage {
                    inner: Some(untrusted_message::Inner::GetQuoteReply(GetQuoteReply {
                        request_id: request.request_id,
                        sgx_quote,
                    })),
                });
            }
            Err(err) => {
                warn!("sgx get_quote error: {:?}", err);
            }
        }
    }

    fn handle_get_attestation_request(&mut self, request: GetAttestationRequest) {
        info!("fetching attestation for {}", util::ToHex(&request.request_id));

        let enclave_name = self.enclave_name.clone();
        let _ignore = self
            .attestation_tx
            .cast(move |attestation_manager: &mut AttestationManager| attestation_manager.get_attestation(enclave_name, request));
    }

    fn handle_untrusted_transaction_reply(&mut self, reply: UntrustedTransactionReply) {
        if let Some(reply_fun) = self.txn_requests.remove(reply.request_id) {
            if let Some(data) = reply.data {
                reply_fun(data);
            }
        }
    }

    fn handle_untrusted_xfer_reply(&mut self, reply: UntrustedXferReply) {
        if let Some(reply_fun) = self.xfer_requests.remove(reply.request_id) {
            reply_fun(reply);
        }
    }

    fn handle_get_enclave_status_reply(&mut self, reply: GetEnclaveStatusReply) {
        match &reply.inner {
            Some(get_enclave_status_reply::Inner::ReplicaStatus(status)) => {
                if let Some(memory_status) = &status.memory_status {
                    MEMORY_USED_GAUGE.update(memory_status.used_bytes);
                    MEMORY_CHUNKS_GAUGE.update(memory_status.free_chunks);
                }
                if let Some(partition_status) = &status.partition {
                    if let Ok(duration_since_epoch) = SystemTime::now().duration_since(UNIX_EPOCH) {
                        REPLICA_ATTESTATION_AGE_GAUGE.update(duration_since_epoch.as_secs() - partition_status.min_attestation.unix_timestamp_seconds);
                    }

                    REPLICA_MIN_ATTESTATION_GAUGE.update(partition_status.min_attestation.unix_timestamp_seconds);
                    REPLICA_TERM_GAUGE.update(partition_status.current_term);
                    REPLICA_LOG_PREV_GAUGE.update(partition_status.prev_log_index);
                    REPLICA_LOG_APPLIED_METER.set(partition_status.last_applied_index);
                    REPLICA_LOG_COMMITTED_METER.set(partition_status.commit_index);
                    REPLICA_LOG_APPENDED_METER.set(partition_status.last_log_index);
                    REPLICA_BACKUPS_COUNT_GAUGE.update(partition_status.backup_count);
                }

                let partition_config = status
                    .partition
                    .as_ref()
                    .map(|partition: &EnclaveReplicaPartitionStatus| PartitionConfig {
                        group_id: partition.group_id.clone(),
                        range:    partition.range.clone(),
                        node_ids: partition
                            .peers
                            .iter()
                            .map(|peer: &EnclavePeerStatus| peer.node_id.clone())
                            .chain(self.node_id().map(Vec::from))
                            .collect(),
                    });

                let _ignore = self
                    .peer_manager_tx
                    .cast(move |peer_manager: &mut PeerManager| peer_manager.set_partition_config(partition_config));
            }
            Some(get_enclave_status_reply::Inner::FrontendStatus(status)) => {
                if let Some(memory_status) = &status.memory_status {
                    MEMORY_USED_GAUGE.update(memory_status.used_bytes);
                    MEMORY_CHUNKS_GAUGE.update(memory_status.free_chunks);
                }
                let mut inflight_requests: u64 = 0;
                let mut unsent_requests: u64 = 0;
                for partition_status in &status.partitions {
                    for peer in &partition_status.nodes {
                        inflight_requests += peer.inflight_requests;
                        unsent_requests += peer.unsent_requests;
                    }
                }
                FRONTEND_REQUESTS_INFLIGHT_GAUGE.update(inflight_requests);
                FRONTEND_REQUESTS_UNSENT_GAUGE.update(unsent_requests);
            }
            None => (),
        }

        self.status = Some(reply);
    }

    fn handle_enclave_transaction_signal(&mut self, enclave_txn: EnclaveTransactionSignal) {
        use crate::protobufs::kbupd::enclave_transaction_signal::Transaction;

        let mut fetch_status = false;

        if enclave_txn.log_index == 1 {
            fetch_status = true;
        }

        match enclave_txn.transaction {
            Some(Transaction::FrontendRequest(frontend_request)) => {
                if let Some(frontend_request_transaction) = frontend_request.transaction {
                    self.handle_enclave_frontend_request_transaction(frontend_request_transaction);
                }
            }
            Some(Transaction::StartXfer(_)) |
            Some(Transaction::SetSid(_)) |
            Some(Transaction::RemoveChunk(_)) |
            Some(Transaction::ApplyChunk(_)) |
            Some(Transaction::PauseXfer(_)) |
            Some(Transaction::ResumeXfer(_)) |
            Some(Transaction::SetTime(_)) => {
                fetch_status = true;
            }
            Some(Transaction::FinishXfer(_)) => {
                let _ignore = self
                    .peer_manager_tx
                    .cast(|peer_manager: &mut PeerManager| peer_manager.xfer_finished());
                fetch_status = true;
            }
            None => (),
        }

        if fetch_status {
            self.enqueue_message(UntrustedMessage {
                inner: Some(untrusted_message::Inner::GetEnclaveStatusRequest(GetEnclaveStatusRequest {
                    memory_status: false,
                })),
            })
        }
    }

    fn handle_enclave_frontend_request_transaction(&mut self, transaction: enclave_frontend_request_transaction::Transaction) {
        use crate::protobufs::kbupd::enclave_frontend_request_transaction::Transaction;
        match transaction {
            Transaction::Create(_) => {
                REPLICA_BACKUPS_CREATE_METER.mark();
            }
            Transaction::Backup(_) => {
                REPLICA_BACKUPS_BACKUP_METER.mark();
            }
            Transaction::Restore(_) => {
                REPLICA_BACKUPS_RESTORE_METER.mark();
            }
            Transaction::Delete(_) => {
                REPLICA_BACKUPS_DELETE_METER.mark();
            }
            Transaction::XferInProgress(_) => {
                REPLICA_BACKUPS_XFER_IN_PROGRESS_METER.mark();
            }
            Transaction::WrongPartition(_) => {
                REPLICA_BACKUPS_WRONG_PARTITION_METER.mark();
            }
            Transaction::InvalidRequest(_) => {
                REPLICA_BACKUPS_INVALID_REQUEST_METER.mark();
            }
            Transaction::InternalError(_) => {
                REPLICA_BACKUPS_INTERNAL_ERROR_METER.mark();
            }
        }
    }
}

//
// NodeId impls
//

impl AsRef<[u8]> for NodeId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; 32]> for NodeId {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Deref for NodeId {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&'_ [u8]> for NodeId {
    type Error = TryFromSliceError;

    fn try_from(from: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(from.try_into()?))
    }
}

impl From<[u8; 32]> for NodeId {
    fn from(from: [u8; 32]) -> Self {
        Self(from)
    }
}

impl From<NodeId> for Vec<u8> {
    fn from(from: NodeId) -> Self {
        from.to_vec()
    }
}

impl Display for NodeId {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(fmt, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl Debug for NodeId {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(self, fmt)
    }
}

//
// PendingRequestMap impls
//

impl<V> Default for PendingRequestMap<V> {
    fn default() -> Self {
        Self {
            last_request_id: Default::default(),
            requests:        Default::default(),
        }
    }
}

impl<V> PendingRequestMap<V> {
    pub fn push(&mut self, request: V) -> u64 {
        self.last_request_id = self.last_request_id.wrapping_add(1);
        self.requests.insert(self.last_request_id.clone(), request);
        self.last_request_id.clone()
    }

    pub fn remove(&mut self, request_id: u64) -> Option<V> {
        self.requests.remove(&request_id)
    }
}

//
// internal
//

fn decode_field<'a>(field: &'a mut [u8]) -> impl FnOnce(&[u8]) -> Option<&[u8]> + 'a {
    move |encoded: &[u8]| {
        encoded.get(..field.len()).and_then(|data| {
            field.copy_from_slice(data);
            encoded.get(data.len()..)
        })
    }
}
