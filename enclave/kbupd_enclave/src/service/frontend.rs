//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use crate::prelude::*;

use std::cmp::Ordering;
use std::ops::Add;
use std::rc::*;
use std::time::*;

use hashbrown::HashMap;
use prost::Message;
use sgx_ffi::util::SecretValue;
use sgxsd_ffi::ecalls::SgxsdMsgFrom;

use crate::ffi::ecalls::*;
use crate::hasher::DefaultHasher;
use crate::kbupd_send;
use crate::protobufs::kbupd::*;
use crate::protobufs::kbupd_client;
use crate::protobufs::kbupd_enclave::*;
use crate::protobufs::raft::*;
use crate::remote::*;
use crate::remote_group::*;
use crate::service::replica::PartitionKeyRange;
use crate::util::*;

const NODE_TYPE: NodeType = NodeType::Frontend;

//
// data structures
//

pub struct FrontendState {
    config:          EnclaveFrontendConfig,
    replicas:        PeerManager<Replica>,
    partitions:      HashMap<RaftGroupId, Partition, DefaultHasher>,
    key_ranges:      PartitionKeyRanges,
    last_request_id: PendingRequestId,
}

type RemoteReplicaMessageSender = RemoteSender<FrontendToReplicaMessage>;

struct Replica {
    remote:   RemoteState<FrontendToReplicaMessage, ReplicaToFrontendMessage>,
    group_id: RaftGroupId,
}

struct Partition {
    remote_group: RemoteGroupState<RemoteReplicaMessageSender, PendingRequest>,
}

#[derive(Default)]
struct PartitionKeyRanges {
    ranges: Vec<(PartitionKeyRange, RaftGroupId)>,
}

#[derive(Clone, Default, Eq, PartialEq, Ord, PartialOrd)]
struct PendingRequestId {
    id: u64,
}

#[allow(variant_size_differences)]
enum PendingRequestFrom {
    Client(PendingClientRequest),
    Untrusted { untrusted_request_id: u64 },
}

struct PendingRequest {
    id:              PendingRequestId,
    message:         Rc<FrontendToReplicaMessage>,
    min_attestation: Option<AttestationParameters>,
    from:            PendingRequestFrom,
}

pub struct PendingClientRequest {
    from: SgxsdMsgFrom,
}

//
// FrontendState impls
//

impl FrontendState {
    pub fn init(request: StartFrontendRequest) -> Self {
        let mut state = Self {
            config:          request.config,
            replicas:        PeerManager::new(NODE_TYPE),
            partitions:      Default::default(),
            key_ranges:      Default::default(),
            last_request_id: Default::default(),
        };

        for partition_config in request.partitions {
            state.update_partition(partition_config);
        }

        kbupd_send(EnclaveMessage {
            inner: Some(enclave_message::Inner::StartFrontendReply(StartFrontendReply {
                node_id: state.replicas.our_node_id().to_vec(),
            })),
        });

        state
    }

    fn update_partition(&mut self, config: PartitionConfig) {
        let PartitionConfig { group_id, range, node_ids } = config;
        let group_id = RaftGroupId { id: group_id };
        if let Some(range) = range {
            match PartitionKeyRange::try_from_pb(&range) {
                Ok(range) => {
                    self.key_ranges.update(&group_id, range);
                }
                Err(()) => {
                    error!("received partition config for {} with invalid range: {}", &group_id, &range);
                    return;
                }
            }
        } else {
            self.key_ranges.remove(&group_id);
        }
        if !self.partitions.contains_key(&group_id) {
            let mut remotes = Vec::with_capacity(node_ids.len());
            for replica_node_id in node_ids {
                if let Some(replica) = self.start_replica_remote(replica_node_id[..].into(), group_id.clone()) {
                    remotes.push(replica.remote.sender().clone());
                } else {
                    warn!("couldnt connect to evicted replica {}", NodeId::from(replica_node_id));
                }
            }
            let group_name = format!("{}", ToHex(&group_id.id));
            self.partitions.insert(group_id, Partition {
                remote_group: RemoteGroupState::new(group_name, remotes),
            });
        };
    }

    fn start_replica_remote(&mut self, node_id: NodeId, group_id: RaftGroupId) -> Option<&Replica> {
        match self
            .replicas
            .start_peer(node_id, NodeType::Replica, RemoteAuthorizationType::RemoteOnly)
        {
            Ok(replica_entry) => match replica_entry.connect(|remote| Replica { remote, group_id }) {
                Ok(replica) => Some(replica),
                Err((replica_entry, mapper)) => {
                    warn!(
                        "inserting disconnected replica entry for {} due to connect error",
                        replica_entry.remote().id()
                    );
                    Some(replica_entry.insert(mapper))
                }
            },
            Err(Some(replica)) => Some(replica),
            Err(None) => None,
        }
    }

    //
    // untrusted messages
    //

    pub fn untrusted_message(&mut self, untrusted_message: UntrustedMessage) {
        match untrusted_message.inner {
            Some(untrusted_message::Inner::StartFrontendRequest(_)) | Some(untrusted_message::Inner::StartReplicaRequest(_)) => (),

            Some(untrusted_message::Inner::StartReplicaGroupRequest(_)) => (),
            Some(untrusted_message::Inner::UntrustedTransactionRequest(request)) => self.handle_untrusted_transaction_request(request),
            Some(untrusted_message::Inner::UntrustedXferRequest(_)) => (),
            Some(untrusted_message::Inner::GetEnclaveStatusRequest(request)) => self.handle_get_enclave_status_request(request),

            Some(untrusted_message::Inner::GetQeInfoReply(reply)) => self.handle_get_qe_info_reply(reply),
            Some(untrusted_message::Inner::GetQuoteReply(reply)) => self.handle_get_quote_reply(reply),
            Some(untrusted_message::Inner::GetAttestationReply(reply)) => self.handle_get_attestation_reply(reply),

            Some(untrusted_message::Inner::NewMessageSignal(signal)) => self.handle_new_message_signal(signal),
            Some(untrusted_message::Inner::TimerTickSignal(signal)) => self.handle_timer_tick_signal(signal),
            Some(untrusted_message::Inner::SetFrontendConfigSignal(signal)) => self.handle_set_frontend_config_signal(signal),
            Some(untrusted_message::Inner::SetReplicaConfigSignal(_)) => (),
            Some(untrusted_message::Inner::ResetPeerSignal(signal)) => self.handle_reset_peer_signal(signal),
            Some(untrusted_message::Inner::SetVerboseLoggingSignal(signal)) => self.handle_set_verbose_logging_signal(signal),

            None => (),
        }
    }

    fn handle_untrusted_transaction_request(&mut self, request: UntrustedTransactionRequest) {
        let from = PendingRequestFrom::Untrusted {
            untrusted_request_id: request.request_id,
        };
        match validate_untrusted_transaction_request(request.data) {
            Ok(transaction_request_data) => {
                self.request_transaction(transaction_request_data, from);
            }
            Err(()) => {
                error!("received invalid untrusted transaction request");
                self.cancel_pending_request(from);
            }
        }
    }

    fn handle_get_enclave_status_request(&mut self, request: GetEnclaveStatusRequest) {
        let memory_status = if request.memory_status { Some(memory_status()) } else { None };
        let mut partitions = Vec::with_capacity(self.partitions.len());
        for (group_id, partition) in &self.partitions {
            partitions.push(EnclaveFrontendPartitionStatus {
                group_id: group_id.id.clone(),
                nodes:    partition.remote_group.status(),
            });
        }
        let mut ranges = Vec::with_capacity(self.key_ranges.ranges.len());
        for (range, group_id) in &self.key_ranges.ranges {
            ranges.push(EnclaveFrontendRangeStatus {
                range:    range.to_pb(),
                group_id: group_id.id.clone(),
            });
        }
        kbupd_send(EnclaveMessage {
            inner: Some(enclave_message::Inner::GetEnclaveStatusReply(GetEnclaveStatusReply {
                inner: Some(get_enclave_status_reply::Inner::FrontendStatus(EnclaveFrontendStatus {
                    memory_status,
                    partitions,
                    ranges,
                })),
            })),
        });
    }

    fn handle_get_qe_info_reply(&mut self, reply: GetQeInfoReply) {
        self.replicas.get_qe_info_reply(reply);
    }

    fn handle_get_quote_reply(&mut self, reply: GetQuoteReply) {
        self.replicas.get_quote_reply(reply);
    }

    fn handle_get_attestation_reply(&mut self, reply: GetAttestationReply) {
        if let Some((Replica { remote, .. }, attestation)) = self.replicas.get_attestation_reply(reply) {
            let peer_node_id = remote.id().clone();
            self.replica_authorized(attestation, peer_node_id);
        }
    }

    fn replica_authorized(&mut self, _attestation: AttestationParameters, replica_node_id: NodeId) {
        if let Some((_replica, partition)) = Self::get_partition_replica_mut(&mut self.replicas, &mut self.partitions, &replica_node_id) {
            partition.remote_group.remote_authorized(&replica_node_id);
        }
    }

    fn handle_new_message_signal(&mut self, signal: NewMessageSignal) {
        match self.replicas.new_message_signal(signal) {
            Ok(Some((from, message))) => {
                let from_node_id = from.remote_mut().id().clone();
                self.replica_message(message, from_node_id);
            }
            Ok(None) => (),
            Err(peer_entry) => warn!(
                "unsolicited connect request from {}: {}",
                peer_entry.node_id(),
                peer_entry.connect_request()
            ),
        }
    }

    fn handle_timer_tick_signal(&mut self, _signal: TimerTickSignal) {
        self.replicas
            .timer_tick(self.config.min_connect_timeout_ticks, self.config.max_connect_timeout_ticks);

        for partition in self.partitions.values_mut() {
            partition
                .remote_group
                .timer_tick(self.config.replica_timeout_ticks, self.config.request_quote_ticks);
        }
    }

    fn handle_set_frontend_config_signal(&mut self, signal: SetFrontendConfigSignal) {
        info!("setting frontend config to {:#}", &signal.config);
        self.config = signal.config;
    }

    fn handle_reset_peer_signal(&mut self, signal: ResetPeerSignal) {
        let node_id: NodeId = signal.peer_node_id.into();
        if let Some((_replica, partition)) = Self::get_partition_replica_mut(&mut self.replicas, &mut self.partitions, &node_id) {
            partition.remote_group.reset_peer(&node_id);
        }
    }

    fn handle_set_verbose_logging_signal(&mut self, signal: SetVerboseLoggingSignal) {
        crate::logging::set_verbose_logging_enabled(signal.verbose_logging);
    }

    //
    // replica messages
    //

    fn replica_message(&mut self, replica_message: ReplicaToFrontendMessage, from_node_id: NodeId) {
        match replica_message.inner {
            Some(replica_to_frontend_message::Inner::TransactionReply(transaction_reply)) => {
                self.handle_transaction_reply(transaction_reply, from_node_id)
            }
            Some(replica_to_frontend_message::Inner::EnclaveGetQuoteReply(reply)) => {
                self.handle_enclave_get_quote_reply(reply, from_node_id)
            }
            None => (),
        }
    }

    fn handle_transaction_reply(&mut self, transaction_reply: TransactionReply, from_node_id: NodeId) {
        if let Some((replica, partition)) = Self::get_partition_replica_mut(&mut self.replicas, &mut self.partitions, &from_node_id) {
            match transaction_reply.data {
                Some(transaction_reply::Data::ClientResponse(client_reply)) => {
                    let maybe_pending_request: Option<PendingRequest> = partition.remote_group.handle_reply(&PendingRequestId {
                        id: transaction_reply.request_id,
                    });
                    if let Some(PendingRequestFrom::Client(pending_client_request)) =
                        maybe_pending_request.map(|pending_request| pending_request.from)
                    {
                        pending_client_request.reply(&client_reply);
                    } else {
                        info!("pending client request {} not found", transaction_reply.request_id);
                    }
                }
                Some(transaction_reply::Data::InvalidRequest(_invalid_request_error)) => {
                    error!(
                        "replica {} reported InvalidRequest {}",
                        &from_node_id, &transaction_reply.request_id
                    );
                    let maybe_pending_request: Option<PendingRequest> = partition.remote_group.handle_reply(&PendingRequestId {
                        id: transaction_reply.request_id,
                    });
                    if let Some(pending_request) = maybe_pending_request {
                        self.cancel_pending_request(pending_request.from);
                    }
                }
                Some(transaction_reply::Data::InternalError(_internal_error)) => {
                    warn!(
                        "replica {} reported InternalError on request {}!",
                        &from_node_id, &transaction_reply.request_id
                    );
                    let maybe_pending_request: Option<PendingRequest> = partition.remote_group.handle_reply(&PendingRequestId {
                        id: transaction_reply.request_id,
                    });
                    if let Some(pending_request) = maybe_pending_request {
                        self.cancel_pending_request(pending_request.from);
                    }
                }
                Some(transaction_reply::Data::CreateBackupReply(create_backup_reply)) => {
                    let maybe_pending_request: Option<PendingRequest> = partition.remote_group.handle_reply(&PendingRequestId {
                        id: transaction_reply.request_id,
                    });
                    if let Some(PendingRequestFrom::Untrusted { untrusted_request_id }) =
                        maybe_pending_request.map(|pending_request| pending_request.from)
                    {
                        kbupd_send(EnclaveMessage {
                            inner: Some(enclave_message::Inner::UntrustedTransactionReply(UntrustedTransactionReply {
                                request_id: untrusted_request_id,
                                data:       Some(untrusted_transaction_reply::Data::CreateBackupReply(create_backup_reply)),
                            })),
                        });
                    } else {
                        info!("pending untrusted transaction request {} not found", transaction_reply.request_id);
                    }
                }
                Some(transaction_reply::Data::DeleteBackupReply(delete_backup_reply)) => {
                    let maybe_pending_request: Option<PendingRequest> = partition.remote_group.handle_reply(&PendingRequestId {
                        id: transaction_reply.request_id,
                    });
                    match maybe_pending_request.map(|pending_request| pending_request.from) {
                        Some(PendingRequestFrom::Client(pending_client_request)) => {
                            pending_client_request.reply(&kbupd_client::Response {
                                backup:  None,
                                restore: None,
                                delete:  Some(kbupd_client::DeleteResponse {}),
                            });
                        }
                        Some(PendingRequestFrom::Untrusted { untrusted_request_id }) => {
                            kbupd_send(EnclaveMessage {
                                inner: Some(enclave_message::Inner::UntrustedTransactionReply(UntrustedTransactionReply {
                                    request_id: untrusted_request_id,
                                    data:       Some(untrusted_transaction_reply::Data::DeleteBackupReply(delete_backup_reply)),
                                })),
                            });
                        }
                        None => {
                            info!("pending client request {} not found", transaction_reply.request_id);
                        }
                    }
                }
                Some(transaction_reply::Data::NotLeader(not_leader_error_data)) => {
                    let new_leader: Option<NodeId> = not_leader_error_data.leader_node_id.map(NodeId::from);
                    partition
                        .remote_group
                        .remote_not_leader(not_leader_error_data.term, new_leader.as_ref(), &from_node_id);
                    verbose!(
                        "replica {} reported NotLeader for partition {} with new leader {} at term {}",
                        replica.remote.id(),
                        &replica.group_id,
                        OptionDisplay(new_leader.as_ref()),
                        &not_leader_error_data.term
                    );
                }
                Some(transaction_reply::Data::WrongPartition(wrong_partition_error_data)) => {
                    let maybe_pending_request: Option<PendingRequest> = partition.remote_group.handle_reply(&PendingRequestId {
                        id: transaction_reply.request_id,
                    });
                    if let Some(range) = &wrong_partition_error_data.range {
                        match PartitionKeyRange::try_from_pb(range) {
                            Ok(range) => {
                                info!("partition {} reported WrongPartition with range {}", &replica.group_id, range);
                                self.key_ranges.update(&replica.group_id, range);
                            }
                            Err(()) => {
                                error!(
                                    "partition {} reported WrongPartition with invalid range {}",
                                    &replica.group_id, range
                                );
                            }
                        }
                    } else {
                        info!("partition {} reported WrongPartition with no range", &replica.group_id);
                        self.key_ranges.remove(&replica.group_id);
                    }
                    if let Some(new_partition) = wrong_partition_error_data.new_partition {
                        info!(
                            "partition {} reported WrongPartition with new partition {} and range {}",
                            &replica.group_id,
                            ToHex(&new_partition.group_id),
                            OptionDisplay(new_partition.range.as_ref())
                        );
                        self.update_partition(new_partition);
                    } else {
                        warn!(
                            "partition {} reported WrongPartition but didn't know the right one!",
                            &replica.group_id
                        );
                    }
                    if let Some(pending_request) = maybe_pending_request {
                        self.send_transaction_request(pending_request);
                    }
                }
                Some(transaction_reply::Data::ServiceIdMismatch(_service_id_mismatch_data)) => {
                    let maybe_pending_request: Option<PendingRequest> = partition.remote_group.handle_reply(&PendingRequestId {
                        id: transaction_reply.request_id,
                    });
                    if let Some(pending_request) = maybe_pending_request {
                        warn!("partition {} reported ServiceIdMismatch");
                        self.cancel_pending_request(pending_request.from);
                    }
                }
                Some(transaction_reply::Data::XferInProgress(_xfer_in_progress_data)) => {
                    let maybe_pending_request: Option<PendingRequest> = partition.remote_group.handle_reply(&PendingRequestId {
                        id: transaction_reply.request_id,
                    });
                    if let Some(pending_request) = maybe_pending_request {
                        info!(
                            "partition {} reported XferInProgress for backup id {}",
                            &replica.group_id,
                            OptionDisplay(pending_request.backup_id())
                        );
                        self.cancel_pending_request(pending_request.from);
                    }
                }
                None => {
                    let maybe_pending_request: Option<PendingRequest> = partition.remote_group.handle_reply(&PendingRequestId {
                        id: transaction_reply.request_id,
                    });
                    if let Some(pending_request) = maybe_pending_request {
                        self.cancel_pending_request(pending_request.from);
                    }
                }
            }
        }
    }

    fn handle_enclave_get_quote_reply(&mut self, reply: EnclaveGetQuoteReply, from_node_id: NodeId) {
        self.replicas.request_attestation(reply.sgx_quote, from_node_id);
    }

    //
    // client requests
    //

    pub fn client_request(&mut self, data: transaction_request::Data, from: SgxsdMsgFrom) {
        self.request_transaction(data, PendingRequestFrom::Client(PendingClientRequest { from }));
    }

    fn request_transaction(&mut self, data: transaction_request::Data, from: PendingRequestFrom) {
        let id = self.last_request_id.clone() + 1;
        self.last_request_id = id.clone();
        let min_attestation = match &data {
            transaction_request::Data::Create(_) | transaction_request::Data::Delete(_) => None,
            transaction_request::Data::Backup(BackupTransactionRequest { valid_from, .. }) |
            transaction_request::Data::Restore(RestoreTransactionRequest { valid_from, .. }) => {
                Some(AttestationParameters::new(Duration::from_secs(*valid_from)))
            }
        };
        let message = Rc::new(FrontendToReplicaMessage {
            inner: Some(frontend_to_replica_message::Inner::TransactionRequest(TransactionRequest {
                request_id: id.id,
                data:       Some(data),
            })),
        });
        let pending_request = PendingRequest {
            id,
            message,
            min_attestation,
            from,
        };
        self.send_transaction_request(pending_request);
    }

    fn send_transaction_request(&mut self, mut pending_request: PendingRequest) {
        let Self { partitions, .. } = self;

        if pending_request.id != self.last_request_id {
            pending_request.id = self.last_request_id.clone() + 1;
            self.last_request_id = pending_request.id.clone();
            match &mut Rc::make_mut(&mut pending_request.message).inner {
                Some(frontend_to_replica_message::Inner::TransactionRequest(txn_request)) => {
                    txn_request.request_id = pending_request.id.id;
                }
                Some(frontend_to_replica_message::Inner::EnclaveGetQuoteRequest(_)) | None => (),
            }
        }

        if let Some(backup_id) = pending_request.backup_id() {
            let maybe_group_id: Option<&RaftGroupId> = self.key_ranges.find(backup_id);
            let maybe_partition: Option<&mut Partition> = maybe_group_id.and_then(|group_id| partitions.get_mut(group_id));
            if let Some(partition) = maybe_partition {
                let trimmed = partition.remote_group.trim_to(
                    self.config.pending_request_count.saturating_sub(1).to_usize(),
                    self.config.pending_request_ttl,
                );
                if trimmed.len() != 0 {
                    info!(
                        "dropping {} old pending requests for partition {}",
                        trimmed.len(),
                        partition.remote_group.name()
                    );
                }

                if partition.remote_group.pending_len() < self.config.pending_request_count.to_usize() {
                    match partition.remote_group.send(pending_request) {
                        Ok(()) => (),
                        Err(RemoteGroupSendError::NotYetValid(pending_request)) => {
                            reject_pending_request_not_yet_valid(pending_request);
                        }
                        Err(RemoteGroupSendError::AlreadySent(pending_request)) => {
                            warn!("dropping already sent request {}", &pending_request.id.id);
                            self.cancel_pending_request(pending_request.from);
                        }
                    }
                } else {
                    self.cancel_pending_request(pending_request.from);
                }

                for trimmed_pending_request in trimmed {
                    self.cancel_pending_request(trimmed_pending_request.from)
                }
            } else {
                warn!("dropping request for missing partition of {}", backup_id);
                self.cancel_pending_request(pending_request.from);
            }
        } else {
            self.cancel_pending_request(pending_request.from);
        }
    }

    fn cancel_pending_request(&mut self, from: PendingRequestFrom) {
        match from {
            PendingRequestFrom::Untrusted { untrusted_request_id } => {
                kbupd_send(EnclaveMessage {
                    inner: Some(enclave_message::Inner::UntrustedTransactionReply(UntrustedTransactionReply {
                        request_id: untrusted_request_id,
                        data:       None,
                    })),
                });
            }
            PendingRequestFrom::Client(pending_client_request) => {
                drop(pending_client_request);
            }
        }
    }

    fn get_partition_replica_mut<'a, 'b>(
        replicas: &'a mut PeerManager<Replica>,
        partitions: &'b mut HashMap<RaftGroupId, Partition, DefaultHasher>,
        node_id: &NodeId,
    ) -> Option<(&'a mut Replica, &'b mut Partition)>
    {
        let replica = replicas.get_peer_mut(node_id)?;
        let partition = partitions.get_mut(&replica.group_id)?;
        Some((replica, partition))
    }

    pub fn decode_request(&self, request_type: u32, backup_id: Vec<u8>, request_data: &[u8]) -> Result<transaction_request::Data, ()> {
        let request = kbupd_client::Request::decode(request_data).map_err(|_| ())?;
        let backup_id = BackupId::try_from_slice(&backup_id)?;
        match request {
            kbupd_client::Request {
                backup: Some(backup_request),
                restore: None,
                delete: None,
            } => match request_type {
                KBUPD_REQUEST_TYPE_ANY | KBUPD_REQUEST_TYPE_BACKUP => self.validate_backup_request(backup_id, backup_request),
                _ => Err(()),
            },
            kbupd_client::Request {
                backup: None,
                restore: Some(restore_request),
                delete: None,
            } => match request_type {
                KBUPD_REQUEST_TYPE_ANY | KBUPD_REQUEST_TYPE_RESTORE => Self::validate_restore_request(backup_id, restore_request),
                _ => Err(()),
            },
            kbupd_client::Request {
                backup: None,
                restore: None,
                delete: Some(delete_request),
            } => match request_type {
                KBUPD_REQUEST_TYPE_ANY | KBUPD_REQUEST_TYPE_DELETE => Self::validate_delete_request(backup_id, delete_request),
                _ => Err(()),
            },
            _ => Err(()),
        }
    }

    fn validate_backup_request(
        &self,
        backup_id: BackupId,
        mut request: kbupd_client::BackupRequest,
    ) -> Result<transaction_request::Data, ()>
    {
        if let kbupd_client::BackupRequest {
            service_id,
            backup_id: Some(request_backup_id),
            nonce: Some(nonce),
            valid_from: Some(valid_from),
            data: Some(data),
            pin: Some(pin),
            tries: Some(tries),
        } = &mut request
        {
            if (Self::validate_request_service_id(service_id) &&
                request_backup_id == &backup_id.id &&
                nonce.len() == 32 &&
                data.len() <= self.config.max_backup_data_length.to_usize() &&
                pin.len() == 32 &&
                *tries != 0 &&
                *tries <= u16::max_value().into())
            {
                Ok(transaction_request::Data::Backup(BackupTransactionRequest {
                    service_id: service_id.take(),
                    backup_id,
                    nonce: std::mem::replace(nonce, Vec::new()),
                    valid_from: *valid_from,
                    data: SecretBytes {
                        data: std::mem::replace(data, Vec::new()),
                    },
                    pin: SecretBytes {
                        data: std::mem::replace(pin, Vec::new()),
                    },
                    tries: *tries,
                }))
            } else {
                Err(())
            }
        } else {
            Err(())
        }
    }

    fn validate_restore_request(backup_id: BackupId, mut request: kbupd_client::RestoreRequest) -> Result<transaction_request::Data, ()> {
        if let kbupd_client::RestoreRequest {
            service_id,
            backup_id: Some(request_backup_id),
            nonce: Some(nonce),
            valid_from: Some(valid_from),
            pin: Some(pin),
        } = &mut request
        {
            if (Self::validate_request_service_id(service_id) && request_backup_id == &backup_id.id && nonce.len() == 32 && pin.len() == 32)
            {
                Ok(transaction_request::Data::Restore(RestoreTransactionRequest {
                    service_id: service_id.take(),
                    backup_id,
                    valid_from: *valid_from,
                    nonce: std::mem::replace(nonce, Vec::new()),
                    pin: SecretBytes {
                        data: std::mem::replace(pin, Vec::new()),
                    },
                }))
            } else {
                Err(())
            }
        } else {
            Err(())
        }
    }

    fn validate_delete_request(backup_id: BackupId, request: kbupd_client::DeleteRequest) -> Result<transaction_request::Data, ()> {
        if let kbupd_client::DeleteRequest {
            service_id,
            backup_id: Some(request_backup_id),
        } = request
        {
            if (Self::validate_request_service_id(&service_id) && request_backup_id == backup_id.id) {
                Ok(transaction_request::Data::Delete(DeleteTransactionRequest {
                    service_id,
                    backup_id,
                }))
            } else {
                Err(())
            }
        } else {
            Err(())
        }
    }

    fn validate_request_service_id(maybe_service_id: &Option<Vec<u8>>) -> bool {
        if let Some(service_id) = maybe_service_id {
            service_id.len() == 32
        } else {
            true
        }
    }
}

fn reject_pending_request_not_yet_valid(pending_request: PendingRequest) {
    match pending_request.from {
        PendingRequestFrom::Client(pending_client_request) => {
            info!(
                "rejecting not yet valid client request {} requiring {}",
                &pending_request.id.id,
                OptionDisplay(pending_request.min_attestation.as_ref())
            );
            match &pending_request.message.as_ref().inner {
                Some(frontend_to_replica_message::Inner::TransactionRequest(TransactionRequest { data, .. })) => match data {
                    Some(transaction_request::Data::Backup(_)) => {
                        pending_client_request.reply(&kbupd_client::Response {
                            backup:  Some(kbupd_client::BackupResponse {
                                status: Some(kbupd_client::backup_response::Status::NotYetValid.into()),
                                nonce:  None,
                            }),
                            restore: None,
                            delete:  None,
                        });
                    }
                    Some(transaction_request::Data::Restore(_)) => {
                        pending_client_request.reply(&kbupd_client::Response {
                            backup:  None,
                            restore: Some(kbupd_client::RestoreResponse {
                                status: Some(kbupd_client::restore_response::Status::NotYetValid.into()),
                                nonce:  None,
                                data:   None,
                                tries:  None,
                            }),
                            delete:  None,
                        });
                    }
                    Some(transaction_request::Data::Create(_)) | Some(transaction_request::Data::Delete(_)) | None => (),
                },
                Some(frontend_to_replica_message::Inner::EnclaveGetQuoteRequest(_)) | None => (),
            }
        }
        PendingRequestFrom::Untrusted { untrusted_request_id } => {
            info!(
                "rejecting not yet valid untrusted request {} requiring {}",
                untrusted_request_id,
                OptionDisplay(pending_request.min_attestation.as_ref())
            );
        }
    }
}

//
// PartitionKeyRanges impls
//

impl PartitionKeyRanges {
    fn range_cmp(one: &PartitionKeyRange, two: &PartitionKeyRange) -> Ordering {
        (one.first(), one.last()).cmp(&(two.first(), two.last()))
    }

    fn entry_cmp(one: &(PartitionKeyRange, RaftGroupId), two: &(PartitionKeyRange, RaftGroupId)) -> Ordering {
        Self::range_cmp(&one.0, &two.0)
    }

    fn key_cmp(range: &PartitionKeyRange, key: &BackupId) -> Ordering {
        match range.first().as_ref().cmp(&key.id) {
            Ordering::Greater => Ordering::Greater,
            Ordering::Less | Ordering::Equal => match range.last().as_ref().cmp(&key.id) {
                Ordering::Less => Ordering::Less,
                Ordering::Greater | Ordering::Equal => Ordering::Equal,
            },
        }
    }

    fn update(&mut self, update_group_id: &RaftGroupId, update_range: PartitionKeyRange) {
        let mut matches = self
            .ranges
            .iter_mut()
            .filter(|(_, group_id)| group_id == update_group_id)
            .peekable();
        if matches.peek().is_none() {
            match self.ranges[..]
                .binary_search_by(|(range, _)| Self::range_cmp(range, &update_range))
                .and_then(|ranges_index| self.ranges.get_mut(ranges_index).ok_or(ranges_index))
            {
                Ok((_, group_id)) => {
                    *group_id = update_group_id.clone();
                }
                Err(ranges_index) => {
                    self.ranges.insert(ranges_index, (update_range, update_group_id.clone()));
                }
            }
        } else {
            for (range, _) in matches {
                *range = update_range;
            }
        }
        self.ranges[..].sort_unstable_by(Self::entry_cmp);
    }

    fn remove(&mut self, remove_group_id: &RaftGroupId) {
        self.ranges.retain(|(_range, group_id)| group_id != remove_group_id);
    }

    fn find<'a>(&'a self, key: &BackupId) -> Option<&'a RaftGroupId> {
        self.ranges[..]
            .binary_search_by(|(range, _)| Self::key_cmp(range, key))
            .ok()
            .and_then(|ranges_index| self.ranges.get(ranges_index))
            .filter(|(range, _group_id)| range.contains_id(key))
            .map(|(_range, group_id)| group_id)
    }
}

//
// PendingRequestId impls
//

impl Add<u64> for PendingRequestId {
    type Output = Self;

    fn add(self, inc: u64) -> Self {
        Self {
            id: self.id.checked_add(inc).unwrap_or_else(|| panic!("overflow")),
        }
    }
}

//
// PendingRequest impls
//

impl PendingRequest {
    fn backup_id(&self) -> Option<&BackupId> {
        if let Some(frontend_to_replica_message::Inner::TransactionRequest(TransactionRequest { data: Some(data), .. })) =
            &self.message.inner
        {
            match data {
                transaction_request::Data::Create(create_request) => Some(&create_request.backup_id),
                transaction_request::Data::Backup(backup_request) => Some(&backup_request.backup_id),
                transaction_request::Data::Restore(restore_request) => Some(&restore_request.backup_id),
                transaction_request::Data::Delete(delete_request) => Some(&delete_request.backup_id),
            }
        } else {
            None
        }
    }
}

impl RemoteGroupPendingRequest for PendingRequest {
    type Message = FrontendToReplicaMessage;
    type RequestId = PendingRequestId;

    fn request_id(&self) -> &Self::RequestId {
        &self.id
    }

    fn message(&self) -> Rc<Self::Message> {
        Rc::clone(&self.message)
    }

    fn min_attestation(&self) -> Option<AttestationParameters> {
        self.min_attestation
    }
}

//
// PendingClientRequest impls
//

impl PendingClientRequest {
    pub fn reply(self, reply: &kbupd_client::Response) {
        let mut data = SecretValue::new(Vec::with_capacity(reply.encoded_len()));
        match reply.encode(data.get_mut()) {
            Ok(()) => (),
            Err(_) => {
                error!("error encoding client reply");
                return;
            }
        }
        match self.from.reply(data.get_mut()) {
            Ok(()) => {
                // no need to erase, as SgxsdFrom::reply encrypts in-place
                data.get_mut().clear();
            }
            Err(sgx_status) => {
                error!("error replying to client request: {}", sgx_status);
            }
        }
    }
}

//
// Replica impls
//

impl Peer for Replica {
    type Message = ReplicaToFrontendMessage;

    fn remote_mut(&mut self) -> &mut dyn Remote {
        &mut self.remote
    }

    fn recv(&mut self, msg_data: &[u8]) -> Result<Self::Message, RemoteRecvError> {
        self.remote.recv(msg_data)
    }

    fn send_quote_reply(&mut self, _reply: EnclaveGetQuoteReply) -> Result<(), ()> {
        Ok(())
    }
}

//
// RemoteSender impls
//

impl RemoteGroupNode for RemoteSender<FrontendToReplicaMessage> {
    fn request_quote(&mut self, request: EnclaveGetQuoteRequest) -> Result<(), ()> {
        self.send(Rc::new(FrontendToReplicaMessage {
            inner: Some(frontend_to_replica_message::Inner::EnclaveGetQuoteRequest(request)),
        }))
    }
}

//
// internal
//

fn validate_untrusted_transaction_request(
    request_data: Option<untrusted_transaction_request::Data>,
) -> Result<transaction_request::Data, ()> {
    match request_data {
        Some(untrusted_transaction_request::Data::CreateBackupRequest(create_backup_request)) => {
            if create_backup_request.backup_id.id.len() == 32 {
                Ok(transaction_request::Data::Create(create_backup_request))
            } else {
                Err(())
            }
        }
        Some(untrusted_transaction_request::Data::DeleteBackupRequest(delete_backup_request)) => {
            if delete_backup_request.backup_id.id.len() == 32 {
                Ok(transaction_request::Data::Delete(DeleteTransactionRequest {
                    service_id: None,
                    backup_id:  delete_backup_request.backup_id,
                }))
            } else {
                Err(())
            }
        }
        None => Err(()),
    }
}
