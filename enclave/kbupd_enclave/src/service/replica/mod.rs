//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

mod partition_data;
mod partition_key_range;
mod replica_group;

use crate::prelude::*;

use std::collections::*;
use std::convert::TryInto;
use std::rc::*;
use std::time::*;

use prost::Message;
use sgx_ffi::util::SecretValue;
use sgxsd_ffi::RdRand;

use crate::ffi::ecalls::kbupd_send;
use crate::lru::*;
use crate::protobufs::kbupd::*;
use crate::protobufs::kbupd_client;
use crate::protobufs::kbupd_enclave::*;
use crate::protobufs::raft::*;
use crate::raft::*;
use crate::remote::*;
use crate::remote_group::*;
use crate::storage::*;
use crate::util;
use crate::util::*;

use self::partition_data::*;
use self::replica_group::*;

pub use self::partition_key_range::{PartitionKey, PartitionKeyRange};

//
// data structures
//

pub struct ReplicaState {
    config:    EnclaveReplicaConfig,
    peers:     PeerManager<PeerState>,
    frontends: Lru<NodeId>,
    partition: Option<Partition>,
}

struct Partition {
    group: ReplicaGroupState,
    data:  PartitionData,

    create_group_request: CreateRaftGroupRequest,
}

type ReplicaRemoteSender = RemoteSender<ReplicaToReplicaMessage>;

enum PeerState {
    Frontend {
        remote:    RemoteState<ReplicaToFrontendMessage, FrontendToReplicaMessage>,
        lru_entry: Weak<LruEntry<NodeId>>,
    },
    Replica {
        remote:     RemoteState<ReplicaToReplicaMessage, ReplicaToReplicaMessage>,
        authorized: bool,
    },
}

enum PeerMessage {
    Frontend(FrontendToReplicaMessage),
    Replica(ReplicaToReplicaMessage),
}

//
// ReplicaState impls
//

impl ReplicaState {
    pub fn init(request: StartReplicaRequest) -> Self {
        let state = Self {
            peers:     PeerManager::new(NodeType::Replica),
            config:    request.config,
            frontends: Lru::new(),
            partition: None,
        };

        kbupd_send(EnclaveMessage {
            inner: Some(enclave_message::Inner::StartReplicaReply(StartReplicaReply {
                node_id: state.node_id().to_vec(),
            })),
        });

        state
    }

    pub fn node_id(&self) -> &NodeId {
        self.peers.our_node_id()
    }

    //
    // untrusted messages
    //

    pub fn untrusted_message(&mut self, untrusted_message: UntrustedMessage) {
        match untrusted_message.inner {
            Some(untrusted_message::Inner::StartFrontendRequest(_)) | Some(untrusted_message::Inner::StartReplicaRequest(_)) => (),

            Some(untrusted_message::Inner::StartReplicaGroupRequest(request)) => self.handle_start_replica_group_request(request),
            Some(untrusted_message::Inner::UntrustedTransactionRequest(request)) => {
                warn!("received untrusted transaction request: {}", request)
            }
            Some(untrusted_message::Inner::UntrustedXferRequest(request)) => self.handle_untrusted_xfer_request(request),
            Some(untrusted_message::Inner::GetEnclaveStatusRequest(request)) => self.handle_get_enclave_status_request(request),

            Some(untrusted_message::Inner::GetQeInfoReply(reply)) => self.handle_get_qe_info_reply(reply),
            Some(untrusted_message::Inner::GetQuoteReply(reply)) => self.handle_get_quote_reply(reply),
            Some(untrusted_message::Inner::GetAttestationReply(reply)) => self.handle_get_attestation_reply(reply),

            Some(untrusted_message::Inner::NewMessageSignal(signal)) => self.handle_new_message_signal(signal),
            Some(untrusted_message::Inner::TimerTickSignal(signal)) => self.handle_timer_tick_signal(signal),
            Some(untrusted_message::Inner::SetFrontendConfigSignal(_)) => (),
            Some(untrusted_message::Inner::SetReplicaConfigSignal(signal)) => self.handle_set_replica_config_signal(signal),
            Some(untrusted_message::Inner::ResetPeerSignal(signal)) => self.handle_reset_peer_signal(signal),
            Some(untrusted_message::Inner::SetVerboseLoggingSignal(signal)) => self.handle_set_verbose_logging_signal(signal),

            None => (),
        }
    }

    fn handle_start_replica_group_request(&mut self, request: StartReplicaGroupRequest) {
        let group_id = generate_group_id();
        let service_id = if request.source_partition.is_some() {
            None
        } else {
            Some(generate_service_id())
        };

        let mut node_ids = request.peer_node_ids;
        if !node_ids.iter().any(|peer| peer[..] == self.node_id()[..]) {
            node_ids.push(self.node_id().to_vec());
        }

        let create_group_request = CreateRaftGroupRequest {
            service_id,
            group_id,
            node_ids,
            config: request.config,
            source_partition: request.source_partition,
        };
        let _ignore = self.create_raft_group(create_group_request);

        if let Some(partition) = &mut self.partition {
            let _raft_msg = partition.group.raft.timeout();
        }

        kbupd_send(EnclaveMessage {
            inner: Some(enclave_message::Inner::StartReplicaGroupReply(StartReplicaGroupReply {
                service_id: self.partition.as_ref().and_then(|partition| partition.data.service_id().cloned()),
                group_id:   self.partition.as_ref().map(|partition| partition.group.id().id.clone()),
            })),
        });
    }

    fn handle_untrusted_xfer_request(&mut self, untrusted_xfer_request: UntrustedXferRequest) {
        let command = match untrusted_xfer_request.data {
            Some(untrusted_xfer_request::Data::XferControlCommand(command)) => command,
            None => {
                warn!("No XferControlCommand");
                return;
            }
        };

        let request_id = untrusted_xfer_request.request_id;

        let maybe_status = match XferControlCommand::from_i32(command) {
            Some(XferControlCommand::Start) => {
                let status = self.start_partitioning().err().unwrap_or(UntrustedXferReplyStatus::Ok);
                Some(status)
            }
            Some(XferControlCommand::Pause) => {
                info!("requesting pause of partitioning process");
                let pause_xfer_txn = TransactionData {
                    inner: Some(transaction_data::Inner::PauseXfer(PauseXferTransaction { request_id })),
                };
                self.request_transaction(pause_xfer_txn);
                None
            }
            Some(XferControlCommand::Resume) => self.resume_partitioning(request_id).err(),
            Some(XferControlCommand::Finish) => {
                info!("requesting finish of partitioning process");
                let finish_xfer_txn = TransactionData {
                    inner: Some(transaction_data::Inner::FinishXfer(FinishXferTransaction {
                        request_id,
                        force: false,
                    })),
                };
                self.request_transaction(finish_xfer_txn);
                None
            }
            Some(XferControlCommand::Cancel) => {
                warn!("requesting cancel of partitioning process");
                let finish_xfer_txn = TransactionData {
                    inner: Some(transaction_data::Inner::FinishXfer(FinishXferTransaction {
                        request_id,
                        force: true,
                    })),
                };
                self.request_transaction(finish_xfer_txn);
                None
            }
            None => {
                warn!("Unknown XferControlCommand {}", command);
                Some(UntrustedXferReplyStatus::Unknown)
            }
        };

        if let Some(status) = maybe_status {
            send_untrusted_xfer_reply(request_id, status);
        }
    }

    fn start_partitioning(&mut self) -> Result<(), UntrustedXferReplyStatus> {
        let partition = match &mut self.partition {
            Some(partition) => partition,
            None => {
                warn!("Tried to start partitioning without a partition!");
                return Err(UntrustedXferReplyStatus::InvalidState);
            }
        };
        let xfer_source = match partition.data.xfer_state_mut() {
            XferState::DestinationPartition(xfer_source) => xfer_source,
            _ => {
                warn!("Tried to start partitioning as a non-destination replica!");
                return Err(UntrustedXferReplyStatus::InvalidState);
            }
        };
        let node_ids: Vec<_> = (partition.group.raft.peers().iter())
            .map(|node_id| node_id.to_vec())
            .chain(std::iter::once(self.peers.our_node_id().to_vec()))
            .collect();

        let chunk_size = self.config.transfer_chunk_size;
        info!("requesting xfer of range {} chunk size {}", xfer_source.desired_range(), chunk_size);

        let request = PendingXferRequest {
            id:              PendingXferRequestId::XferRequest,
            message:         Rc::new(ReplicaToReplicaMessage {
                inner: Some(replica_to_replica_message::Inner::XferRequest(XferRequest {
                    group_id: partition.group.id().clone(),
                    chunk_size,
                    full_range: xfer_source.desired_range().to_pb(),
                    node_ids,
                })),
            }),
            min_attestation: None,
        };
        if let Err(error) = xfer_source.remote_group_mut().send(request) {
            error!("error sending XferRequest: {}", &error);
            return Err(UntrustedXferReplyStatus::InvalidState);
        }
        Ok(())
    }

    fn resume_partitioning(&mut self, request_id: u64) -> Result<(), UntrustedXferReplyStatus> {
        let partition = match &mut self.partition {
            Some(partition) => partition,
            None => {
                warn!("Tried to resume partitioning without a partition!");
                return Err(UntrustedXferReplyStatus::InvalidState);
            }
        };
        let xfer_destination = match partition.data.xfer_state() {
            XferState::SourcePartition(xfer_destination) => xfer_destination,
            _ => {
                warn!("Tried to resume partitioning as a non-source replica!");
                return Err(UntrustedXferReplyStatus::InvalidState);
            }
        };
        let chunk_size = self.config.transfer_chunk_size.min(xfer_destination.chunk_size());
        let chunk_last = partition.data.next_chunk_last(chunk_size, xfer_destination.full_range());
        info!("requesting resume of partitioning process with next chunk {}", &chunk_last);
        let resume_xfer_txn = TransactionData {
            inner: Some(transaction_data::Inner::ResumeXfer(ResumeXferTransaction {
                request_id,
                chunk_last,
            })),
        };
        self.request_transaction(resume_xfer_txn);
        Ok(())
    }

    fn handle_get_enclave_status_request(&mut self, request: GetEnclaveStatusRequest) {
        let partition = if let Some(partition) = &self.partition {
            let mut peers = Vec::new();
            for node_id in partition.group.raft.peers() {
                let attestation = partition.group.get(node_id).and_then(|peer| peer.attestation());
                let replication_status = partition
                    .group
                    .raft
                    .replication_state(node_id)
                    .map(|replication: &ReplicationState| EnclavePeerReplicationStatus {
                        next_index:     replication.next_idx.id,
                        match_index:    replication.match_idx.id,
                        inflight_index: replication.inflight.map(|inflight_log_idx: LogIdx| inflight_log_idx.id),
                        probing:        replication.send_probe,
                    });
                peers.push(EnclavePeerStatus {
                    node_id: node_id.to_vec(),
                    attestation,
                    replication_status,
                    is_leader: partition.group.raft.leader().0 == Some(node_id),
                    unsent_requests: Default::default(),
                    inflight_requests: Default::default(),
                });
            }
            Some(EnclaveReplicaPartitionStatus {
                group_id: partition.group.id().id.clone(),
                service_id: partition.data.service_id().map(|service_id| service_id.id.clone()),
                range: partition.data.range().map(PartitionKeyRange::to_pb),
                peers,
                min_attestation: partition.group.attestation(),
                is_leader: partition.group.raft.is_leader(),
                current_term: partition.group.raft.leader().1.id,
                prev_log_index: partition.group.raft.log().prev_idx().id,
                last_applied_index: partition.group.raft.last_applied().id,
                commit_index: partition.group.raft.commit_idx().id,
                last_log_index: partition.group.raft.log().last_idx().id,
                last_log_term: partition.group.raft.log().last_term().id,
                log_data_length: partition.group.raft.log().data_len().to_u64(),
                backup_count: partition.data.storage_len().to_u64(),
                xfer_status: partition.data.xfer_status(),
            })
        } else {
            None
        };
        let memory_status = if request.memory_status { Some(memory_status()) } else { None };
        kbupd_send(EnclaveMessage {
            inner: Some(enclave_message::Inner::GetEnclaveStatusReply(GetEnclaveStatusReply {
                inner: Some(get_enclave_status_reply::Inner::ReplicaStatus(EnclaveReplicaStatus {
                    memory_status,
                    partition,
                })),
            })),
        });
    }

    fn handle_get_qe_info_reply(&mut self, reply: GetQeInfoReply) {
        self.peers.get_qe_info_reply(reply);
    }

    fn handle_get_quote_reply(&mut self, reply: GetQuoteReply) {
        self.peers.get_quote_reply(reply);
    }

    fn handle_get_attestation_reply(&mut self, reply: GetAttestationReply) {
        match self.peers.get_attestation_reply(reply) {
            Some((peer @ PeerState::Replica { .. }, attestation)) => {
                let peer_node_id = peer.remote_mut().id().clone();
                let _ignore = peer.authorize();
                self.replica_authorized(attestation, peer_node_id);
            }
            Some((PeerState::Frontend { .. }, _attestation)) => {
                // we don't actually care about frontend authorization being refreshed
            }
            None => (),
        }
    }

    fn replica_authorized(&mut self, attestation: AttestationParameters, node_id: NodeId) {
        info!("authorized peer {} with {}", &node_id, &attestation);
        if let Some(partition) = &mut self.partition {
            if let Some(remote_group) = partition.data.xfer_state_mut().remote_group_mut() {
                remote_group.remote_authorized(&node_id);
            }
            if let Some(replica) = partition.group.get(&node_id) {
                if partition.group.raft.peers().contains(&node_id) {
                    let create_raft_group_req = Rc::new(ReplicaToReplicaMessage {
                        inner: Some(replica_to_replica_message::Inner::CreateRaftGroupRequest(
                            partition.create_group_request.clone(),
                        )),
                    });
                    match replica.sender.send(create_raft_group_req) {
                        Ok(()) => (),
                        Err(()) => {
                            error!("error sending raft group to {}", &node_id);
                        }
                    }

                    if let Some(raft_message) = partition.group.raft.reset_peer(node_id) {
                        partition.group.send_raft_message(raft_message);
                    }

                    self.raft_step();
                }
            }
        }
    }

    fn handle_timer_tick_signal(&mut self, signal: TimerTickSignal) {
        let now = Duration::from_secs(signal.now_secs);

        self.peers
            .timer_tick(self.config.min_connect_timeout_ticks, self.config.max_connect_timeout_ticks);

        let remote_group_timeout_ticks = self.config.election_timeout_ticks.saturating_mul(2);

        if let Some(partition) = &mut self.partition {
            if let Some(remote_group) = partition.data.xfer_state_mut().remote_group_mut() {
                remote_group.timer_tick(remote_group_timeout_ticks, self.config.request_quote_ticks);
            }

            if let Some(txn_data) = partition
                .group
                .timer_tick(self.config.attestation_expiry_ticks, self.config.request_quote_ticks, now)
            {
                let mut encoded_txn_data = Vec::with_capacity(txn_data.encoded_len());
                if let Ok(()) = txn_data.encode(&mut encoded_txn_data) {
                    let _ignore = partition.group.raft.client_request(encoded_txn_data);
                } else {
                    error!("error encoding timer tick transaction");
                }
            }

            if let Some(raft_message) = partition.group.raft.timer_tick() {
                partition.group.send_raft_message(raft_message);
            }
            self.raft_step();
        }
    }

    fn handle_new_message_signal(&mut self, new_message_signal: NewMessageSignal) {
        match self.peers.new_message_signal(new_message_signal) {
            Ok(Some((from, PeerMessage::Frontend(message)))) => {
                let from_node_id = from.remote_mut().id().clone();
                if let PeerState::Frontend { lru_entry, .. } = from {
                    self.frontends.bump(lru_entry);
                }
                self.frontend_message(message, from_node_id);
            }
            Ok(Some((from, PeerMessage::Replica(message)))) => {
                let from_node_id = from.remote_mut().id().clone();
                if let Some(attestation) = from.authorize() {
                    self.replica_authorized(attestation, from_node_id.clone());
                }
                self.replica_message(message, from_node_id);
            }
            Ok(None) => (),
            Err(peer_entry) => match NodeType::from_i32(peer_entry.connect_request().node_type) {
                Some(NodeType::Frontend) => {
                    info!("accepted frontend connection from {}", &peer_entry.node_id());
                    let frontends = &mut self.frontends;
                    let _ignore = peer_entry.accept(
                        |remote| PeerState::Frontend {
                            lru_entry: frontends.push_back(remote.id().clone()),
                            remote,
                        },
                        RemoteAuthorizationType::SelfOnly,
                    );
                    if self.frontends.len() > self.config.max_frontend_count.to_usize() {
                        self.pop_frontend();
                    }
                }
                Some(NodeType::Replica) => {
                    info!("accepting replica connection from {}", peer_entry.node_id());
                    let _ignore = peer_entry.accept(PeerState::new_replica, RemoteAuthorizationType::Mutual);
                }
                None | Some(NodeType::None) => {
                    warn!(
                        "bad node type in connect request from {}: {}",
                        peer_entry.node_id(),
                        peer_entry.connect_request().node_type
                    );
                }
            },
        }
    }

    fn pop_frontend(&mut self) {
        if let Some(lru_entry) = self.frontends.pop_front() {
            self.peers.remove_peer(lru_entry.get());
            info!("evicted connection state for old frontend {}", lru_entry.get());
        }
    }

    fn handle_set_replica_config_signal(&mut self, signal: SetReplicaConfigSignal) {
        info!("setting replica config to {:#}", &signal.config);
        self.config = signal.config;
        if let Some(partition) = &mut self.partition {
            partition.group.set_config(&self.config);
        }
    }

    fn handle_reset_peer_signal(&mut self, signal: ResetPeerSignal) {
        let node_id: NodeId = signal.peer_node_id.into();
        warn!("resetting peer {}", &node_id);
        if let Some(partition) = &mut self.partition {
            if let Some(remote_group) = partition.data.xfer_state_mut().remote_group_mut() {
                remote_group.reset_peer(&node_id);
            }
            if &node_id == self.peers.our_node_id() {
                if let Some(raft_message) = partition.group.raft.timeout() {
                    partition.group.send_raft_message(raft_message);
                }
                self.raft_step();
            } else if partition.group.raft.peers().contains(&node_id) {
                if let Some(raft_message) = partition.group.raft.reset_peer(node_id) {
                    partition.group.send_raft_message(raft_message);
                }
                self.raft_step();
            }
        }
    }

    fn handle_set_verbose_logging_signal(&mut self, signal: SetVerboseLoggingSignal) {
        crate::logging::set_verbose_logging_enabled(signal.verbose_logging);
    }

    //
    // replica messages
    //

    fn replica_message(&mut self, replica_msg: ReplicaToReplicaMessage, from: NodeId) {
        match replica_msg.inner {
            Some(replica_to_replica_message::Inner::RaftMessage(raft_msg)) => self.handle_raft_message(raft_msg, from),
            Some(replica_to_replica_message::Inner::CreateRaftGroupRequest(request)) => {
                self.handle_create_raft_group_request(request, from)
            }
            Some(replica_to_replica_message::Inner::EnclaveGetQuoteRequest(request)) => {
                self.handle_enclave_get_quote_request(request, from)
            }
            Some(replica_to_replica_message::Inner::EnclaveGetQuoteReply(reply)) => self.handle_enclave_get_quote_reply(reply, from),

            Some(replica_to_replica_message::Inner::XferRequest(request)) => self.handle_xfer_request(request, from),
            Some(replica_to_replica_message::Inner::XferReply(reply)) => self.handle_xfer_reply(reply, from),
            Some(replica_to_replica_message::Inner::XferChunkRequest(request)) => self.handle_xfer_chunk_request(request, from),
            Some(replica_to_replica_message::Inner::XferChunkReply(reply)) => self.handle_xfer_chunk_reply(reply, from),
            Some(replica_to_replica_message::Inner::XferErrorNotLeader(xfer_error)) => self.handle_xfer_error_not_leader(xfer_error, from),
            None => (),
        }
    }

    fn handle_raft_message(&mut self, raft_msg: RaftMessage, from: NodeId) {
        if let Some(partition) = &mut self.partition {
            if partition.group.is_authorized(&from) {
                if let Some(reply) = partition.group.raft.receive(raft_msg, from) {
                    partition.group.send_raft_message(reply);
                }
                self.raft_step();
            } else {
                warn!("dropped raft message from unauthorized replica {}: {}", &from, &raft_msg);
            }
        }
    }

    fn handle_create_raft_group_request(&mut self, request: CreateRaftGroupRequest, from: NodeId) {
        info!("received raft group from {}", &from);
        let _ignore = self.create_raft_group(request);
    }

    fn create_raft_group(&mut self, create_group_request: CreateRaftGroupRequest) -> Result<(), ()> {
        let CreateRaftGroupRequest {
            group_id,
            service_id,
            node_ids,
            config,
            source_partition,
        } = create_group_request.clone();
        let node_ids: BTreeSet<NodeId> = node_ids.into_iter().map(|node_id| node_id.into()).collect();
        if node_ids.contains(self.node_id()) {
            if let Some(partition) = &self.partition {
                if partition.group.id() != &group_id {
                    warn!(
                        "tried to start raft group {} on replica already containing partition {}",
                        &group_id,
                        partition.group.id()
                    );
                }
                Err(())
            } else {
                let range = if source_partition.is_some() {
                    None
                } else {
                    Some(PartitionKeyRange::new_unbounded())
                };

                info!(
                    "creating replica group {} service {} with range {} and nodes {}",
                    &group_id,
                    OptionDisplay(service_id.as_ref()),
                    OptionDisplay(range.as_ref()),
                    ListDisplay(node_ids.iter())
                );

                let raft_log = RaftLogStorage::new(
                    config.raft_log_data_size.to_usize(),
                    config.raft_log_index_size,
                    self.config.raft_log_index_page_cache_size.to_usize(),
                )?;
                let raft = RaftState::new(
                    group_id,
                    self.node_id().clone(),
                    node_ids,
                    raft_log,
                    RdRand,
                    self.config.election_timeout_ticks,
                    self.config.heartbeat_timeout_ticks,
                    self.config.replication_chunk_size.to_usize(),
                );
                let replica_group = self.connect_to_peers(raft)?;

                let xfer_state = if let Some(source_partition) = source_partition {
                    XferState::DestinationPartition(self.connect_to_source(source_partition)?)
                } else {
                    XferState::None
                };

                let partition_data_config = PartitionDataConfig {
                    capacity:               config.storage_size.to_usize(),
                    max_backup_data_length: config.max_backup_data_length,
                };

                self.partition = Some(Partition {
                    group: replica_group,
                    data: PartitionData::new(partition_data_config, service_id, range, xfer_state),
                    create_group_request,
                });

                self.raft_step();
                Ok(())
            }
        } else {
            warn!("tried to start raft group {} not containing us", &group_id);
            Err(())
        }
    }

    fn connect_to_peers(&mut self, raft: RaftState<RaftLogStorage, RdRand, NodeId>) -> Result<ReplicaGroupState, ()> {
        let mut remotes = Vec::new();
        let our_node_id = self.peers.our_node_id().clone();
        for peer_node_id in raft.peers().iter() {
            match self
                .peers
                .start_peer(peer_node_id.clone(), NodeType::Replica, RemoteAuthorizationType::Mutual)
            {
                Ok(peer_entry) => {
                    let sender = peer_entry.remote().sender().clone();
                    if *peer_node_id < our_node_id {
                        info!("connecting to peer replica {}", &peer_node_id);
                        match peer_entry.connect(PeerState::new_replica) {
                            Ok(_peer) => (),
                            Err((peer_entry, _mapper)) => {
                                error!("aborting starting group due to error connecting to {}", peer_entry.remote().id());
                                return Err(());
                            }
                        }
                    } else {
                        peer_entry.insert(PeerState::new_replica);
                    }
                    remotes.push(RemoteReplicaState { sender });
                }
                Err(Some(PeerState::Replica { remote, .. })) => {
                    remotes.push(RemoteReplicaState {
                        sender: remote.sender().clone(),
                    });
                }
                Err(Some(PeerState::Frontend { .. })) | Err(None) => {
                    error!("started group with {} when it's already connected as a frontend!", peer_node_id);
                    return Err(());
                }
            }
        }
        Ok(ReplicaGroupState::new(raft, remotes.into()))
    }

    fn connect_to_source(&mut self, source_partition: SourcePartitionConfig) -> Result<XferSource, ()> {
        let desired_range = match PartitionKeyRange::try_from_pb(&source_partition.range) {
            Ok(desired_range) => desired_range,
            Err(()) => {
                error!(
                    "started replica group with source partition config containing invalid range: {}",
                    &source_partition
                );
                return Err(());
            }
        };
        let mut remotes: Vec<ReplicaRemoteSender> = Vec::with_capacity(source_partition.node_ids.len());
        for source_node_id_vec in source_partition.node_ids {
            let source_node_id: NodeId = source_node_id_vec[..].into();
            info!("connecting to source replica {}", &source_node_id);

            let sender = match self
                .peers
                .start_peer(source_node_id.clone(), NodeType::Replica, RemoteAuthorizationType::Mutual)
            {
                Ok(peer_entry) => {
                    let sender = peer_entry.remote().sender().clone();
                    match peer_entry.connect(PeerState::new_replica) {
                        Ok(_peer) => (),
                        Err((peer_entry, _)) => {
                            error!("error initiating connection to source replica {}", peer_entry.remote().id());
                            return Err(());
                        }
                    }
                    sender
                }
                Err(Some(PeerState::Replica { remote, .. })) => remote.sender().clone(),
                Err(Some(PeerState::Frontend { .. })) | Err(None) => {
                    error!(
                        "source replica {} was already connected as a frontend!",
                        NodeId::from(source_node_id_vec)
                    );
                    return Err(());
                }
            };
            if !remotes.iter().any(|remote| remote.id() == sender.id()) {
                remotes.push(sender);
            }
        }
        let remote_group = RemoteGroupState::new("source partition".to_string(), remotes);

        info!("started destination partition for range {} with {}", &desired_range, &remote_group);

        Ok(XferSource::new(remote_group, desired_range))
    }

    fn handle_enclave_get_quote_request(&mut self, _request: EnclaveGetQuoteRequest, from: NodeId) {
        self.peers.request_quote(from);
    }

    fn handle_enclave_get_quote_reply(&mut self, reply: EnclaveGetQuoteReply, from: NodeId) {
        self.peers.request_attestation(reply.sgx_quote, from);
    }

    fn handle_xfer_request(&mut self, xfer_request: XferRequest, from: NodeId) {
        match &mut self.partition {
            Some(_) => (),
            None => {
                warn!("received XferRequest from {} without having a partition: {}", &from, &xfer_request);
                return;
            }
        }
        match PartitionKeyRange::try_from_pb(&xfer_request.full_range) {
            Ok(_) => (),
            Err(()) => {
                warn!("received XferRequest from {} with invalid range: {}", &from, &xfer_request);
                return;
            }
        }

        let start_xfer_txn = TransactionData {
            inner: Some(transaction_data::Inner::StartXfer(StartXferTransaction {
                from_node_id: from.to_vec(),
                xfer_request,
            })),
        };
        self.request_transaction(start_xfer_txn);
    }

    fn handle_xfer_reply(&mut self, xfer_reply: XferReply, from: NodeId) {
        let xfer_source = match self.partition.as_mut().map(|partition| partition.data.xfer_state_mut()) {
            Some(XferState::DestinationPartition(xfer_source)) => xfer_source,
            _ => {
                warn!("received unexpected XferReply from {}", &from);
                self.send_xfer_error_not_leader(from);
                return;
            }
        };
        if xfer_source.remote_group().contains_authorized_node(&from) {
            xfer_source.received_reply(&PendingXferRequestId::XferRequest);
            let txn = TransactionData {
                inner: Some(transaction_data::Inner::SetSid(SetSidTransaction {
                    from_node_id: from.to_vec(),
                    service_id:   xfer_reply.service,
                })),
            };
            self.request_transaction(txn);
        } else {
            warn!("received XferReply from unknown source node {}", &from);
            self.send_xfer_error_not_leader(from);
        }
    }

    fn handle_xfer_chunk_request(&mut self, xfer_chunk_request: XferChunkRequest, from: NodeId) {
        let xfer_source = match self.partition.as_mut().map(|partition| partition.data.xfer_state_mut()) {
            Some(XferState::DestinationPartition(xfer_source)) => xfer_source,
            _ => {
                warn!("received unexpected XferChunkRequest from {}", &from);
                self.send_xfer_error_not_leader(from);
                return;
            }
        };
        if xfer_source.remote_group().contains_authorized_node(&from) {
            let new_last = xfer_chunk_request.chunk_range.last.clone();
            let txn = TransactionData {
                inner: Some(transaction_data::Inner::ApplyChunk(ApplyChunkTransaction {
                    from_node_id: from.to_vec(),
                    xfer_chunk_request,
                    xfer_chunk_reply: XferChunkReply {
                        new_last,
                        chunk_size: self.config.transfer_chunk_size,
                    },
                })),
            };
            self.request_transaction(txn);
        } else {
            warn!("received XferChunkRequest from unknown source node {}", &from);
            self.send_xfer_error_not_leader(from);
        }
    }

    fn handle_xfer_chunk_reply(&mut self, xfer_chunk_reply: XferChunkReply, from: NodeId) {
        if let Some(partition) = &mut self.partition {
            if let XferState::SourcePartition(xfer_destination) = partition.data.xfer_state_mut() {
                xfer_destination.received_reply(&PendingXferRequestId::XferReply);
                xfer_destination.received_reply(&PendingXferRequestId::XferChunkRequest {
                    new_last: xfer_chunk_reply.new_last.clone(),
                });
            }
        }

        let partition = match &self.partition {
            Some(partition) => partition,
            None => {
                warn!("received unexpected XferChunkReply from {}", &from);
                self.send_xfer_error_not_leader(from);
                return;
            }
        };
        let xfer_destination = match partition.data.xfer_state() {
            XferState::SourcePartition(xfer_destination) => xfer_destination,
            _ => {
                warn!("received unexpected XferChunkReply from {}", &from);
                self.send_xfer_error_not_leader(from);
                return;
            }
        };

        if xfer_destination.remote_group().contains_authorized_node(&from) {
            let chunk_size = self.config.transfer_chunk_size.min(xfer_chunk_reply.chunk_size);
            let chunk_last = partition.data.next_chunk_last(chunk_size, xfer_destination.full_range());
            let txn = TransactionData {
                inner: Some(transaction_data::Inner::RemoveChunk(RemoveChunkTransaction {
                    from_node_id: from.to_vec(),
                    xfer_chunk_reply,
                    chunk_last,
                })),
            };
            self.request_transaction(txn);
        } else {
            warn!("received XferChunkReply from unknown source node {}", &from);
            self.send_xfer_error_not_leader(from);
        }
    }

    fn handle_xfer_error_not_leader(&mut self, xfer_error_not_leader: XferErrorNotLeader, from: NodeId) {
        let term: TermId = xfer_error_not_leader.term;
        let leader: Option<NodeId> = xfer_error_not_leader.leader_node_id.map(NodeId::from);
        if let Some(partition) = &mut self.partition {
            if let Some(remote_group) = partition.data.xfer_state_mut().remote_group_mut() {
                remote_group.remote_not_leader(term, leader.as_ref(), &from);
            }
        }
    }

    //
    // frontend messages
    //

    fn frontend_message(&mut self, msg: FrontendToReplicaMessage, from: NodeId) {
        match msg.inner {
            Some(frontend_to_replica_message::Inner::TransactionRequest(req)) => self.handle_transaction_request(req, from),
            Some(frontend_to_replica_message::Inner::EnclaveGetQuoteRequest(request)) => {
                self.handle_enclave_get_quote_request(request, from)
            }
            None => (),
        }
    }

    fn handle_transaction_request(&mut self, request: TransactionRequest, from_node_id: NodeId) {
        if let Some(request_data) = request.data {
            match self.accept_transaction_request(request_data) {
                Ok(transaction) => {
                    let frontend_request_txn = TransactionData {
                        inner: Some(transaction_data::Inner::FrontendRequest(FrontendRequestTransaction {
                            from_node_id: from_node_id.to_vec(),
                            request_id:   request.request_id,
                            transaction:  Some(transaction),
                        })),
                    };
                    self.request_transaction(frontend_request_txn);
                }
                Err(early_response) => {
                    if let Some(from) = self.peers.get_frontend(&from_node_id) {
                        send_transaction_reply(from, request.request_id, early_response);
                    }
                }
            }
        } else {
            if let Some(from) = self.peers.get_frontend(&from_node_id) {
                let _ignore = from.send(Rc::new(ReplicaToFrontendMessage {
                    inner: Some(replica_to_frontend_message::Inner::TransactionReply(TransactionReply {
                        request_id: request.request_id,
                        data:       None,
                    })),
                }));
            }
        }
    }

    fn accept_transaction_request(
        &mut self,
        request_data: transaction_request::Data,
    ) -> Result<frontend_request_transaction::Transaction, transaction_reply::Data>
    {
        let partition = match &mut self.partition {
            Some(partition) => partition,
            None => {
                return Err(transaction_reply::Data::NotLeader(TransactionErrorNotLeader {
                    leader_node_id: None,
                    term:           Default::default(),
                }));
            }
        };

        if !partition.group.raft.is_leader() {
            let (leader, &term) = partition.group.raft.leader();
            return Err(transaction_reply::Data::NotLeader(TransactionErrorNotLeader {
                leader_node_id: leader.map(|leader| leader.to_vec()),
                term,
            }));
        }

        match request_data {
            transaction_request::Data::Create(create_backup_request) => {
                if let Ok(backup_id) = PartitionKey::try_from_pb(&create_backup_request.backup_id) {
                    if let Some((nonce, tries)) = partition.data.get_entry_nonce(&backup_id) {
                        Err(transaction_reply::Data::CreateBackupReply(CreateBackupReply {
                            token: nonce.to_combined().to_vec(),
                            tries: tries.map(u16::from).map(u32::from),
                        }))
                    } else {
                        Ok(frontend_request_transaction::Transaction::Create(CreateBackupTransaction {
                            backup_id:          create_backup_request.backup_id,
                            new_creation_nonce: generate_nonce_16(),
                            new_nonce:          generate_nonce_16(),
                        }))
                    }
                } else {
                    Err(transaction_reply::Data::InvalidRequest(TransactionErrorInvalidRequest {}))
                }
            }
            transaction_request::Data::Backup(backup_request) => {
                let min_attestation = AttestationParameters::new(Duration::from_secs(backup_request.valid_from));
                let our_service_id = partition.data.service_id_bytes();
                let request_service_id = backup_request.service_id.as_ref().map(|service_id: &Vec<u8>| &service_id[..]);
                let request_nonce = Self::decode_transaction_request_nonce(backup_request.nonce)?;

                if (our_service_id.is_none() || (request_service_id.is_some() && request_service_id != our_service_id)) {
                    Err(transaction_reply::Data::ServiceIdMismatch(TransactionErrorServiceIdMismatch {}))
                } else if min_attestation > partition.group.attestation() {
                    Err(transaction_reply::Data::ClientResponse(kbupd_client::Response {
                        backup:  Some(kbupd_client::BackupResponse {
                            status: Some(kbupd_client::backup_response::Status::NotYetValid.into()),
                            nonce:  None,
                        }),
                        restore: None,
                        delete:  None,
                    }))
                } else {
                    Ok(frontend_request_transaction::Transaction::Backup(BackupTransaction {
                        backup_id:          backup_request.backup_id,
                        old_nonce:          request_nonce.current_nonce.to_vec(),
                        new_creation_nonce: generate_nonce_16(),
                        new_nonce:          generate_nonce_16(),
                        data:               backup_request.data,
                        pin:                backup_request.pin,
                        tries:              backup_request.tries,
                    }))
                }
            }
            transaction_request::Data::Restore(restore_request) => {
                let min_attestation = AttestationParameters::new(Duration::from_secs(restore_request.valid_from));
                let our_service_id = partition.data.service_id_bytes();
                let request_service_id = restore_request.service_id.as_ref().map(|service_id: &Vec<u8>| &service_id[..]);
                let request_nonce = Self::decode_transaction_request_nonce(restore_request.nonce)?;

                if (our_service_id.is_none() || (request_service_id.is_some() && request_service_id != our_service_id)) {
                    Err(transaction_reply::Data::ServiceIdMismatch(TransactionErrorServiceIdMismatch {}))
                } else if min_attestation > partition.group.attestation() {
                    Err(transaction_reply::Data::ClientResponse(kbupd_client::Response {
                        backup:  None,
                        restore: Some(kbupd_client::RestoreResponse {
                            status: Some(kbupd_client::restore_response::Status::NotYetValid.into()),
                            nonce:  None,
                            data:   None,
                            tries:  None,
                        }),
                        delete:  None,
                    }))
                } else {
                    Ok(frontend_request_transaction::Transaction::Restore(RestoreTransaction {
                        backup_id:      restore_request.backup_id,
                        creation_nonce: request_nonce.creation_nonce.to_vec(),
                        old_nonce:      request_nonce.current_nonce.to_vec(),
                        new_nonce:      generate_nonce_16(),
                        pin:            restore_request.pin,
                    }))
                }
            }
            transaction_request::Data::Delete(delete_backup_request) => {
                let our_service_id = partition.data.service_id_bytes();
                let request_service_id = delete_backup_request
                    .service_id
                    .as_ref()
                    .map(|service_id: &Vec<u8>| &service_id[..]);
                if (our_service_id.is_none() || (request_service_id.is_some() && request_service_id != our_service_id)) {
                    Err(transaction_reply::Data::ServiceIdMismatch(TransactionErrorServiceIdMismatch {}))
                } else {
                    Ok(frontend_request_transaction::Transaction::Delete(DeleteBackupTransaction {
                        backup_id: delete_backup_request.backup_id,
                    }))
                }
            }
        }
    }

    fn decode_transaction_request_nonce(combined_nonce: Vec<u8>) -> Result<RequestNonce, transaction_reply::Data> {
        let combined_nonce: &[u8; 32] =
            (&combined_nonce[..].try_into()).map_err(|_| transaction_reply::Data::InvalidRequest(TransactionErrorInvalidRequest {}))?;
        Ok(RequestNonce::from_combined(*combined_nonce))
    }

    //
    // raft
    //

    fn raft_step(&mut self) {
        // apply committed transactions
        if let Some(partition) = &mut self.partition {
            let is_leader = partition.group.raft.is_leader();
            while let Some(encoded_transaction) = partition.group.raft.take_committed_transaction() {
                let log_index = partition.group.raft.last_applied().id;

                let txn = match TransactionData::decode(&encoded_transaction.data[..]) {
                    Ok(transaction) => transaction,
                    Err(_) => panic!("error decoding committed raft transaction"),
                };
                let txn_info = if let Some(txn_inner) = txn.inner {
                    Some(
                        partition
                            .data
                            .perform_transaction(txn_inner, &mut self.peers, &mut partition.group, is_leader),
                    )
                } else {
                    None
                };
                kbupd_send(EnclaveMessage {
                    inner: Some(enclave_message::Inner::EnclaveTransactionSignal(EnclaveTransactionSignal {
                        log_index,
                        transaction: txn_info,
                    })),
                });
            }
        }

        // cancel transactions
        if let Some(partition) = &mut self.partition {
            let mut frontends_sent_to = BTreeSet::new();
            for encoded_transaction in partition.group.raft.log_mut().take_cancelled() {
                if let Ok(transaction) = TransactionData::decode(&encoded_transaction.get()[..]) {
                    let should_send = match &transaction.inner {
                        Some(transaction_data::Inner::FrontendRequest(FrontendRequestTransaction { from_node_id, .. })) => {
                            frontends_sent_to.insert(from_node_id.clone())
                        }
                        _ => true,
                    };
                    if should_send {
                        self.cancel_transaction(transaction, None);
                    }
                } else {
                    error!("error decoding cancelled transaction!");
                }
            }
        }

        // append entries
        if let Some(partition) = &mut self.partition {
            for peer in partition.group.raft.peers().clone() {
                if partition.group.is_authorized(&peer) {
                    if let Some(append_request) = partition.group.raft.append_entries(peer) {
                        partition.group.send_raft_message(append_request);
                    }
                }
            }
        }

        if let Some(partition) = &mut self.partition {
            if partition.group.raft.is_leader() {
                partition.data.send_pending_xfer_messages();
            }
        }
    }

    fn request_transaction(&mut self, transaction: TransactionData) {
        if let Some(partition) = &mut self.partition {
            let mut encoded_transaction = SecretValue::new(Vec::with_capacity(transaction.encoded_len()));
            let request_transaction_result = if let Ok(()) = transaction.encode(encoded_transaction.get_mut()) {
                partition.group.raft.client_request(encoded_transaction.into_inner())
            } else {
                error!("error encoding transaction!");
                Err(())
            };
            match request_transaction_result {
                Ok(()) => {
                    self.raft_step();
                }
                Err(()) => {
                    let transaction_error = transaction_reply::Data::InternalError(TransactionErrorInternalError {});
                    self.cancel_transaction(transaction, Some(transaction_error))
                }
            }
        } else {
            self.cancel_transaction(transaction, None);
        }
    }

    fn cancel_transaction(&mut self, transaction: TransactionData, transaction_error: Option<transaction_reply::Data>) {
        match transaction.inner {
            Some(transaction_data::Inner::FrontendRequest(client_req_txn)) => {
                let leader: Option<(Option<&NodeId>, &TermId)> = self.partition.as_ref().map(|partition| partition.group.raft.leader());
                let from_node_id: NodeId = client_req_txn.from_node_id.into();
                if let Some(from) = self.peers.get_frontend(&from_node_id) {
                    let transaction_error = match transaction_error {
                        Some(transaction_error) => transaction_error,
                        None => transaction_reply::Data::NotLeader(TransactionErrorNotLeader {
                            leader_node_id: leader.and_then(|leader| leader.0).map(|leader| leader.to_vec()),
                            term:           leader.map(|leader| leader.1).cloned().unwrap_or_default(),
                        }),
                    };
                    send_transaction_reply(from, client_req_txn.request_id, transaction_error);
                }
            }
            Some(transaction_data::Inner::StartXfer(request)) => {
                let from_node_id: NodeId = request.from_node_id.into();
                self.send_xfer_error_not_leader(from_node_id);
            }
            Some(transaction_data::Inner::SetSid(request)) => {
                let from_node_id: NodeId = request.from_node_id.into();
                self.send_xfer_error_not_leader(from_node_id);
            }
            Some(transaction_data::Inner::RemoveChunk(request)) => {
                let from_node_id: NodeId = request.from_node_id.into();
                self.send_xfer_error_not_leader(from_node_id);
            }
            Some(transaction_data::Inner::ApplyChunk(request)) => {
                let from_node_id: NodeId = request.from_node_id.into();
                self.send_xfer_error_not_leader(from_node_id);
            }
            Some(transaction_data::Inner::PauseXfer(request)) => {
                info!("cannot pause partitioning process on non-leader");
                send_untrusted_xfer_reply(request.request_id, UntrustedXferReplyStatus::NotLeader);
            }
            Some(transaction_data::Inner::ResumeXfer(request)) => {
                info!("cannot resume partitioning process on non-leader");
                send_untrusted_xfer_reply(request.request_id, UntrustedXferReplyStatus::NotLeader);
            }
            Some(transaction_data::Inner::FinishXfer(request)) => {
                info!("cannot finish partitioning process on non-leader");
                send_untrusted_xfer_reply(request.request_id, UntrustedXferReplyStatus::NotLeader);
            }
            Some(transaction_data::Inner::SetTime(_request)) => {}
            None => {}
        }
    }

    fn send_xfer_error_not_leader(&self, from_node_id: NodeId) {
        let leader = self.partition.as_ref().map(|partition| partition.group.raft.leader());
        if let Some(PeerState::Replica { remote, .. }) = self.peers.get_peer(&from_node_id) {
            let r2r_msg = Rc::new(ReplicaToReplicaMessage {
                inner: Some(replica_to_replica_message::Inner::XferErrorNotLeader(XferErrorNotLeader {
                    leader_node_id: leader.and_then(|leader| leader.0).map(|leader| leader.to_vec()),
                    term:           leader.map(|leader| leader.1).cloned().unwrap_or_default(),
                })),
            });
            let _ignore = remote.send(r2r_msg);
        }
    }
}

//
// RaftGroupId impls
//

fn generate_group_id() -> RaftGroupId {
    RaftGroupId {
        id: RdRand.rand_bytes(vec![0; 32]),
    }
}

//
// ServiceId impls
//

fn generate_service_id() -> ServiceId {
    ServiceId {
        id: RdRand.rand_bytes(vec![0; 32]),
    }
}

//
// PeerState impls
//

impl PeerState {
    fn new_replica(remote: RemoteState<ReplicaToReplicaMessage, ReplicaToReplicaMessage>) -> Self {
        let authorized = remote.attestation().is_some();
        PeerState::Replica { remote, authorized }
    }

    #[must_use]
    fn authorize(&mut self) -> Option<AttestationParameters> {
        match self {
            PeerState::Frontend { .. } => None,
            PeerState::Replica { remote, authorized } => {
                if !*authorized {
                    let maybe_attestation = remote.attestation();
                    if maybe_attestation.is_some() {
                        *authorized = true;
                    }
                    maybe_attestation
                } else {
                    None
                }
            }
        }
    }
}

impl Peer for PeerState {
    type Message = PeerMessage;

    fn remote_mut(&mut self) -> &mut dyn Remote {
        match self {
            PeerState::Frontend { remote, .. } => remote,
            PeerState::Replica { remote, .. } => remote,
        }
    }

    fn recv(&mut self, msg_data: &[u8]) -> Result<PeerMessage, RemoteRecvError> {
        match self {
            PeerState::Frontend { remote, .. } => remote.recv(msg_data).map(PeerMessage::Frontend),
            PeerState::Replica { remote, .. } => remote.recv(msg_data).map(PeerMessage::Replica),
        }
    }

    fn send_quote_reply(&mut self, reply: EnclaveGetQuoteReply) -> Result<(), ()> {
        match self {
            PeerState::Frontend { remote, .. } => remote.send(Rc::new(ReplicaToFrontendMessage {
                inner: Some(replica_to_frontend_message::Inner::EnclaveGetQuoteReply(reply)),
            })),
            PeerState::Replica { remote, .. } => remote.send(Rc::new(ReplicaToReplicaMessage {
                inner: Some(replica_to_replica_message::Inner::EnclaveGetQuoteReply(reply)),
            })),
        }
    }
}

impl PeerManager<PeerState> {
    fn get_frontend(&mut self, node_id: &NodeId) -> Option<&mut dyn RemoteMessageSender<Message = ReplicaToFrontendMessage>> {
        match self.get_peer_mut(node_id) {
            Some(PeerState::Frontend { remote, .. }) => Some(remote),
            _ => None,
        }
    }
}

//
// RemoteSender impls
//

impl RemoteGroupNode for RemoteSender<ReplicaToReplicaMessage> {
    fn request_quote(&mut self, request: EnclaveGetQuoteRequest) -> Result<(), ()> {
        self.send(Rc::new(ReplicaToReplicaMessage {
            inner: Some(replica_to_replica_message::Inner::EnclaveGetQuoteRequest(request)),
        }))
    }
}

//
// utils
//

fn generate_nonce_16() -> Vec<u8> {
    RdRand.rand_bytes(vec![0; 16])
}

fn send_transaction_reply(
    from: &mut dyn RemoteMessageSender<Message = ReplicaToFrontendMessage>,
    request_id: u64,
    data: transaction_reply::Data,
)
{
    let _ignore = from.send(Rc::new(ReplicaToFrontendMessage {
        inner: Some(replica_to_frontend_message::Inner::TransactionReply(TransactionReply {
            request_id,
            data: Some(data),
        })),
    }));
}

fn send_untrusted_xfer_reply(request_id: u64, status: UntrustedXferReplyStatus) {
    kbupd_send(EnclaveMessage {
        inner: Some(enclave_message::Inner::UntrustedXferReply(UntrustedXferReply {
            request_id,
            status: status.into(),
        })),
    });
}

//
// tests
//

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::ecalls;
    use crate::ffi::mocks;
    use mockers::*;

    fn init(start_replica_req: StartReplicaRequest) -> ReplicaState {
        ReplicaState::init(start_replica_req)
    }

    fn valid_range() -> PartitionKeyRangePb {
        PartitionKeyRangePb {
            first: BackupId { id: vec![0x00; 32] },
            last:  BackupId { id: vec![0xFF; 32] },
        }
    }

    #[test]
    fn init_test() {
        let scenario = Scenario::new();
        let expected_enclave_messages: Vec<Box<dyn MatchArg<_>>> =
            vec![Box::new(arg!(enclave_message::Inner::StartReplicaReply(StartReplicaReply { .. })))];
        mocks::expect_enclave_messages(&scenario, expected_enclave_messages);
        init(StartReplicaRequest {
            config: Default::default(),
        });
        ecalls::kbupd_send_flush();
    }

    #[test]
    fn start_new_group_no_peers() {
        let scenario = Scenario::new();
        let expected_enclave_messages: Vec<Box<dyn MatchArg<_>>> = vec![
            Box::new(arg!(enclave_message::Inner::StartReplicaReply(StartReplicaReply { .. }))),
            Box::new(arg!(
                enclave_message::Inner::StartReplicaGroupReply(StartReplicaGroupReply {
                    service_id: Some(_),
                    group_id: Some(_),
                    ..
                })
            )),
        ];
        mocks::expect_enclave_messages(&scenario, expected_enclave_messages);
        let mut state = init(StartReplicaRequest {
            config: Default::default(),
        });
        state.handle_start_replica_group_request(StartReplicaGroupRequest {
            peer_node_ids:    vec![],
            source_partition: None,
            config:           Default::default(),
        });
        ecalls::kbupd_send_flush();
    }

    #[test]
    fn start_new_group_with_peer() {
        let scenario = Scenario::new();
        let expected_enclave_messages: Vec<Box<dyn MatchArg<_>>> = vec![
            Box::new(arg!(enclave_message::Inner::StartReplicaReply(StartReplicaReply { .. }))),
            Box::new(arg!(
                enclave_message::Inner::StartReplicaGroupReply(StartReplicaGroupReply {
                    service_id: Some(_),
                    group_id: Some(_),
                    ..
                })
            )),
            Box::new(arg!(enclave_message::Inner::GetQeInfoRequest(GetQeInfoRequest { .. }))),
        ];
        mocks::expect_enclave_messages(&scenario, expected_enclave_messages);
        let mut state = init(StartReplicaRequest {
            config: Default::default(),
        });
        state.handle_start_replica_group_request(StartReplicaGroupRequest {
            peer_node_ids:    vec![vec![0; 32]],
            source_partition: None,
            config:           Default::default(),
        });
        state.handle_timer_tick_signal(Default::default());
        ecalls::kbupd_send_flush();
    }

    #[test]
    fn start_new_xfer_group_no_peers() {
        let scenario = Scenario::new();
        let expected_enclave_messages: Vec<Box<dyn MatchArg<_>>> = vec![
            Box::new(arg!(enclave_message::Inner::StartReplicaReply(StartReplicaReply { .. }))),
            Box::new(arg!(
                enclave_message::Inner::StartReplicaGroupReply(StartReplicaGroupReply {
                    service_id: None,
                    group_id: Some(_),
                    ..
                })
            )),
            Box::new(arg!(enclave_message::Inner::GetQeInfoRequest(GetQeInfoRequest { .. }))),
        ];
        mocks::expect_enclave_messages(&scenario, expected_enclave_messages);
        let mut state = init(StartReplicaRequest {
            config: Default::default(),
        });
        state.handle_start_replica_group_request(StartReplicaGroupRequest {
            peer_node_ids:    vec![vec![0; 32]],
            source_partition: Some(SourcePartitionConfig {
                range:    valid_range(),
                node_ids: vec![],
            }),
            config:           Default::default(),
        });
        state.handle_timer_tick_signal(Default::default());
        ecalls::kbupd_send_flush();
    }

    #[test]
    fn start_new_xfer_group_with_peer() {
        let scenario = Scenario::new();
        let expected_enclave_messages: Vec<Box<dyn MatchArg<_>>> = vec![
            Box::new(arg!(enclave_message::Inner::StartReplicaReply(StartReplicaReply { .. }))),
            Box::new(arg!(enclave_message::Inner::GetQeInfoRequest(GetQeInfoRequest { .. }))),
            Box::new(arg!(
                enclave_message::Inner::StartReplicaGroupReply(StartReplicaGroupReply {
                    service_id: None,
                    group_id: Some(_),
                    ..
                })
            )),
        ];
        mocks::expect_enclave_messages(&scenario, expected_enclave_messages);
        let mut state = init(StartReplicaRequest {
            config: Default::default(),
        });
        state.handle_start_replica_group_request(StartReplicaGroupRequest {
            peer_node_ids:    vec![vec![0; 32]],
            source_partition: Some(SourcePartitionConfig {
                range:    valid_range(),
                node_ids: vec![vec![0; 32]],
            }),
            config:           Default::default(),
        });
        state.handle_timer_tick_signal(Default::default());
        ecalls::kbupd_send_flush();
    }
}
