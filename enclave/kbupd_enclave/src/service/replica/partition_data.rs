//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

mod backup_entry;

use crate::prelude::*;

use std::cmp::*;
use std::collections::*;
use std::convert::TryInto;
use std::mem;
use std::num::*;
use std::rc::*;
use std::time::*;

use bytes::*;
use num_traits::ToPrimitive;

use self::backup_entry::BackupEntrySecrets;
use super::*;
use crate::protobufs::kbupd::*;
use crate::protobufs::kbupd_client;
use crate::protobufs::kbupd_enclave::*;
use crate::protobufs::raft::*;
use crate::remote::*;
use crate::remote_group::*;
use crate::util::*;

pub(super) struct PartitionData {
    storage:    BTreeMap<PartitionKey, BackupEntry>,
    config:     PartitionDataConfig,
    service_id: Option<ServiceId>,
    range:      Option<PartitionKeyRange>,
    xfer_state: XferState,
}

pub(super) struct PartitionDataConfig {
    pub capacity:               usize,
    pub max_backup_data_length: u32,
}

#[allow(clippy::large_enum_variant)]
pub(super) enum XferState {
    DestinationPartition(XferSource),
    SourcePartition(XferDestination),
    None,
}

pub(super) struct XferSource {
    remote_group:  RemoteGroupState<ReplicaRemoteSender, PendingXferRequest>,
    desired_range: PartitionKeyRange,

    cur_xfer_chunk_reply: Option<PendingXferRequest>,
}

pub(super) struct XferDestination {
    remote_group_id: RaftGroupId,
    remote_group:    RemoteGroupState<ReplicaRemoteSender, PendingXferRequest>,
    full_range:      PartitionKeyRange,
    chunk_size:      u32,

    paused:   bool,
    inflight: Option<PartitionKeyRange>,

    cur_xfer_reply:         Option<PendingXferRequest>,
    cur_xfer_chunk_request: Option<PendingXferRequest>,
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub(super) enum PendingXferRequestId {
    XferRequest,
    XferReply,
    XferChunkRequest { new_last: BackupId },
    XferChunkReply { new_last: BackupId },
}

#[derive(Clone)]
pub(super) struct PendingXferRequest {
    pub id:              PendingXferRequestId,
    pub message:         Rc<ReplicaToReplicaMessage>,
    pub min_attestation: Option<AttestationParameters>,
}

pub(super) struct RequestNonce {
    pub creation_nonce: [u8; 16],
    pub current_nonce:  [u8; 16],
}

pub(super) struct BackupEntry {
    nonce:   RequestNonce,
    secrets: Option<BackupEntrySecrets>,
}

pub(super) struct XferBackupEntry {
    id:    PartitionKey,
    entry: BackupEntry,
}

pub(super) enum FrontendRequestError {
    InvalidRequest,
    StorageFull,
}

impl PartitionData {
    pub fn new(
        config: PartitionDataConfig,
        service_id: Option<ServiceId>,
        range: Option<PartitionKeyRange>,
        xfer_state: XferState,
    ) -> Self
    {
        Self {
            storage: Default::default(),
            config,
            service_id,
            range,
            xfer_state,
        }
    }

    pub fn service_id(&self) -> Option<&ServiceId> {
        self.service_id.as_ref()
    }

    pub fn service_id_bytes(&self) -> Option<&[u8]> {
        self.service_id.as_ref().map(|service_id| &service_id.id[..])
    }

    pub fn xfer_state(&self) -> &XferState {
        &self.xfer_state
    }

    pub fn xfer_state_mut(&mut self) -> &mut XferState {
        &mut self.xfer_state
    }

    pub fn range(&self) -> Option<&PartitionKeyRange> {
        self.range.as_ref()
    }

    pub fn storage_len(&self) -> usize {
        self.storage.len()
    }

    pub fn xfer_status(&self) -> Option<enclave_replica_partition_status::XferStatus> {
        match &self.xfer_state {
            XferState::SourcePartition(xfer_destination) => Some(enclave_replica_partition_status::XferStatus::OutgoingXferStatus(
                EnclaveOutgoingXferStatus {
                    group_id:            xfer_destination.remote_group_id.id.clone(),
                    full_xfer_range:     xfer_destination.full_range.to_pb(),
                    current_chunk_range: xfer_destination.inflight.as_ref().map(PartitionKeyRange::to_pb),
                    paused:              xfer_destination.paused,
                    min_attestation:     xfer_destination
                        .cur_xfer_chunk_request
                        .as_ref()
                        .and_then(PendingXferRequest::min_attestation),
                    nodes:               xfer_destination.remote_group.status(),
                },
            )),
            XferState::DestinationPartition(xfer_source) => Some(enclave_replica_partition_status::XferStatus::IncomingXferStatus(
                EnclaveIncomingXferStatus {
                    desired_range: xfer_source.desired_range.to_pb(),
                    nodes:         xfer_source.remote_group.status(),
                },
            )),
            XferState::None => None,
        }
    }

    pub fn send_pending_xfer_messages(&mut self) {
        match &mut self.xfer_state {
            XferState::DestinationPartition(xfer_source) => {
                if let Some(cur_xfer_chunk_reply) = xfer_source.cur_xfer_chunk_reply.clone() {
                    let _ignore = xfer_source.remote_group_mut().send(cur_xfer_chunk_reply);
                }
            }
            XferState::SourcePartition(xfer_destination) => {
                if let Some(cur_xfer_reply) = xfer_destination.cur_xfer_reply.clone() {
                    let _ignore = xfer_destination.remote_group_mut().send(cur_xfer_reply);
                }
                if let Some(cur_xfer_chunk_request) = xfer_destination.cur_xfer_chunk_request.clone() {
                    let _ignore = xfer_destination.remote_group_mut().send(cur_xfer_chunk_request);
                }
            }
            XferState::None => (),
        }
    }

    pub fn get_entry_nonce(&mut self, backup_id: &PartitionKey) -> Option<(RequestNonce, Option<NonZeroU16>)> {
        if let Some(backup) = self.storage.get(backup_id) {
            Some((backup.request_nonce(), backup.tries()))
        } else {
            None
        }
    }

    pub fn perform_transaction(
        &mut self,
        txn: transaction_data::Inner,
        peers: &mut PeerManager<PeerState>,
        group: &mut ReplicaGroupState,
        is_leader: bool,
    ) -> enclave_transaction_signal::Transaction
    {
        match txn {
            transaction_data::Inner::FrontendRequest(txn) => {
                enclave_transaction_signal::Transaction::FrontendRequest(self.perform_client_transaction(txn, peers, is_leader))
            }
            transaction_data::Inner::StartXfer(txn) => {
                enclave_transaction_signal::Transaction::StartXfer(self.perform_start_xfer_transaction(txn, peers))
            }
            transaction_data::Inner::SetSid(txn) => enclave_transaction_signal::Transaction::SetSid(self.perform_set_sid_transaction(txn)),
            transaction_data::Inner::RemoveChunk(txn) => {
                enclave_transaction_signal::Transaction::RemoveChunk(self.perform_remove_chunk_transaction(txn, group))
            }
            transaction_data::Inner::ApplyChunk(txn) => {
                enclave_transaction_signal::Transaction::ApplyChunk(self.perform_apply_chunk_transaction(txn, group))
            }
            transaction_data::Inner::PauseXfer(txn) => {
                enclave_transaction_signal::Transaction::PauseXfer(self.perform_pause_xfer_transaction(txn))
            }
            transaction_data::Inner::ResumeXfer(txn) => {
                enclave_transaction_signal::Transaction::ResumeXfer(self.perform_resume_xfer_transaction(txn, group))
            }
            transaction_data::Inner::FinishXfer(txn) => {
                enclave_transaction_signal::Transaction::FinishXfer(self.perform_finish_xfer_transaction(txn))
            }
            transaction_data::Inner::SetTime(txn) => {
                enclave_transaction_signal::Transaction::SetTime(self.perform_set_time_transaction(txn, group))
            }
        }
    }

    fn perform_client_transaction(
        &mut self,
        txn: FrontendRequestTransaction,
        peers: &mut PeerManager<PeerState>,
        is_leader: bool,
    ) -> EnclaveFrontendRequestTransaction
    {
        let backup_id = txn.backup_id().cloned();
        let txn_reply_data = if let Some(backup_id) = txn.backup_id() {
            if self.check_xfer_in_progress(backup_id) {
                transaction_reply::Data::XferInProgress(TransactionErrorXferInProgress {})
            } else if !self.range_contains(backup_id) {
                let maybe_our_range = if let XferState::SourcePartition(xfer_destination) = &self.xfer_state {
                    if let (Some(our_authoritative_range), Some(inflight)) = (&self.range, &xfer_destination.inflight) {
                        match PartitionKeyRange::new(*inflight.first(), *our_authoritative_range.last()) {
                            Ok(our_range) => Some(our_range),
                            Err(()) => {
                                error!(
                                    "our authoritative range {} is less than inflight range {}!",
                                    our_authoritative_range, inflight
                                );
                                None
                            }
                        }
                    } else if let Some(our_authoritative_range) = &self.range {
                        Some(*our_authoritative_range)
                    } else if let Some(inflight_range) = &xfer_destination.inflight {
                        Some(*inflight_range)
                    } else {
                        None
                    }
                } else {
                    self.range
                };

                let new_partition = if let XferState::SourcePartition(xfer_destination) = &self.xfer_state {
                    let other_range = if let Some(our_range) = &maybe_our_range {
                        if let Some(other_last) = our_range.first().checked_sub(1) {
                            match PartitionKeyRange::new(*xfer_destination.full_range.first(), other_last) {
                                Ok(other_range) => Some(other_range.to_pb()),
                                Err(()) => None,
                            }
                        } else {
                            None
                        }
                    } else {
                        Some(xfer_destination.full_range.to_pb())
                    };
                    Some(PartitionConfig {
                        group_id: xfer_destination.remote_group_id.id.clone(),
                        range:    other_range,
                        node_ids: xfer_destination
                            .remote_group
                            .get_remotes()
                            .into_iter()
                            .map(|r| r.to_vec())
                            .collect(),
                    })
                } else {
                    info!("Wrong partition for {}, but we don't know the right one!", backup_id);
                    None
                };

                transaction_reply::Data::WrongPartition(TransactionErrorWrongPartition {
                    range: maybe_our_range.map(|r| r.to_pb()),
                    new_partition,
                })
            } else if let Some(txn_data) = txn.transaction {
                match self.perform_frontend_request(txn_data) {
                    Ok(response_data) => response_data,
                    Err(FrontendRequestError::InvalidRequest) => transaction_reply::Data::InvalidRequest(TransactionErrorInvalidRequest {}),
                    Err(FrontendRequestError::StorageFull) => transaction_reply::Data::InternalError(TransactionErrorInternalError {}),
                }
            } else {
                transaction_reply::Data::InvalidRequest(TransactionErrorInvalidRequest {})
            }
        } else {
            transaction_reply::Data::WrongPartition(TransactionErrorWrongPartition {
                range:         self.range.map(|r| r.to_pb()),
                new_partition: None,
            })
        };

        let txn_info = if let Some(backup_id) = backup_id {
            enclave_frontend_request_transaction::Transaction::from_reply(backup_id, &txn_reply_data)
        } else {
            enclave_frontend_request_transaction::Transaction::InvalidRequest(EnclaveTransactionErrorInvalidRequest {})
        };

        if is_leader {
            let from_node_id: NodeId = txn.from_node_id.clone().into();
            if let Some(from) = peers.get_frontend(&from_node_id) {
                send_transaction_reply(from, txn.request_id, txn_reply_data);
            }
        }

        EnclaveFrontendRequestTransaction {
            transaction: Some(txn_info),
        }
    }

    fn check_xfer_in_progress(&self, id: &BackupId) -> bool {
        if let XferState::SourcePartition(xfer_destination) = &self.xfer_state {
            if let Some(inflight) = &xfer_destination.inflight {
                inflight.contains_id(id)
            } else {
                false
            }
        } else {
            false
        }
    }

    fn range_contains(&self, backup_id: &BackupId) -> bool {
        if let Some(range) = &self.range {
            range.contains_id(backup_id)
        } else {
            false
        }
    }

    fn frontend_request_field_to_array<T>(src: &[u8]) -> Result<T, FrontendRequestError>
    where T: AsMut<[u8]> + Default {
        match util::copy_exact(src) {
            Ok(array) => Ok(array),
            Err(()) => Err(FrontendRequestError::InvalidRequest),
        }
    }

    fn frontend_request_backup_id(backup_id: &BackupId) -> Result<PartitionKey, FrontendRequestError> {
        match PartitionKey::try_from_pb(backup_id) {
            Ok(backup_id) => Ok(backup_id),
            Err(()) => Err(FrontendRequestError::InvalidRequest),
        }
    }

    fn get_or_insert_backup_with(
        &mut self,
        backup_id: PartitionKey,
        create_fun: impl FnOnce() -> BackupEntry,
    ) -> Result<&mut BackupEntry, FrontendRequestError>
    {
        let storage_len = self.storage.len();
        match self.storage.entry(backup_id) {
            btree_map::Entry::Occupied(backup_entry) => Ok(backup_entry.into_mut()),
            btree_map::Entry::Vacant(backup_entry) => {
                if storage_len < self.config.capacity {
                    Ok(backup_entry.insert(create_fun()))
                } else {
                    Err(FrontendRequestError::StorageFull)
                }
            }
        }
    }

    fn perform_frontend_request(
        &mut self,
        txn_data: frontend_request_transaction::Transaction,
    ) -> Result<transaction_reply::Data, FrontendRequestError>
    {
        match txn_data {
            frontend_request_transaction::Transaction::Create(create_request) => {
                let backup_id = Self::frontend_request_backup_id(&create_request.backup_id)?;
                let new_creation_nonce = Self::frontend_request_field_to_array(&create_request.new_creation_nonce)?;
                let new_nonce = Self::frontend_request_field_to_array(&create_request.new_nonce)?;
                let backup = self.get_or_insert_backup_with(backup_id, || BackupEntry {
                    nonce:   RequestNonce {
                        creation_nonce: new_creation_nonce,
                        current_nonce:  new_nonce,
                    },
                    secrets: None,
                })?;

                Ok(transaction_reply::Data::CreateBackupReply(CreateBackupReply {
                    token: backup.request_nonce().to_combined().to_vec(),
                    tries: backup.tries().map(u16::from).map(u32::from),
                }))
            }
            frontend_request_transaction::Transaction::Backup(backup_request) => {
                let backup_id = Self::frontend_request_backup_id(&backup_request.backup_id)?;
                let new_creation_nonce = Self::frontend_request_field_to_array(&backup_request.new_creation_nonce)?;
                let new_nonce = Self::frontend_request_field_to_array(&backup_request.new_nonce)?;
                let tries = backup_request
                    .tries
                    .to_u16()
                    .and_then(NonZeroU16::new)
                    .ok_or(FrontendRequestError::InvalidRequest)?;

                let max_backup_data_length = self.config.max_backup_data_length;

                let backup = self.get_or_insert_backup_with(backup_id, || BackupEntry {
                    nonce:   RequestNonce {
                        creation_nonce: new_creation_nonce,
                        current_nonce:  new_nonce,
                    },
                    secrets: None,
                })?;

                let backup_response = if backup_request.old_nonce == backup.nonce.creation_nonce {
                    kbupd_client::BackupResponse {
                        status: Some(kbupd_client::backup_response::Status::Ok.into()),
                        nonce:  Some(backup.request_nonce().to_combined().to_vec()),
                    }
                } else if backup_request.old_nonce != backup.nonce.current_nonce {
                    kbupd_client::BackupResponse {
                        status: Some(kbupd_client::backup_response::Status::AlreadyExists.into()),
                        nonce:  Some(backup.request_nonce().to_combined().to_vec()),
                    }
                } else {
                    let backup_request_pin: &[u8; BackupEntry::PIN_LENGTH] = match backup_request.pin.data[..].try_into() {
                        Ok(backup_request_pin) => backup_request_pin,
                        Err(_) => return Err(FrontendRequestError::InvalidRequest),
                    };
                    if backup_request.data.data.len() > max_backup_data_length.to_usize() {
                        return Err(FrontendRequestError::InvalidRequest);
                    }
                    backup.nonce.creation_nonce = backup.nonce.current_nonce;
                    backup.nonce.current_nonce = new_nonce;
                    backup.secrets = Some(BackupEntrySecrets::new(tries, backup_request_pin, &backup_request.data.data));

                    kbupd_client::BackupResponse {
                        status: Some(kbupd_client::backup_response::Status::Ok.into()),
                        nonce:  Some(backup.request_nonce().to_combined().to_vec()),
                    }
                };
                Ok(transaction_reply::Data::ClientResponse(kbupd_client::Response {
                    backup:  Some(backup_response),
                    restore: None,
                    delete:  None,
                }))
            }
            frontend_request_transaction::Transaction::Restore(restore_request) => {
                let backup_id = Self::frontend_request_backup_id(&restore_request.backup_id)?;
                let restore_response = if let btree_map::Entry::Occupied(mut storage_entry) = self.storage.entry(backup_id) {
                    let entry = storage_entry.get_mut();
                    let new_nonce = Self::frontend_request_field_to_array(&restore_request.new_nonce)?;

                    if restore_request.creation_nonce != entry.nonce.creation_nonce {
                        kbupd_client::RestoreResponse {
                            status: Some(kbupd_client::restore_response::Status::Missing.into()),
                            nonce:  None,
                            data:   None,
                            tries:  None,
                        }
                    } else if restore_request.old_nonce != entry.nonce.current_nonce {
                        kbupd_client::RestoreResponse {
                            status: Some(kbupd_client::restore_response::Status::NonceMismatch.into()),
                            nonce:  Some(entry.request_nonce().to_combined().to_vec()),
                            data:   None,
                            tries:  entry.tries().map(u16::from).map(u32::from),
                        }
                    } else {
                        entry.nonce.current_nonce = new_nonce;

                        if let Some(entry_secrets) = &mut entry.secrets {
                            if entry_secrets.pin_consttime_eq(&restore_request.pin.data) {
                                kbupd_client::RestoreResponse {
                                    status: Some(kbupd_client::restore_response::Status::Ok.into()),
                                    tries:  Some(u32::from(entry_secrets.tries.get())),
                                    data:   Some(entry_secrets.data().to_vec()),
                                    nonce:  Some(entry.request_nonce().to_combined().to_vec()),
                                }
                            } else if let Some(tries_minus_one) = entry_secrets.tries.get().checked_sub(2) {
                                // decrement tries
                                entry_secrets.tries = tries_minus_one
                                    .checked_add(1)
                                    .and_then(NonZeroU16::new)
                                    .unwrap_or_else(|| unreachable!());
                                kbupd_client::RestoreResponse {
                                    status: Some(kbupd_client::restore_response::Status::PinMismatch.into()),
                                    tries:  Some(u32::from(entry_secrets.tries.get())),
                                    data:   None,
                                    nonce:  Some(entry.request_nonce().to_combined().to_vec()),
                                }
                            } else {
                                // ran out of tries. erase backup.
                                storage_entry.remove();
                                kbupd_client::RestoreResponse {
                                    status: Some(kbupd_client::restore_response::Status::Missing.into()),
                                    nonce:  None,
                                    data:   None,
                                    tries:  None,
                                }
                            }
                        } else {
                            // no secret data present
                            kbupd_client::RestoreResponse {
                                status: Some(kbupd_client::restore_response::Status::Missing.into()),
                                nonce:  None,
                                data:   None,
                                tries:  None,
                            }
                        }
                    }
                } else {
                    kbupd_client::RestoreResponse {
                        status: Some(kbupd_client::restore_response::Status::Missing.into()),
                        nonce:  None,
                        data:   None,
                        tries:  None,
                    }
                };
                Ok(transaction_reply::Data::ClientResponse(kbupd_client::Response {
                    backup:  None,
                    restore: Some(restore_response),
                    delete:  None,
                }))
            }
            frontend_request_transaction::Transaction::Delete(delete_request) => {
                let backup_id = Self::frontend_request_backup_id(&delete_request.backup_id)?;
                self.storage.remove(&backup_id);
                Ok(transaction_reply::Data::DeleteBackupReply(DeleteBackupReply {}))
            }
        }
    }

    fn perform_start_xfer_transaction(
        &mut self,
        txn: StartXferTransaction,
        peers: &mut PeerManager<PeerState>,
    ) -> EnclaveStartXferTransaction
    {
        let from = NodeId::from(&txn.from_node_id);

        match &self.xfer_state {
            XferState::SourcePartition(xfer_destination) => {
                if txn.xfer_request.group_id != xfer_destination.remote_group_id {
                    warn!(
                        "received XferRequest from {} while having xfer destination {}: {}",
                        &from, &xfer_destination.remote_group_id, &txn.xfer_request
                    );
                } else {
                    verbose!("received duplicate XferRequest from {}", &from);
                }
                return Default::default();
            }
            XferState::DestinationPartition(_xfer_source) => {
                warn!(
                    "received XferRequest from {} while having xfer source: {}",
                    &from, &txn.xfer_request
                );
                return Default::default();
            }
            XferState::None => (),
        }

        let full_range = match PartitionKeyRange::try_from_pb(&txn.xfer_request.full_range) {
            Ok(full_range) => full_range,
            Err(()) => {
                error!("received XferRequest from {} with invalid range: {}", &from, &txn.xfer_request);
                return Default::default();
            }
        };
        let our_range = match &self.range {
            Some(our_range) => our_range,
            None => {
                warn!("received XferRequest from {} while having no range: {}", &from, &txn.xfer_request);
                return Default::default();
            }
        };
        if (our_range.first() != full_range.first() || !our_range.contains_range(&full_range)) {
            warn!(
                "received XferRequest from {} with requested range outside our range {}: {}",
                &from, &our_range, &txn.xfer_request
            );
            return Default::default();
        }

        let service_id = match &self.service_id {
            Some(service_id) => service_id,
            None => {
                warn!(
                    "received XferRequest from {} while having no service id: {}",
                    &from, &txn.xfer_request
                );
                return Default::default();
            }
        };

        let mut attestations: Vec<(NodeId, AttestationParameters)> = Vec::new();
        let mut senders: Vec<ReplicaRemoteSender> = Vec::new();
        for node_id in &txn.xfer_request.node_ids {
            match peers.start_peer(node_id.into(), NodeType::Replica, RemoteAuthorizationType::Mutual) {
                Ok(peer_entry) => {
                    senders.push(peer_entry.remote().sender().clone());
                    peer_entry.insert(PeerState::new_replica);
                }
                Err(Some(PeerState::Replica { remote, .. })) => {
                    if let Some(attestation) = remote.attestation() {
                        attestations.push((remote.id().clone(), attestation));
                    }
                    senders.push(remote.sender().clone());
                }
                Err(Some(PeerState::Frontend { .. })) | Err(None) => {
                    error!(
                        "started xfer to {} when it's already connected as a frontend!",
                        NodeId::from(node_id)
                    );
                }
            }
        }

        let cur_xfer_reply = PendingXferRequest {
            id:              PendingXferRequestId::XferReply,
            message:         Rc::new(ReplicaToReplicaMessage {
                inner: Some(replica_to_replica_message::Inner::XferReply(XferReply {
                    service: service_id.clone(),
                })),
            }),
            min_attestation: None,
        };
        let remote_group_id = txn.xfer_request.group_id.clone();
        let group_name = format!("{}", &remote_group_id);
        let mut remote_group = RemoteGroupState::new(group_name, senders);
        for (replica_node_id, _attestation) in &attestations {
            remote_group.remote_authorized(replica_node_id);
        }
        let chunk_size = txn.xfer_request.chunk_size;

        let display_nodes = txn.xfer_request.node_ids.iter().map(|node| util::ToHex(node));
        info!(
            "starting xfer of range {} chunk size {} to group {} with nodes {}",
            &full_range,
            &chunk_size,
            &remote_group_id,
            ListDisplay(display_nodes)
        );

        self.xfer_state = XferState::SourcePartition(XferDestination {
            remote_group_id,
            remote_group,
            full_range,
            chunk_size,
            paused: true,
            inflight: None,

            cur_xfer_reply: Some(cur_xfer_reply),
            cur_xfer_chunk_request: None,
        });

        EnclaveStartXferTransaction {}
    }

    fn perform_set_sid_transaction(&mut self, txn: SetSidTransaction) -> EnclaveSetSidTransaction {
        if let XferState::DestinationPartition(xfer_source) = &mut self.xfer_state {
            xfer_source.received_reply(&PendingXferRequestId::XferRequest);
        }
        if let Some(service_id) = &self.service_id {
            if service_id != &txn.service_id {
                error!(
                    "tried to set service id {} on partition already having service id {}",
                    &txn.service_id, &service_id
                );
            }
            Default::default()
        } else {
            self.service_id = Some(txn.service_id.clone());

            EnclaveSetSidTransaction {
                service_id: Some(txn.service_id),
            }
        }
    }

    fn perform_remove_chunk_transaction(
        &mut self,
        txn: RemoveChunkTransaction,
        group: &mut ReplicaGroupState,
    ) -> EnclaveRemoveChunkTransaction
    {
        if let XferState::SourcePartition(xfer_destination) = &mut self.xfer_state {
            xfer_destination.received_reply(&PendingXferRequestId::XferReply);
            xfer_destination.received_reply(&PendingXferRequestId::XferChunkRequest {
                new_last: txn.xfer_chunk_reply.new_last.clone(),
            });

            if let Some(inflight) = &xfer_destination.inflight {
                if inflight.last() == &txn.xfer_chunk_reply.new_last {
                    xfer_destination.inflight = None;
                } else {
                    warn!(
                        "dropping out of order RemoveChunkTransaction {} expecting {}",
                        &txn.xfer_chunk_reply.new_last, &inflight
                    );
                }
            }

            xfer_destination.chunk_size = txn.xfer_chunk_reply.chunk_size;

            let chunk_range = self.remove_chunk(&txn.chunk_last, group);
            EnclaveRemoveChunkTransaction {
                chunk_range: chunk_range.as_ref().map(PartitionKeyRange::to_pb),
            }
        } else {
            warn!("dropping unexpected RemoveChunkTransaction {}", &txn.xfer_chunk_reply.new_last);
            Default::default()
        }
    }

    pub fn next_chunk_last(&self, chunk_size: u32, full_range: &PartitionKeyRange) -> BackupId {
        let max_entry_len = XferBackupEntry::encoded_len(self.config.max_backup_data_length);
        let chunk_count = (chunk_size / max_entry_len).max(1);
        let chunk_range = self.storage.range(full_range).take(chunk_count.to_usize());
        if let Some((chunk_last, _value)) = chunk_range.last() {
            chunk_last.to_pb()
        } else {
            full_range.to_pb().last
        }
    }

    fn remove_chunk(&mut self, chunk_last: &BackupId, group: &ReplicaGroupState) -> Option<PartitionKeyRange> {
        let xfer_destination = match &mut self.xfer_state {
            XferState::SourcePartition(xfer_destination) => xfer_destination,
            _ => {
                error!("tried to remove a chunk from a non-source partition");
                return None;
            }
        };
        let chunk_last = match PartitionKey::try_from_pb(chunk_last) {
            Ok(chunk_last) => chunk_last,
            Err(()) => {
                error!("invalid xfer chunk backup id {}", &chunk_last);
                return None;
            }
        };

        if xfer_destination.paused {
            info!("not sending xfer chunk {} as transfer is paused", &chunk_last);
            return None;
        }

        if let Some(inflight) = &xfer_destination.inflight {
            info!("not sending xfer chunk {} as xfer chunk {} is in progress", &chunk_last, inflight);
            return None;
        }

        let split_range_res = if let Some(our_range) = &mut self.range {
            let mut chunk_range = *our_range;
            match chunk_range.split_off_inclusive(&chunk_last) {
                Ok(our_new_range) => {
                    self.range = our_new_range;
                    Ok(chunk_range)
                }
                Err(()) => Err(()),
            }
        } else {
            Err(())
        };

        let chunk_range = match split_range_res {
            Ok(chunk_range) => chunk_range,
            Err(()) => {
                info!("All transfers sent");
                return None;
            }
        };

        let maybe_our_new_first = if let Some(range) = &self.range { Some(range.first()) } else { None };

        let entries = Self::storage_split_to(&mut self.storage, maybe_our_new_first);

        info!("sending xfer chunk {} length {}", &chunk_range, entries.len());

        let max_entry_len = XferBackupEntry::encoded_len(self.config.max_backup_data_length);
        let mut data = SecretBytes {
            data: Vec::with_capacity(entries.len().saturating_mul(max_entry_len.to_usize())),
        };
        for (id, entry) in entries {
            let xfer_entry = XferBackupEntry { id, entry };
            xfer_entry.encode(&mut data.data);
        }

        xfer_destination.inflight = Some(chunk_range);

        let min_attestation = group.attestation_expiration_window();
        xfer_destination.cur_xfer_chunk_request = Some(PendingXferRequest {
            id:              PendingXferRequestId::XferChunkRequest {
                new_last: chunk_last.to_pb(),
            },
            message:         Rc::new(ReplicaToReplicaMessage {
                inner: Some(replica_to_replica_message::Inner::XferChunkRequest(XferChunkRequest {
                    data,
                    chunk_range: chunk_range.to_pb(),
                    min_attestation,
                })),
            }),
            min_attestation: Some(min_attestation),
        });
        Some(chunk_range)
    }

    fn storage_split_to(
        storage: &mut BTreeMap<PartitionKey, BackupEntry>,
        maybe_split_key: Option<&PartitionKey>,
    ) -> impl DoubleEndedIterator<Item = (PartitionKey, BackupEntry)> + ExactSizeIterator
    {
        let new_map = if let Some(split_key) = maybe_split_key {
            storage.split_off(split_key)
        } else {
            Default::default()
        };
        std::mem::replace(storage, new_map).into_iter()
    }

    fn perform_apply_chunk_transaction(
        &mut self,
        txn: ApplyChunkTransaction,
        group: &mut ReplicaGroupState,
    ) -> EnclaveApplyChunkTransaction
    {
        if let XferState::DestinationPartition(xfer_source) = &mut self.xfer_state {
            let request = &txn.xfer_chunk_request;
            info!("received xfer chunk {} length {}", &request.chunk_range, request.data.data.len());

            let new_first = if let Some(range) = &self.range {
                range.first()
            } else {
                xfer_source.desired_range.first()
            };

            let chunk_range = match PartitionKeyRange::try_from_pb(&request.chunk_range) {
                Ok(chunk_range) => {
                    if xfer_source.desired_range.contains_range(&chunk_range) {
                        if !self.range.map(|range| range.overlaps_range(&chunk_range)).unwrap_or(false) {
                            chunk_range
                        } else {
                            warn!(
                                "dropping old xfer chunk {} current range {}",
                                &chunk_range,
                                OptionDisplay(self.range)
                            );
                            return Default::default();
                        }
                    } else {
                        error!(
                            "dropping xfer chunk {} not in desired range {}",
                            &chunk_range, &xfer_source.desired_range
                        );
                        return Default::default();
                    }
                }
                Err(()) => {
                    error!("dropping xfer chunk with invalid range {}", &request.chunk_range);
                    return Default::default();
                }
            };

            let new_range = match PartitionKeyRange::new(*new_first, *chunk_range.last()) {
                Ok(new_range) => new_range,
                Err(()) => {
                    warn!("dropping old xfer chunk {} < {}", chunk_range.last(), &new_first);
                    return Default::default();
                }
            };
            let old_range = std::mem::replace(&mut self.range, Some(new_range));

            let xfer_chunk_reply = PendingXferRequest {
                id:              PendingXferRequestId::XferChunkReply {
                    new_last: txn.xfer_chunk_reply.new_last.clone(),
                },
                message:         Rc::new(ReplicaToReplicaMessage {
                    inner: Some(replica_to_replica_message::Inner::XferChunkReply(txn.xfer_chunk_reply.clone())),
                }),
                min_attestation: None,
            };
            let old_xfer_chunk_reply = mem::replace(&mut xfer_source.cur_xfer_chunk_reply, Some(xfer_chunk_reply));
            if let Some(old_xfer_chunk_reply) = old_xfer_chunk_reply {
                xfer_source.received_reply(&old_xfer_chunk_reply.id);
            }

            let AttestationParameters { unix_timestamp_seconds } = request.min_attestation;
            let min_attestation_time = Duration::from_secs(unix_timestamp_seconds);
            if min_attestation_time > group.get_attestation_time_now() {
                group.set_attestation_time_now(min_attestation_time);
            }

            let mut entries_data = &request.data.data[..];
            let mut entry_count = 0;
            while entries_data.has_remaining() {
                let entry = XferBackupEntry::decode(&mut entries_data);
                if !old_range.map(|old_range| old_range.contains(&entry.id)).unwrap_or(false) {
                    self.storage.insert(entry.id, entry.entry);
                    entry_count += 1;
                } else {
                    error!(
                        "dropping transferred backup id {} within current range {}",
                        &entry.id,
                        OptionDisplay(self.range)
                    );
                }
            }

            if chunk_range.last() >= xfer_source.desired_range.last() {
                info!("All transfer chunks applied");
            }

            drop(txn);

            let mut chunk_ids = Vec::with_capacity(entry_count);
            for (backup_id, _) in self.storage.range(&chunk_range) {
                chunk_ids.push(backup_id.to_pb());
            }
            EnclaveApplyChunkTransaction {
                chunk_range: Some(chunk_range.to_pb()),
                chunk_ids,
            }
        } else {
            warn!("dropping unexpected ApplyChunkTransaction {}", txn.xfer_chunk_reply.new_last);
            Default::default()
        }
    }

    fn perform_pause_xfer_transaction(&mut self, txn: PauseXferTransaction) -> EnclavePauseXferTransaction {
        let xfer_destination = match &mut self.xfer_state {
            XferState::SourcePartition(xfer_destination) => xfer_destination,
            _ => {
                warn!("Tried to pause partitioning as a non-source replica!");
                send_untrusted_xfer_reply(txn.request_id, UntrustedXferReplyStatus::InvalidState);
                return Default::default();
            }
        };
        if !xfer_destination.paused {
            info!(
                "Pausing partitioning process at {}",
                OptionDisplay(self.range.as_ref().map(PartitionKeyRange::first))
            );
        }
        xfer_destination.paused = true;

        send_untrusted_xfer_reply(txn.request_id, UntrustedXferReplyStatus::Ok);

        EnclavePauseXferTransaction {}
    }

    fn perform_resume_xfer_transaction(
        &mut self,
        txn: ResumeXferTransaction,
        group: &mut ReplicaGroupState,
    ) -> EnclaveResumeXferTransaction
    {
        let xfer_destination = match &mut self.xfer_state {
            XferState::SourcePartition(xfer_destination) => xfer_destination,
            _ => {
                warn!("Tried to resume partitioning as a non-source replica!");
                send_untrusted_xfer_reply(txn.request_id, UntrustedXferReplyStatus::InvalidState);
                return Default::default();
            }
        };
        info!("Resuming partitioning process with next chunk {}", &txn.chunk_last);
        xfer_destination.paused = false;
        let chunk_range = self.remove_chunk(&txn.chunk_last, group);

        send_untrusted_xfer_reply(txn.request_id, UntrustedXferReplyStatus::Ok);

        EnclaveResumeXferTransaction {
            chunk_range: chunk_range.as_ref().map(PartitionKeyRange::to_pb),
        }
    }

    fn perform_finish_xfer_transaction(&mut self, txn: FinishXferTransaction) -> EnclaveFinishXferTransaction {
        let status = match &mut self.xfer_state {
            XferState::DestinationPartition(xfer_source) => {
                let xfer_done = if let Some(range) = &self.range {
                    range.contains_range(&xfer_source.desired_range)
                } else {
                    false
                };
                if xfer_done || txn.force {
                    info!("Finishing partitioning process");
                    // XXX Disconnect source nodes
                    self.xfer_state = XferState::None;
                    UntrustedXferReplyStatus::Ok
                } else {
                    warn!("tried to finish in-progress partitioning process!");
                    UntrustedXferReplyStatus::InvalidState
                }
            }
            XferState::SourcePartition(xfer_destination) => {
                let xfer_done = if let Some(range) = &self.range {
                    !xfer_destination.full_range.contains(range.first())
                } else {
                    true
                };
                if xfer_done || txn.force {
                    info!("Finishing partitioning process");
                    self.xfer_state = XferState::None;
                    UntrustedXferReplyStatus::Ok
                } else {
                    warn!("tried to finish in-progress partitioning process!");
                    UntrustedXferReplyStatus::InvalidState
                }
            }
            XferState::None => UntrustedXferReplyStatus::InvalidState,
        };

        send_untrusted_xfer_reply(txn.request_id, status);
        EnclaveFinishXferTransaction {}
    }

    fn perform_set_time_transaction(&mut self, txn: SetTimeTransaction, group: &mut ReplicaGroupState) -> EnclaveSetTimeTransaction {
        if !group.set_attestation_time_now(Duration::from_secs(txn.now_secs)) {
            warn!(
                "tried to set attestation time backward from {} to {}",
                group.get_attestation_time_now().as_secs(),
                txn.now_secs
            );
            Default::default()
        } else {
            EnclaveSetTimeTransaction {
                now_secs: Some(txn.now_secs),
            }
        }
    }
}

//
// XferState impls
//

impl XferState {
    pub fn remote_group_mut(&mut self) -> Option<&mut RemoteGroupState<ReplicaRemoteSender, PendingXferRequest>> {
        match self {
            XferState::DestinationPartition(xfer_source) => Some(&mut xfer_source.remote_group),
            XferState::SourcePartition(xfer_destination) => Some(&mut xfer_destination.remote_group),
            XferState::None => None,
        }
    }
}

//
// XferSource impls
//

impl XferSource {
    pub fn new(remote_group: RemoteGroupState<ReplicaRemoteSender, PendingXferRequest>, desired_range: PartitionKeyRange) -> Self {
        Self {
            remote_group,
            desired_range,
            cur_xfer_chunk_reply: None,
        }
    }

    pub fn remote_group(&self) -> &RemoteGroupState<ReplicaRemoteSender, PendingXferRequest> {
        &self.remote_group
    }

    pub fn remote_group_mut(&mut self) -> &mut RemoteGroupState<ReplicaRemoteSender, PendingXferRequest> {
        &mut self.remote_group
    }

    pub fn desired_range(&self) -> &PartitionKeyRange {
        &self.desired_range
    }

    pub fn received_reply(&mut self, request_id: &PendingXferRequestId) {
        if let Some(pending_request) = self.remote_group.handle_reply(request_id) {
            match &pending_request.id {
                PendingXferRequestId::XferRequest => (),
                PendingXferRequestId::XferReply => (),
                PendingXferRequestId::XferChunkReply { .. } => {
                    if let Some(cur_xfer_chunk_reply) = &self.cur_xfer_chunk_reply {
                        if cur_xfer_chunk_reply.id == pending_request.id {
                            self.cur_xfer_chunk_reply = None;
                        }
                    }
                }
                PendingXferRequestId::XferChunkRequest { .. } => (),
            }
        }
    }
}

//
// XferDestination impls
//

impl XferDestination {
    pub fn remote_group(&self) -> &RemoteGroupState<ReplicaRemoteSender, PendingXferRequest> {
        &self.remote_group
    }

    pub fn remote_group_mut(&mut self) -> &mut RemoteGroupState<ReplicaRemoteSender, PendingXferRequest> {
        &mut self.remote_group
    }

    pub fn full_range(&self) -> &PartitionKeyRange {
        &self.full_range
    }

    pub fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    pub fn received_reply(&mut self, request_id: &PendingXferRequestId) {
        if let Some(pending_request) = self.remote_group.handle_reply(request_id) {
            match &pending_request.id {
                PendingXferRequestId::XferRequest => (),
                PendingXferRequestId::XferReply => {
                    self.cur_xfer_reply = None;
                }
                PendingXferRequestId::XferChunkReply { .. } => (),
                PendingXferRequestId::XferChunkRequest { .. } => {
                    if let Some(cur_xfer_chunk_request) = &self.cur_xfer_chunk_request {
                        if cur_xfer_chunk_request.id == pending_request.id {
                            self.cur_xfer_chunk_request = None;
                        }
                    }
                }
            }
        }
    }
}

//
// PendingXferRequest impls
//

impl RemoteGroupPendingRequest for PendingXferRequest {
    type Message = ReplicaToReplicaMessage;
    type RequestId = PendingXferRequestId;

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
// RequestNonce impls
//

impl RequestNonce {
    pub fn from_combined(mut combined: [u8; 32]) -> Self {
        let (creation_nonce, current_nonce) = Self::split_mut(&mut combined);
        Self {
            creation_nonce: *creation_nonce,
            current_nonce:  *current_nonce,
        }
    }

    pub fn to_combined(&self) -> [u8; 32] {
        let mut combined = [0; 32];

        let (combined_creation_nonce, combined_current_nonce) = Self::split_mut(&mut combined);

        *combined_creation_nonce = self.creation_nonce;
        *combined_current_nonce = self.current_nonce;

        combined
    }

    const fn encoded_len() -> u32 {
        32
    }

    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(&self.creation_nonce);
        buf.put_slice(&self.current_nonce);
    }

    fn decode<B: Buf>(buf: &mut B) -> Self {
        let mut value = Self {
            creation_nonce: Default::default(),
            current_nonce:  Default::default(),
        };
        buf.copy_to_slice(&mut value.creation_nonce);
        buf.copy_to_slice(&mut value.current_nonce);
        value
    }

    fn split_mut(combined: &mut [u8; 32]) -> (&mut [u8; 16], &mut [u8; 16]) {
        let (creation_nonce, current_nonce) = combined.split_at_mut(16);
        let creation_nonce: &mut [u8; 16] = creation_nonce.try_into().unwrap_or_else(|_| static_unreachable!());
        let current_nonce: &mut [u8; 16] = current_nonce.try_into().unwrap_or_else(|_| static_unreachable!());
        (creation_nonce, current_nonce)
    }
}

//
// BackupEntry impls
//

impl BackupEntry {
    const PIN_LENGTH: usize = 32;

    const fn encoded_len(data_len: u32) -> u32 {
        RequestNonce::encoded_len() + BackupEntrySecrets::encoded_len(data_len)
    }

    fn encode<B: BufMut>(&self, buf: &mut B) {
        self.nonce.encode(buf);
        BackupEntrySecrets::encode_opt(self.secrets.as_ref(), buf);
    }

    fn decode<B: Buf>(buf: &mut B) -> Self {
        let nonce = RequestNonce::decode(buf);
        let secrets = BackupEntrySecrets::decode(buf);
        Self { nonce, secrets }
    }

    fn tries(&self) -> Option<NonZeroU16> {
        self.secrets.as_ref().map(|secrets: &BackupEntrySecrets| secrets.tries)
    }

    fn request_nonce(&self) -> RequestNonce {
        RequestNonce {
            current_nonce:  self.nonce.current_nonce,
            creation_nonce: self.nonce.creation_nonce,
        }
    }
}

//
// XferBackupEntry impls
//

impl XferBackupEntry {
    fn encoded_len(data_len: u32) -> u32 {
        BackupId::valid_len() + BackupEntry::encoded_len(data_len)
    }

    fn encode<B: BufMut>(&self, buf: &mut B) {
        self.entry.encode(buf);
        buf.put_slice(&self.id[..]);
    }

    fn decode<B: Buf>(buf: &mut B) -> Self {
        let entry = BackupEntry::decode(buf);
        let mut id = [0; 32];
        buf.copy_to_slice(&mut id);
        Self {
            id: PartitionKey::new(id),
            entry,
        }
    }
}

//
// utils
//

fn send_untrusted_xfer_reply(request_id: u64, status: UntrustedXferReplyStatus) {
    kbupd_send(EnclaveMessage {
        inner: Some(enclave_message::Inner::UntrustedXferReply(UntrustedXferReply {
            request_id,
            status: status.into(),
        })),
    });
}
