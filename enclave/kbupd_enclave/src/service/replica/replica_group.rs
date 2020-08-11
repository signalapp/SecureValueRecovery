//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use crate::prelude::*;

use std::fmt;
use std::rc::*;
use std::time::*;

use sgxsd_ffi::RdRand;

use crate::protobufs::kbupd_enclave::*;
use crate::raft::*;
use crate::remote::*;
use crate::storage::*;
use crate::util::ListDisplay;

use super::*;

const ATTESTATION_EXPIRATION_WINDOW: Duration = Duration::from_secs(86400);

pub(super) struct ReplicaGroupState {
    pub raft: RaftState<RaftLogStorage, RdRand, NodeId>,

    remotes: Box<[RemoteReplicaState]>,

    attestation_time_ticks: u32,
    request_quote_ticks:    u32,

    attestation_time_now: Duration,
}

pub(super) struct RemoteReplicaState {
    pub sender: ReplicaRemoteSender,
}

//
// ReplicaGroupState impls
//

impl ReplicaGroupState {
    pub fn new(raft: RaftState<RaftLogStorage, RdRand, NodeId>, remotes: Box<[RemoteReplicaState]>) -> Self {
        Self {
            raft,
            remotes,
            attestation_time_ticks: 0,
            request_quote_ticks: 0,
            attestation_time_now: Duration::from_secs(0),
        }
    }

    pub fn id(&self) -> &RaftGroupId {
        self.raft.group_id()
    }

    pub fn set_config(&mut self, config: &EnclaveReplicaConfig) {
        self.raft
            .log_mut()
            .set_index_cache_size(config.raft_log_index_page_cache_size.to_usize());
        self.raft.set_election_timeout_ticks(config.election_timeout_ticks);
        self.raft.set_heartbeat_timeout_ticks(config.heartbeat_timeout_ticks);
        self.raft.set_replication_chunk_size(config.replication_chunk_size.to_usize());
    }

    pub fn get(&self, node_id: &NodeId) -> Option<&RemoteReplicaState> {
        self.remotes
            .iter()
            .find(|replica: &&RemoteReplicaState| replica.sender.id() == node_id)
    }

    pub fn timer_tick(&mut self, max_attestation_time_ticks: u32, max_request_quote_ticks: u32, now: Duration) -> Option<TransactionData> {
        self.attestation_time_ticks = self.attestation_time_ticks.saturating_add(1);
        self.request_quote_ticks = self.request_quote_ticks.saturating_add(1);

        if self.request_quote_ticks >= max_request_quote_ticks {
            self.request_quote_ticks = Default::default();

            for remote in &mut self.remotes[..] {
                let _ignore = remote.sender.request_quote(EnclaveGetQuoteRequest {});
            }
        }

        if self.attestation_time_ticks >= max_attestation_time_ticks {
            if now > self.attestation_time_now {
                match self.check_quorum_attestation_time(now) {
                    Ok(()) => {
                        self.attestation_time_ticks = 0;
                        Some(TransactionData {
                            inner: Some(transaction_data::Inner::SetTime(SetTimeTransaction { now_secs: now.as_secs() })),
                        })
                    }
                    Err(invalid) => {
                        if self.attestation_time_ticks.checked_rem(max_attestation_time_ticks) == Some(0) {
                            info!(
                                "not setting attestation time to {} with invalid attestations for {} of {} replicas: {}",
                                now.as_secs(),
                                invalid.len(),
                                self.remotes.iter().len(),
                                ListDisplay(invalid)
                            );
                        }
                        None
                    }
                }
            } else {
                if now < self.attestation_time_now {
                    warn!(
                        "not setting attestation time backward from {} to {}",
                        self.attestation_time_now.as_secs(),
                        now.as_secs()
                    );
                }
                None
            }
        } else {
            None
        }
    }

    pub fn is_authorized(&self, node_id: &NodeId) -> bool {
        (self.get(node_id))
            .map(|replica: &RemoteReplicaState| replica.check_attestation_time(self.attestation_time_now))
            .unwrap_or(false)
    }

    pub fn set_attestation_time_now(&mut self, now: Duration) -> bool {
        if now > self.attestation_time_now {
            for replica in self.remotes.iter() {
                if !replica.check_attestation_time(now) {
                    if let Some(attestation) = replica.attestation() {
                        warn!(
                            "replica {} is now invalid at {}: {}",
                            replica.sender.id(),
                            now.as_secs(),
                            attestation
                        );
                    }
                }
            }
            info!(
                "set attestation time from {} to {}",
                self.attestation_time_now.as_secs(),
                now.as_secs()
            );
            self.attestation_time_now = now;
            true
        } else {
            now < self.attestation_time_now
        }
    }

    pub fn get_attestation_time_now(&self) -> Duration {
        self.attestation_time_now
    }

    pub fn attestation(&self) -> AttestationParameters {
        AttestationParameters::new(self.attestation_time_now)
    }

    pub fn attestation_expiration_window(&self) -> AttestationParameters {
        let min_unix_timestamp = self
            .attestation_time_now
            .checked_sub(ATTESTATION_EXPIRATION_WINDOW)
            .unwrap_or_default();
        AttestationParameters::new(min_unix_timestamp)
    }

    fn check_quorum_attestation_time(&self, now: Duration) -> Result<(), Vec<&RemoteReplicaState>> {
        let replicas_iter = self.remotes.iter();
        let replicas_len = replicas_iter.len();
        let invalid: Vec<_> = replicas_iter
            .filter(|replica: &&RemoteReplicaState| !replica.check_attestation_time(now))
            .collect();
        if invalid.len() < quorum_size(replicas_len) {
            if invalid.is_empty() {
                info!("setting attestation time to {}", now.as_secs());
            } else {
                warn!(
                    "setting attestation time to {} with invalid attestations for {} of {} replicas: {}",
                    now.as_secs(),
                    invalid.len(),
                    replicas_len,
                    ListDisplay(invalid)
                );
            }
            Ok(())
        } else {
            Err(invalid)
        }
    }

    pub fn send_raft_message(&self, sendable: SendableRaftMessage<NodeId>) {
        match sendable {
            SendableRaftMessage::Broadcast { message } => {
                let r2r_message = Rc::new(ReplicaToReplicaMessage {
                    inner: Some(replica_to_replica_message::Inner::RaftMessage(message)),
                });
                for replica in self.remotes.iter() {
                    if replica.check_attestation_time(self.attestation_time_now) {
                        let _ignore = replica.sender.send(Rc::clone(&r2r_message));
                    } else {
                        verbose!(
                            "dropping broadcast message to {} with expired attestation {}",
                            replica.sender.id(),
                            OptionDisplay(replica.attestation())
                        );
                    }
                }
            }
            SendableRaftMessage::Reply { message, from } => {
                if let Some(replica) = self.get(&from) {
                    if replica.check_attestation_time(self.attestation_time_now) {
                        let r2r_message = Rc::new(ReplicaToReplicaMessage {
                            inner: Some(replica_to_replica_message::Inner::RaftMessage(message)),
                        });

                        let _ignore = replica.sender.send(r2r_message);
                    } else {
                        warn!(
                            "dropping message to {} with expired attestation {}: {}",
                            replica.sender.id(),
                            OptionDisplay(replica.attestation()),
                            message
                        );
                    }
                }
            }
        }
    }
}

//
// RemoteReplicaState impls
//

impl RemoteReplicaState {
    pub fn attestation(&self) -> Option<AttestationParameters> {
        self.sender.attestation()
    }

    fn check_attestation_time(&self, now: Duration) -> bool {
        let min_unix_timestamp = now.checked_sub(ATTESTATION_EXPIRATION_WINDOW).unwrap_or_default();
        let min_attestation = AttestationParameters::new(min_unix_timestamp);
        self.attestation() >= Some(min_attestation)
    }
}

impl fmt::Display for RemoteReplicaState {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { sender } = self;
        write!(fmt, "({}, {})", sender, OptionDisplay(sender.attestation()))
    }
}
