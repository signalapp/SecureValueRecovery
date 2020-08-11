//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use crate::prelude::*;

use std::collections::*;
use std::fmt;
use std::rc::*;

use rand_core::RngCore;
use sgxsd_ffi::RdRand;

use crate::protobufs::kbupd::*;
use crate::protobufs::kbupd_enclave::*;
use crate::protobufs::raft::*;
use crate::remote::*;
use crate::util::*;

pub trait RemoteGroupPendingRequest {
    type RequestId: Clone + Ord + Eq;
    type Message: prost::Message;
    fn request_id(&self) -> &Self::RequestId;
    fn message(&self) -> Rc<Self::Message>;
    fn min_attestation(&self) -> Option<AttestationParameters>;
}

pub trait RemoteGroupNode {
    fn request_quote(&mut self, request: EnclaveGetQuoteRequest) -> Result<(), ()>;
}

pub struct RemoteGroupState<T, R>
where R: RemoteGroupPendingRequest
{
    name:    String,
    nodes:   Box<[RemoteGroupNodeState<T, R::RequestId>]>,
    leader:  Option<usize>,
    term:    TermId,
    pending: BTreeMap<R::RequestId, PendingRequestState<R>>,

    timeout_ticks:       u32,
    request_quote_ticks: u32,
    total_ticks:         u32,
}

pub enum RemoteGroupSendError<R> {
    NotYetValid(R),
    AlreadySent(R),
}

struct PendingRequestState<R> {
    request:      R,
    sent_at_tick: u32,
}

//
// RemoteGroupState impls
//

struct RemoteGroupNodeState<T, RequestId> {
    remote:    T,
    last_sent: Option<RequestId>,
}

impl<T, R> RemoteGroupState<T, R>
where
    T: RemoteMessageSender<Message = R::Message> + 'static,
    T: RemoteGroupNode,
    R: RemoteGroupPendingRequest + 'static,
{
    pub fn new(name: String, remotes: Vec<T>) -> Self {
        let nodes = remotes.into_iter().map(|remote: T| RemoteGroupNodeState {
            remote,
            last_sent: Default::default(),
        });
        Self {
            name,
            nodes: nodes.collect::<Vec<_>>().into(),
            leader: Default::default(),
            term: Default::default(),
            pending: Default::default(),

            timeout_ticks: Default::default(),
            request_quote_ticks: Default::default(),
            total_ticks: Default::default(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn trim_to(&mut self, trim_to_len: usize, ttl_ticks: u32) -> impl DoubleEndedIterator<Item = R> + ExactSizeIterator {
        let mut maybe_trim_key: Option<&R::RequestId> = None;
        if let Some(trim_count) = self.pending.len().checked_sub(trim_to_len) {
            for (pending_request_id, pending_request) in self.pending.iter().take(trim_count) {
                if self.total_ticks.checked_sub(pending_request.sent_at_tick) < Some(ttl_ticks) {
                    break;
                }
                maybe_trim_key = Some(pending_request_id);
            }
        }
        let trimmed = if let Some(trim_key) = maybe_trim_key {
            let split_off = if let Some((new_first_key, _)) = self.pending.range(trim_key..).nth(1) {
                let new_first_key = new_first_key.clone();
                self.pending.split_off(&new_first_key)
            } else {
                BTreeMap::new()
            };
            std::mem::replace(&mut self.pending, split_off)
        } else {
            BTreeMap::new()
        };

        trimmed
            .into_iter()
            .map(|(_, pending_request_state): (_, PendingRequestState<R>)| pending_request_state.request)
    }

    pub fn reset_peer(&mut self, node_id: &NodeId) {
        match self.get_node_mut(node_id) {
            Some(from_node) => {
                from_node.last_sent = Default::default();
            }
            None => return,
        }
        warn!("resetting group {} peer {}", &self.name, node_id);
        let maybe_old_leader = self
            .leader
            .and_then(|leader: usize| self.nodes.get(leader))
            .map(|leader: &RemoteGroupNodeState<T, _>| leader.remote.id());

        if maybe_old_leader == Some(node_id) {
            self.leader = None;
            self.choose_leader();
        }
        self.flush_requests();
    }

    pub fn contains_authorized_node(&self, node_id: &NodeId) -> bool {
        if let Some(node) = self.get_node(node_id) {
            node.remote.attestation().is_some()
        } else {
            false
        }
    }

    pub fn status(&self) -> Vec<EnclavePeerStatus> {
        let mut statuses = Vec::with_capacity(self.nodes.len());
        for (node_idx, node) in self.nodes.iter().enumerate() {
            let unsent_requests = if let Some(last_sent) = &node.last_sent {
                self.pending.range(last_sent..).count().saturating_sub(1)
            } else {
                self.pending.len()
            };
            let inflight_requests = self.pending.len().saturating_sub(unsent_requests);
            statuses.push(EnclavePeerStatus {
                node_id:            node.remote.id().to_vec(),
                attestation:        node.remote.attestation(),
                replication_status: None,
                is_leader:          Some(node_idx) == self.leader,
                unsent_requests:    unsent_requests.to_u64(),
                inflight_requests:  inflight_requests.to_u64(),
            })
        }
        statuses
    }

    fn get_node_mut(&mut self, node_id: &NodeId) -> Option<&mut RemoteGroupNodeState<T, R::RequestId>> {
        self.nodes.iter_mut().find_map(
            |node: &mut RemoteGroupNodeState<T, _>| {
                if node.remote.id() == node_id { Some(node) } else { None }
            },
        )
    }

    fn get_node(&self, node_id: &NodeId) -> Option<&RemoteGroupNodeState<T, R::RequestId>> {
        self.nodes.iter().find_map(
            |node: &RemoteGroupNodeState<T, _>| {
                if node.remote.id() == node_id { Some(node) } else { None }
            },
        )
    }

    fn get_leader_node(&self) -> Option<&RemoteGroupNodeState<T, R::RequestId>> {
        if let Some(leader) = &self.leader {
            self.nodes.get(*leader)
        } else {
            None
        }
    }

    pub fn timer_tick(&mut self, max_timeout_ticks: u32, max_request_quote_ticks: u32) {
        self.timeout_ticks = self.timeout_ticks.saturating_add(1);
        self.request_quote_ticks = self.request_quote_ticks.saturating_add(1);
        self.total_ticks = self.total_ticks.wrapping_add(1);
        if self.timeout_ticks >= max_timeout_ticks {
            self.timeout_ticks = Default::default();

            if !self.pending.is_empty() {
                if let Some(leader) = self.get_leader_node() {
                    info!("group {} timeout on leader {}", &self.name, leader.remote.id());
                    self.leader = None;
                }
                self.choose_leader();
            }
        }
        if self.request_quote_ticks >= max_request_quote_ticks {
            self.request_quote_ticks = Default::default();

            for node in &mut self.nodes[..] {
                let _ignore = node.remote.request_quote(EnclaveGetQuoteRequest {});
            }
        }
    }

    pub fn remote_authorized(&mut self, node_id: &NodeId) {
        if self.get_node(node_id).is_some() {
            self.choose_leader();
        }
    }

    pub fn remote_not_leader(&mut self, term: TermId, maybe_new_leader: Option<&NodeId>, from_node_id: &NodeId) {
        match self.get_node_mut(from_node_id) {
            Some(from_node) => {
                from_node.last_sent = Default::default();
            }
            None => return,
        }
        let nodes = &self.nodes[..];

        let maybe_old_leader = self
            .leader
            .and_then(|leader: usize| nodes.get(leader))
            .map(|leader: &RemoteGroupNodeState<T, _>| leader.remote.id());
        if term >= self.term {
            self.term = term;
            // prevent re-send storm from a node responding NotLeader while contradictorily asserting itself as leader
            if let Some(new_leader) = maybe_new_leader.filter(|new_leader: &&NodeId| new_leader != &from_node_id) {
                if Some(new_leader) != maybe_old_leader {
                    info!("group {} changed leader to {} at term {}", &self.name, new_leader, &self.term.id);
                    self.leader = nodes
                        .iter()
                        .position(|node: &RemoteGroupNodeState<T, _>| node.remote.id() == new_leader);
                }
            } else if let Some(old_leader) = maybe_old_leader {
                info!("group {} lost leader {} at term {}", &self.name, old_leader, &self.term.id);
                self.leader = None;
            }
        } else if let Some(old_leader) = maybe_old_leader {
            if old_leader == from_node_id {
                info!("group {} lost leader {} at term {}", &self.name, old_leader, &self.term.id);
                self.leader = None;
            }
        }
        self.flush_requests();
    }

    pub fn send(&mut self, request: R) -> Result<(), RemoteGroupSendError<R>> {
        let request_id = request.request_id().clone();
        let message = request.message();

        if Some(&request_id) < self.pending.keys().last() {
            return Err(RemoteGroupSendError::AlreadySent(request));
        }

        let nodes = &mut self.nodes[..];
        let maybe_authorized_leader = self
            .leader
            .and_then(|leader: usize| nodes.get_mut(leader))
            .filter(|leader: &&mut RemoteGroupNodeState<T, _>| leader.remote.attestation().is_some());
        if let btree_map::Entry::Vacant(pending_request_entry) = self.pending.entry(request_id) {
            let sent_at_tick = self.total_ticks;
            if let Some(authorized_leader) = maybe_authorized_leader {
                if request.min_attestation() <= authorized_leader.remote.attestation() {
                    authorized_leader.send(message);
                    authorized_leader.mark_sent(Some(request.request_id()));
                    pending_request_entry.insert(PendingRequestState { request, sent_at_tick });
                    Ok(())
                } else {
                    Err(RemoteGroupSendError::NotYetValid(request))
                }
            } else {
                pending_request_entry.insert(PendingRequestState { request, sent_at_tick });
                Ok(())
            }
        } else {
            Err(RemoteGroupSendError::AlreadySent(request))
        }
    }

    pub fn handle_reply(&mut self, request_id: &R::RequestId) -> Option<R> {
        self.timeout_ticks = Default::default();
        self.pending
            .remove(request_id)
            .map(|request_state: PendingRequestState<R>| request_state.request)
    }

    pub fn get_remotes(&self) -> Vec<NodeId> {
        self.nodes[..]
            .iter()
            .map(|node: &RemoteGroupNodeState<T, _>| node.remote.id().clone())
            .collect()
    }

    #[allow(clippy::indexing_slicing, clippy::integer_arithmetic)]
    fn choose_leader(&mut self) {
        if self.get_leader_node().is_none() {
            let mut nodes: Vec<usize> = (0..self.nodes.len()).collect();
            for nodes_idx in 0..nodes.len() {
                let rand = (RdRand.next_u32().to_usize()) % (self.nodes.len() - nodes_idx);
                nodes.swap(nodes_idx, nodes_idx.wrapping_add(rand));

                let node_idx = nodes[nodes_idx];
                let node = &self.nodes[node_idx];
                if (node.remote.attestation().is_some() && self.has_unsent_to(node)) {
                    self.leader = Some(node_idx);
                    self.timeout_ticks = Default::default();
                    info!("group {} chose random leader {}", &self.name, node.remote.id());
                    break;
                }
            }
        }
        self.flush_requests();
    }

    fn flush_requests(&mut self) {
        let nodes = &mut self.nodes[..];
        let maybe_authorized_leader = self
            .leader
            .and_then(|leader: usize| nodes.get_mut(leader))
            .filter(|leader: &&mut RemoteGroupNodeState<T, _>| leader.remote.attestation().is_some());
        if let Some(authorized_leader) = maybe_authorized_leader {
            let mut queue = Vec::new();
            let mut not_yet_valid_count: u64 = 0;
            let mut last_sent_request_id: Option<&R::RequestId> = None;
            for pending_request in self.pending.values_mut() {
                if !authorized_leader.has_sent(&pending_request.request) {
                    if pending_request.request.min_attestation() <= authorized_leader.remote.attestation() {
                        last_sent_request_id = Some(pending_request.request.request_id());
                        queue.push(pending_request.request.message());
                    } else {
                        not_yet_valid_count += 1;
                    }
                }
            }
            if not_yet_valid_count > 0 {
                info!(
                    "group {} not sending {} messages to new leader {} due to attestation timestamp {}",
                    &self.name,
                    not_yet_valid_count,
                    authorized_leader.remote.id(),
                    OptionDisplay(authorized_leader.remote.attestation().as_ref())
                );
            }
            if !queue.is_empty() {
                info!(
                    "group {} resending {} messages to new leader {}",
                    &self.name,
                    queue.len(),
                    authorized_leader.remote.id()
                );
                for message in queue {
                    authorized_leader.send(message);
                }
            }
            authorized_leader.mark_sent(last_sent_request_id);
        }
    }

    fn has_unsent_to(&self, node: &RemoteGroupNodeState<T, R::RequestId>) -> bool {
        if let Some(last_request) = self.pending.values().last() {
            !node.has_sent(&last_request.request)
        } else {
            true
        }
    }
}

impl<T, RequestId> RemoteGroupNodeState<T, RequestId>
where
    T: RemoteMessageSender + 'static,
    RequestId: Clone + Ord + Eq,
{
    fn send(&self, request: Rc<T::Message>) {
        let _ignore = self.remote.send(request);
    }

    fn mark_sent(&mut self, sent_request_id: Option<&RequestId>) {
        if sent_request_id > self.last_sent.as_ref() {
            self.last_sent = sent_request_id.cloned();
        }
    }

    fn has_sent<R>(&self, request: &R) -> bool
    where R: RemoteGroupPendingRequest<RequestId = RequestId> + 'static {
        Some(request.request_id()) <= self.last_sent.as_ref()
    }
}

impl<T, R> fmt::Display for RemoteGroupState<T, R>
where
    T: RemoteMessageSender<Message = R::Message> + RemoteGroupNode + 'static,
    R: RemoteGroupPendingRequest + 'static,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("RemoteGroupState")
            .field("name", &self.name)
            .field("nodes", &ListDisplay(self.nodes.iter().map(|node| node.remote.id())))
            .field("leader", &OptionDisplay(self.get_leader_node().map(|node| node.remote.id())))
            .field("term", &DisplayAsDebug(self.term))
            .finish()
    }
}

impl<R> fmt::Display for RemoteGroupSendError<R> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            RemoteGroupSendError::AlreadySent(_) => "AlreadySent",
            RemoteGroupSendError::NotYetValid(_) => "NotYetValid",
        };
        write!(fmt, "{}", name)
    }
}
