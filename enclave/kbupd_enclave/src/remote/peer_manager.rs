//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::collections::*;
use std::rc::*;

use hashbrown::{hash_map, HashMap};
use prost::Message;
use rand_core::RngCore;
use sgxsd_ffi::RdRand;

use crate::hasher::DefaultHasher;
use crate::kbupd_send;
use crate::protobufs::kbupd::*;
use crate::protobufs::kbupd_enclave::*;
use crate::remote::*;

pub struct PeerManager<T> {
    node_params:      Rc<NodeParams>,
    noise_buffers:    SharedNoiseBuffers,
    connecting_peers: BTreeSet<ConnectingPeerState>,
    qe_info_req:      QeInfoRequestState,
    peers:            HashMap<NodeId, Option<T>, DefaultHasher>,
    total_ticks:      u32,
}

pub struct PeerStarter<'a, T, U> {
    peer_entry:       hash_map::VacantEntry<'a, NodeId, Option<T>, DefaultHasher>,
    connecting_peers: &'a mut BTreeSet<ConnectingPeerState>,
    connecting_peer:  ConnectingPeerState,
    remote:           U,
}

pub struct PeerAcceptor<'a, T> {
    peer_entry:       hash_map::VacantEntry<'a, NodeId, Option<T>, DefaultHasher>,
    node_params:      Rc<NodeParams>,
    noise_buffers:    SharedNoiseBuffers,
    remote_node_type: NodeType,
    qe_info_req:      &'a mut QeInfoRequestState,
    connect_request:  PeerConnectRequest,
}

pub trait Peer {
    type Message;
    fn remote_mut(&mut self) -> &mut dyn Remote;
    fn recv(&mut self, msg_data: &[u8]) -> Result<Self::Message, RemoteRecvError>;
    fn send_quote_reply(&mut self, sgx_quote: EnclaveGetQuoteReply) -> Result<(), ()>;
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
struct ConnectingPeerState {
    next_timeout_tick:   u32,
    last_interval_ticks: u32,
    node_id:             NodeId,
}

enum QeInfoRequestState {
    None,
    Sent { needs_qe_info: Vec<NodeId>, ticks_elapsed: u32 },
}

impl<T> PeerManager<T>
where T: Peer
{
    pub fn new(node_type: NodeType) -> Self {
        Self {
            node_params:      Rc::new(NodeParams::generate(node_type)),
            noise_buffers:    Default::default(),
            connecting_peers: Default::default(),
            qe_info_req:      QeInfoRequestState::None,
            peers:            Default::default(),
            total_ticks:      Default::default(),
        }
    }

    pub fn our_node_id(&self) -> &NodeId {
        self.node_params.node_id()
    }

    pub fn get_peer(&self, node_id: &NodeId) -> Option<&T> {
        let peer = self.peers.get(node_id)?.as_ref()?;
        Some(peer)
    }

    pub fn get_peer_mut(&mut self, node_id: &NodeId) -> Option<&mut T> {
        let peer = self.peers.get_mut(node_id)?.as_mut()?;
        Some(peer)
    }

    pub fn remove_peer(&mut self, node_id: &NodeId) {
        if let hash_map::Entry::Occupied(mut peer_entry) = self.peers.entry(node_id.clone()) {
            if let Some(peer) = peer_entry.get_mut() {
                if let Some(_) = peer.remote_mut().attestation() {
                    *peer_entry.get_mut() = None;
                } else {
                    peer_entry.remove();
                }
            }
        }
    }

    pub fn timer_tick(&mut self, min_timeout_ticks: u32, max_timeout_ticks: u32) {
        self.total_ticks = self.total_ticks.wrapping_add(1);

        if let QeInfoRequestState::Sent { ticks_elapsed, .. } = &mut self.qe_info_req {
            *ticks_elapsed = ticks_elapsed.saturating_add(1);
            if *ticks_elapsed >= min_timeout_ticks {
                Self::send_get_qe_info_request();
                *ticks_elapsed = Default::default();
            }
        }

        let mut new_connecting_peers = BTreeSet::new();
        while let Some(mut connecting_peer) = self.take_connecting_peer() {
            if let Some(peer) = self.peers.get_mut(&connecting_peer.node_id).and_then(Option::as_mut) {
                let last_interval_ticks = connecting_peer.last_interval_ticks;
                let half_interval_ticks = last_interval_ticks.min(max_timeout_ticks / 2).max(min_timeout_ticks);
                let rand_interval_ticks = RdRand.next_u32().checked_rem(half_interval_ticks).unwrap_or(0);
                let next_timeout_ticks = half_interval_ticks.saturating_add(rand_interval_ticks);

                connecting_peer.last_interval_ticks = half_interval_ticks.saturating_add(half_interval_ticks);
                connecting_peer.next_timeout_tick = next_timeout_ticks.saturating_add(self.total_ticks.wrapping_add(1));
                match peer.remote_mut().connect() {
                    Ok(()) => {
                        info!(
                            "connecting to peer {} with retry in {} ticks, next interval {} ticks",
                            peer.remote_mut().id(),
                            next_timeout_ticks,
                            connecting_peer.last_interval_ticks
                        );
                        Self::get_qe_info(&mut self.qe_info_req, peer.remote_mut().id().clone());
                        new_connecting_peers.insert(connecting_peer);
                    }
                    Err(()) => (),
                }
            }
        }
        self.connecting_peers.append(&mut new_connecting_peers);
    }

    fn take_connecting_peer(&mut self) -> Option<ConnectingPeerState> {
        if let Some(connecting_peer) = self.connecting_peers.iter().next() {
            if connecting_peer.next_timeout_tick <= self.total_ticks {
                let connecting_peer = connecting_peer.clone();
                self.connecting_peers.remove(&connecting_peer);
                Some(connecting_peer)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn start_peer<'a, M, R>(
        &'a mut self,
        peer_node_id: NodeId,
        peer_node_type: NodeType,
        auth_type: RemoteAuthorizationType,
    ) -> Result<PeerStarter<'a, T, RemoteState<M, R>>, Option<&'a mut T>>
    where
        M: prost::Message + 'static,
        R: prost::Message + Default + 'static,
    {
        match self.peers.entry(peer_node_id) {
            hash_map::Entry::Occupied(peer_entry) => Err(peer_entry.into_mut().as_mut()),
            hash_map::Entry::Vacant(peer_entry) => {
                let remote = RemoteState::new(
                    Rc::clone(&self.node_params),
                    peer_entry.key().clone(),
                    peer_node_type,
                    auth_type,
                    self.noise_buffers.clone(),
                );
                let connecting_peer = ConnectingPeerState {
                    next_timeout_tick:   self.total_ticks.wrapping_add(1),
                    last_interval_ticks: 0,
                    node_id:             remote.id().clone(),
                };
                Ok(PeerStarter {
                    remote,
                    peer_entry,
                    connecting_peers: &mut self.connecting_peers,
                    connecting_peer,
                })
            }
        }
    }

    pub fn request_quote(&mut self, peer_node_id: NodeId) {
        Self::get_qe_info(&mut self.qe_info_req, peer_node_id);
    }

    fn get_qe_info(qe_info_req: &mut QeInfoRequestState, peer_node_id: NodeId) {
        if let QeInfoRequestState::None = qe_info_req {
            info!("requesting qe_info to generate quote for {}", peer_node_id);
            Self::send_get_qe_info_request();
            *qe_info_req = QeInfoRequestState::Sent {
                needs_qe_info: Default::default(),
                ticks_elapsed: Default::default(),
            };
        }
        if let QeInfoRequestState::Sent { needs_qe_info, .. } = qe_info_req {
            needs_qe_info.push(peer_node_id);
        } else {
            static_unreachable!();
        }
    }

    fn send_get_qe_info_request() {
        kbupd_send(EnclaveMessage {
            inner: Some(enclave_message::Inner::GetQeInfoRequest(GetQeInfoRequest {})),
        });
    }

    pub fn get_qe_info_reply(&mut self, get_qe_info_reply: GetQeInfoReply) {
        if let QeInfoRequestState::Sent { needs_qe_info, .. } = std::mem::replace(&mut self.qe_info_req, QeInfoRequestState::None) {
            info!("generating quotes for {} peers", needs_qe_info.len());
            for peer_node_id in needs_qe_info {
                if let Some(peer) = self.peers.get_mut(&peer_node_id).and_then(Option::as_mut) {
                    match peer.remote_mut().qe_info_reply(&get_qe_info_reply) {
                        Ok(get_quote_request) => {
                            kbupd_send(EnclaveMessage {
                                inner: Some(enclave_message::Inner::GetQuoteRequest(get_quote_request)),
                            });
                        }
                        Err(()) => (),
                    }
                }
            }
        }
    }

    pub fn get_quote_reply(&mut self, get_quote_reply: GetQuoteReply) {
        let peer_node_id = NodeId::from(&get_quote_reply.request_id);
        if let Some(peer) = self.peers.get_mut(&peer_node_id).and_then(Option::as_mut) {
            match peer.remote_mut().get_quote_reply(get_quote_reply) {
                Ok(Some(get_attestation_request)) => {
                    kbupd_send(EnclaveMessage {
                        inner: Some(enclave_message::Inner::GetAttestationRequest(get_attestation_request)),
                    });
                }
                Err(Some(enclave_get_quote_reply)) => {
                    let _ignore = peer.send_quote_reply(enclave_get_quote_reply);
                }
                Ok(None) => (),
                Err(None) => (),
            }
        }
    }

    pub fn request_attestation(&mut self, sgx_quote: Vec<u8>, peer_node_id: NodeId) {
        info!("fetching attestation for peer {}", &peer_node_id);
        kbupd_send(EnclaveMessage {
            inner: Some(enclave_message::Inner::GetAttestationRequest(GetAttestationRequest {
                request_id: peer_node_id.to_vec(),
                sgx_quote,
            })),
        });
    }

    #[must_use]
    pub fn get_attestation_reply(&mut self, get_attestation_reply: GetAttestationReply) -> Option<(&mut T, AttestationParameters)> {
        let peer_node_id: NodeId = get_attestation_reply.request_id.into();
        let peer = self.peers.get_mut(&peer_node_id)?.as_mut()?;
        match peer.remote_mut().attestation_reply(get_attestation_reply.ias_report) {
            Ok(Some(attestation)) => Some((peer, attestation)),
            Ok(None) => None,
            Err(()) => None,
        }
    }

    pub fn new_message_signal(&mut self, message: NewMessageSignal) -> Result<Option<(&mut T, <T as Peer>::Message)>, PeerAcceptor<'_, T>> {
        let peer_node_id: NodeId = message.node_id.into();

        if message.syn {
            let connect_request = match PeerConnectRequest::decode(&message.data[..]) {
                Ok(connect_request) => connect_request,
                Err(decode_error) => {
                    warn!("dropping connect request from {}: {}", &peer_node_id, decode_error);
                    return Ok(None);
                }
            };
            match self.peer_connect_request(connect_request, peer_node_id) {
                Some(peer_acceptor) => Err(peer_acceptor),
                None => Ok(None),
            }
        } else {
            match self.peer_message(message.data, peer_node_id) {
                Ok(result) => Ok(result),
                Err(()) => Ok(None),
            }
        }
    }

    fn peer_message(&mut self, message_data: Vec<u8>, peer_node_id: NodeId) -> Result<Option<(&mut T, <T as Peer>::Message)>, ()> {
        let peer_entry = self.peers.get_mut(&peer_node_id);
        if let Some(Some(peer)) = peer_entry {
            match peer.recv(&message_data) {
                Ok(message) => Ok(Some((peer, message))),
                Err(RemoteRecvError::NeedsAttestation(get_attestation_request)) => {
                    info!("fetching attestation for peer {}", &peer_node_id);
                    kbupd_send(EnclaveMessage {
                        inner: Some(enclave_message::Inner::GetAttestationRequest(get_attestation_request)),
                    });
                    Ok(None)
                }
                Err(RemoteRecvError::DecodeError) | Err(RemoteRecvError::InvalidState) => Err(()),
            }
        } else if let Some(None) = peer_entry {
            warn!("dropping message from evicted peer {}", &peer_node_id);
            Err(())
        } else {
            error!("dropping message from missing peer {}", &peer_node_id);
            Err(())
        }
    }

    fn peer_connect_request(&mut self, connect_request: PeerConnectRequest, peer_node_id: NodeId) -> Option<PeerAcceptor<'_, T>> {
        match self.peers.entry(peer_node_id) {
            hash_map::Entry::Occupied(mut peer_entry) => {
                if let Some(peer) = peer_entry.get_mut().as_mut() {
                    match peer.remote_mut().accept(connect_request) {
                        Ok(()) => {
                            Self::get_qe_info(&mut self.qe_info_req, peer_entry.key().clone());
                        }
                        Err(()) => (),
                    }
                } else {
                    warn!("dropping connect request from evicted peer {}", peer_entry.key());
                }
                None
            }
            hash_map::Entry::Vacant(peer_entry) => {
                if let Some(remote_node_type) = NodeType::from_i32(connect_request.node_type) {
                    Some(PeerAcceptor {
                        peer_entry,
                        node_params: Rc::clone(&self.node_params),
                        noise_buffers: self.noise_buffers.clone(),
                        remote_node_type,
                        qe_info_req: &mut self.qe_info_req,
                        connect_request,
                    })
                } else {
                    warn!(
                        "dropping connect request from {}: invalid node type {}",
                        peer_entry.key(),
                        connect_request.node_type
                    );
                    None
                }
            }
        }
    }
}

//
// PeerStarter impls
//

impl<'a, T, U> PeerStarter<'a, T, U>
where
    T: Peer,
    U: Remote,
{
    pub fn remote(&self) -> &U {
        &self.remote
    }

    pub fn connect<F>(mut self, mapper: F) -> Result<&'a mut T, (Self, F)>
    where F: FnOnce(U) -> T {
        match self.remote.connect() {
            Ok(()) => {
                self.connecting_peers.insert(self.connecting_peer);
                let peer = self.peer_entry.insert(Some(mapper(self.remote)));
                Ok(peer.as_mut().unwrap_or_else(|| unreachable!()))
            }
            Err(()) => Err((self, mapper)),
        }
    }

    pub fn insert(self, mapper: impl FnOnce(U) -> T) -> &'a mut T {
        self.peer_entry
            .insert(Some(mapper(self.remote)))
            .as_mut()
            .unwrap_or_else(|| unreachable!())
    }
}

//
// PeerAcceptor impls
//

impl<'a, T> PeerAcceptor<'a, T>
where T: Peer
{
    pub fn node_id(&self) -> &NodeId {
        self.peer_entry.key()
    }

    pub fn connect_request(&self) -> &PeerConnectRequest {
        &self.connect_request
    }

    pub fn accept<M, R>(self, mapper: impl FnOnce(RemoteState<M, R>) -> T, auth_type: RemoteAuthorizationType) -> Result<&'a mut T, ()>
    where
        M: prost::Message + 'static,
        R: prost::Message + Default + 'static,
    {
        let mut remote = RemoteState::new(
            Rc::clone(&self.node_params),
            self.peer_entry.key().clone(),
            self.remote_node_type,
            auth_type,
            self.noise_buffers,
        );
        remote.accept(self.connect_request)?;
        PeerManager::<T>::get_qe_info(self.qe_info_req, self.peer_entry.key().clone());
        let peer = self.peer_entry.insert(Some(mapper(remote)));
        Ok(peer.as_mut().unwrap_or_else(|| unreachable!()))
    }
}
