//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::collections::{hash_map, HashMap};
use std::convert::TryFrom;
use std::io;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures::prelude::*;
use futures::sync::oneshot;
use kbupd_macro::lazy_init;
use tokio::prelude::*;

use super::connection::*;
use super::peer::*;
use crate::metrics::*;
use crate::protobufs::kbupd::*;
use crate::tls::*;
use crate::*;

const PEER_HELLO_TIMEOUT: Duration = Duration::from_secs(60 * 3);

pub type PeerManagerSender = actor::Sender<PeerManager>;

pub struct PeerManager {
    self_tx:      PeerManagerSender,
    enclave_name: Arc<str>,
    enclave_tx:   EnclaveManagerSender,
    node_id:      NodeId,
    peers:        HashMap<NodeId, actor::Sender<Peer>>,
    source_peers: Vec<NodeId>,
    our_hello:    Arc<RwLock<PeerConnectionHello>>,
    tls_client:   TlsClient,
}

lazy_init! {
    fn init_metrics() {
        static ref MESSAGES_SENT_COUNT_METER:          Meter   = METRICS.metric(&metric_name!("messages", "sent", "count"));
        static ref MESSAGES_SENT_BYTES_METER:          Meter   = METRICS.metric(&metric_name!("messages", "sent", "bytes"));
        pub static ref MESSAGES_RECEIVED_COUNT_METER:  Meter   = METRICS.metric(&metric_name!("messages", "received", "count"));
        pub static ref MESSAGES_RECEIVED_BYTES_METER:  Meter   = METRICS.metric(&metric_name!("messages", "received", "bytes"));
        pub static ref MESSAGES_PENDING_COUNT_COUNTER: Counter = METRICS.metric(&metric_name!("messages", "pending", "count"));
        pub static ref MESSAGES_PENDING_BYTES_COUNTER: Counter = METRICS.metric(&metric_name!("messages", "pending", "bytes"));
        pub static ref PEERS_CONNECTED_COUNTER:        Counter = METRICS.metric(&metric_name!("peers", "connected"));
        pub static ref PEERS_CONNECTING_COUNTER:       Counter = METRICS.metric(&metric_name!("peers", "connecting"));
        pub static ref PEERS_DISCONNECTED_COUNTER:     Counter = METRICS.metric(&metric_name!("peers", "disconnected"));
    }
}

impl PeerManager {
    pub fn new(
        self_tx: PeerManagerSender,
        enclave_name: String,
        enclave_tx: EnclaveManagerSender,
        node_id: NodeId,
        tls_client: TlsClient,
    ) -> Self
    {
        init_metrics();
        let our_hello = Arc::new(RwLock::new(PeerConnectionHello {
            node_id:   node_id.to_vec(),
            partition: None,
        }));
        Self {
            self_tx,
            enclave_name: enclave_name.into(),
            enclave_tx,
            node_id,
            peers: Default::default(),
            source_peers: Default::default(),
            our_hello,
            tls_client,
        }
    }

    pub fn discover_peers(
        &mut self,
        addresses: Vec<String>,
        tls_client: &TlsClient,
        reply_tx: oneshot::Sender<Result<Vec<NodeId>, futures::Canceled>>,
    )
    {
        let mut peers = Vec::new();
        for address in addresses {
            info!("discovering peer at {}", &address);
            let self_tx = self.self_tx.clone();
            let our_hello = self.connection_hello();
            let tls_client = tls_client.clone();
            let reconnect_looper = ReconnectLooper::new(move || -> Box<dyn Future<Item = NodeId, Error = ()> + Send> {
                let connection = PeerConnection::connect(&address, tls_client);
                let sent_hello = connection.and_then(move |connection: PeerConnection| connection.send_hello(our_hello));
                let peer_hello = sent_hello.and_then(PeerConnection::read_hello);
                let address_2 = address.clone();
                let peer_hello = peer_hello.map_err(move |error: io::Error| {
                    warn!("error connecting to peer at {}: {}", address_2, error);
                });

                let peer_node_id = peer_hello.and_then(move |(peer_hello, connection): (PeerConnectionHello, PeerConnection)| {
                    let peer_node_id = NodeId::try_from(&peer_hello.node_id[..]).map_err(drop);
                    let _ignore = self_tx
                        .cast(move |peer_manager: &mut PeerManager| peer_manager.add_connection(Some(address), peer_hello, connection));
                    peer_node_id
                });
                Box::new(peer_node_id)
            });
            peers.push(reconnect_looper.into_future());
        }

        let our_node_id = self.node_id;
        let peer_node_ids = future::join_all(peers).map(move |peer_node_ids: Vec<NodeId>| {
            let peer_node_ids = peer_node_ids.into_iter().filter(|peer_node_id| peer_node_id != &our_node_id);
            peer_node_ids.collect::<Vec<NodeId>>()
        });

        let replied_future = peer_node_ids.then(|result: Result<Vec<NodeId>, ()>| {
            let result = result.map_err(|()| futures::Canceled);
            reply_tx.send(result).map_err(|_| ())
        });

        tokio::spawn(replied_future);
    }

    pub fn set_source_partition(&mut self, source_node_ids: Vec<NodeId>) {
        self.source_peers = source_node_ids;
    }

    pub fn set_partition_config(&mut self, partition: Option<PartitionConfig>) {
        let mut our_hello_guard = match self.our_hello.write() {
            Ok(our_hello_guard) => our_hello_guard,
            Err(poison_error) => poison_error.into_inner(),
        };
        *our_hello_guard = PeerConnectionHello {
            node_id: self.node_id.to_vec(),
            partition,
        };
    }

    pub fn force_reconnect(&self, peer_node_id: NodeId, maybe_new_address: Option<String>) {
        if let Some(peer_tx) = self.peers.get(&peer_node_id) {
            info!("forcibly reconnecting to peer {}", &peer_node_id);
            let _ignore = peer_tx.cast(move |peer: &mut Peer| peer.force_reconnect(maybe_new_address));
        }
    }

    pub fn disconnect(&self, peer_node_id: NodeId) {
        if let Some(peer_tx) = self.peers.get(&peer_node_id) {
            info!("disconnecting from peer {}", &peer_node_id);
            let _ignore = peer_tx.cast(|peer: &mut Peer| peer.disconnect());
        }
    }

    pub fn disconnect_permanently(&mut self, peer_node_id: NodeId) {
        if let Some(_peer_tx) = self.peers.remove(&peer_node_id) {
            info!("permanently disconnecting from peer {}", &peer_node_id);
        }
    }

    pub fn xfer_finished(&self) {
        for source_node_id in &self.source_peers {
            self.disconnect(*source_node_id);
        }
    }

    pub fn send_message(&mut self, message: SendMessageRequest) {
        MESSAGES_SENT_COUNT_METER.mark();
        MESSAGES_SENT_BYTES_METER.inc(message.data.len() as u64);

        let SendMessageRequest {
            node_id: peer_node_id,
            data,
            syn,
            debug_msg,
        } = message;

        let peer_node_id = match NodeId::try_from(&peer_node_id[..]) {
            Ok(peer_node_id) => peer_node_id,
            Err(_) => {
                error!("dropping message to invalid node id: {}", util::ToHex(&peer_node_id));
                return;
            }
        };

        let peer_tx = match self.peers.entry(peer_node_id) {
            hash_map::Entry::Occupied(peer_entry) => peer_entry.into_mut(),
            hash_map::Entry::Vacant(peer_entry) => {
                let (peer_tx, peer_rx) = actor::channel();
                let peer = Peer::new(
                    peer_entry.key().clone().into(),
                    None,
                    self.our_hello.clone(),
                    self.tls_client.clone(),
                    self.enclave_tx.clone(),
                    self.enclave_name.clone(),
                    None,
                    peer_rx,
                );
                tokio::spawn(peer.map_err(|never: util::Never| match never {}));
                warn!("waiting for peer {} with unknown address to connect", peer_entry.key());
                peer_entry.insert(peer_tx)
            }
        };

        let _ignore = peer_tx.cast(move |peer: &mut Peer| peer.send_message(data, syn, debug_msg));
    }

    pub fn accept_connection(&mut self, connection: PeerConnection) {
        let self_tx = self.self_tx.clone();
        let peer_addr = connection.framed.get_ref().peer_addr();

        let sent_hello = connection.send_hello(self.connection_hello());
        let peer_hello = sent_hello.and_then(PeerConnection::read_hello);

        let connection_started = peer_hello.map(move |(hello, connection): (PeerConnectionHello, PeerConnection)| {
            let _ignore = self_tx.cast(move |peer_manager: &mut PeerManager| peer_manager.add_connection(None, hello, connection));
        });

        let connection_started = connection_started.timeout(PEER_HELLO_TIMEOUT);
        let connection_started = connection_started.map_err(move |error: tokio::timer::timeout::Error<io::Error>| {
            if error.is_elapsed() {
                info!("timeout accepting connection from {}", peer_addr);
            } else {
                warn!("error accepting connection from {}: {}", peer_addr, error);
            }
        });

        tokio::spawn(connection_started);
    }

    pub fn add_connection(&mut self, maybe_address: Option<String>, peer_hello: PeerConnectionHello, connection: PeerConnection) {
        let peer_node_id = match NodeId::try_from(&peer_hello.node_id[..]) {
            Ok(peer_node_id) if peer_node_id != self.node_id => peer_node_id,
            Ok(_) => return,
            Err(_) => {
                error!("invalid node id from peer: {}", util::ToHex(&peer_hello.node_id));
                return;
            }
        };
        if let Some(peer_address) = &maybe_address {
            info!("connected to peer {} at {}", &peer_node_id, peer_address);
        } else {
            let peer_socket_addr = connection.framed.get_ref().peer_addr();
            info!("accepted connection from peer {} at {}", &peer_node_id, peer_socket_addr);
        }

        match self.peers.entry(peer_node_id) {
            hash_map::Entry::Occupied(peer_entry) => {
                let _ignore = peer_entry
                    .get()
                    .cast(|peer: &mut Peer| peer.accept_connection(maybe_address, connection));
            }
            hash_map::Entry::Vacant(peer_entry) => {
                let (peer_tx, peer_rx) = actor::channel();
                let peer = Peer::new(
                    peer_entry.key().clone().into(),
                    maybe_address,
                    self.our_hello.clone(),
                    self.tls_client.clone(),
                    self.enclave_tx.clone(),
                    self.enclave_name.clone(),
                    Some(connection),
                    peer_rx,
                );
                tokio::spawn(peer.map_err(|never: util::Never| match never {}));
                peer_entry.insert(peer_tx);
            }
        }
    }

    fn connection_hello(&self) -> PeerConnectionHello {
        let our_hello_guard = match self.our_hello.read() {
            Ok(our_hello_guard) => our_hello_guard,
            Err(poison_error) => poison_error.into_inner(),
        };
        our_hello_guard.clone()
    }
}
