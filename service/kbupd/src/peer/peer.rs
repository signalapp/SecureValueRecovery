//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use futures::prelude::*;
use tokio::net::tcp::{ConnectFuture, TcpStream};
use tokio::timer;

use super::connection::*;
use super::manager::*;
use crate::metrics::*;
use crate::protobufs::kbupd::*;
use crate::tls::*;
use crate::*;

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(60 * 5);

pub struct Peer {
    node_id:          NodeId,
    address:          Option<String>,
    our_hello:        Arc<RwLock<PeerConnectionHello>>,
    tls_client:       TlsClient,
    enclave_tx:       EnclaveManagerSender,
    enclave_name:     Arc<str>,
    state:            PeerState,
    state_counter:    CounterGuard,
    rx:               actor::Receiver<Peer>,
    pending_outgoing: VecDeque<OutgoingPeerMessage>,
    next_outgoing_id: u64,
    next_incoming_id: u64,
}

enum PeerState {
    Disconnected,
    Waiting {
        delay:     timer::Delay,
        max_delay: Duration,
    },
    Connecting {
        connect:   ConnectFuture,
        address:   SocketAddr,
        max_delay: Duration,
    },
    Connected(PeerConnectedState),
}

struct PeerConnectedState {
    framed:    PeerFramed,
    queue:     VecDeque<Arc<PeerConnectionMessage>>,
    keepalive: Option<timer::Delay>,
    timeout:   timer::Delay,
}

struct OutgoingPeerMessage {
    id:   u64,
    data: Arc<PeerConnectionMessage>,
}

//
// Peer impls
//

impl Future for Peer {
    type Error = util::Never;
    type Item = ();

    fn poll(&mut self) -> Result<Async<()>, util::Never> {
        loop {
            match self.inner_poll() {
                Ok(Async::Ready(())) => (),
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(()) => return Ok(Async::Ready(())),
            }
        }
    }
}

impl Peer {
    pub fn new(
        node_id: NodeId,
        address: Option<String>,
        our_hello: Arc<RwLock<PeerConnectionHello>>,
        tls_client: TlsClient,
        enclave_tx: EnclaveManagerSender,
        enclave_name: Arc<str>,
        connection: Option<PeerConnection>,
        rx: actor::Receiver<Peer>,
    ) -> Self
    {
        let mut new_self = Self {
            node_id,
            address,
            our_hello,
            tls_client,
            enclave_tx,
            enclave_name,
            state: PeerState::Disconnected,
            state_counter: PEERS_DISCONNECTED_COUNTER.guard(1),
            rx,
            pending_outgoing: Default::default(),
            next_outgoing_id: Default::default(),
            next_incoming_id: Default::default(),
        };
        if let Some(connection) = connection {
            new_self.accept_connection(None, connection);
        }
        new_self
    }

    pub fn accept_connection(&mut self, maybe_connect_address: Option<String>, connection: PeerConnection) {
        if let Some(connect_address) = maybe_connect_address {
            self.address = Some(connect_address);
        }
        let replace_connection = if let PeerState::Connected(_) = &self.state {
            // XXX this doesn't work with blackholed connection on non-initiator (when self.address is none)
            self.address.is_none() || self.node_id[..] > self.connection_hello().node_id[..]
        } else {
            true
        };
        if replace_connection {
            self.state = self.connected(connection);
        }
    }

    pub fn force_reconnect(&mut self, maybe_new_address: Option<String>) {
        self.state = PeerState::Disconnected;
        if let Some(new_address) = maybe_new_address {
            self.address = Some(new_address);
        }
    }

    pub fn disconnect(&mut self) {
        self.state = PeerState::Disconnected;
        self.address = None;
    }

    pub fn send_message(&mut self, data: Vec<u8>, syn: bool, debug_msg: Option<Vec<u8>>) {
        MESSAGES_PENDING_COUNT_COUNTER.inc(1);
        MESSAGES_PENDING_BYTES_COUNTER.inc(data.len() as u64);

        let id = self.next_outgoing_id;

        if syn {
            debug!("sending connect request {} to peer {}", id, &self.node_id);
        } else if let Some(debug_msg) = &debug_msg {
            debug!(
                "sending message {} to peer {}: {}",
                id,
                &self.node_id,
                String::from_utf8_lossy(debug_msg)
            );
        } else {
            debug!("sending message {} to peer {}", id, &self.node_id);
        }

        let message = OutgoingPeerMessage {
            id,
            data: Arc::new(PeerConnectionMessage {
                inner: Some(peer_connection_message::Inner::Data(PeerConnectionData { id, data, syn })),
            }),
        };

        if let PeerState::Connected(connected_state) = &mut self.state {
            connected_state.enqueue(message.data.clone());
        }
        self.pending_outgoing.push_back(message);
        self.next_outgoing_id = self.next_outgoing_id.checked_add(1).expect("peer message id limit");
    }

    fn connection_hello(&self) -> PeerConnectionHello {
        let our_hello_guard = match self.our_hello.read() {
            Ok(our_hello_guard) => our_hello_guard,
            Err(poison_error) => poison_error.into_inner(),
        };
        our_hello_guard.clone()
    }

    fn inner_poll(&mut self) -> Result<Async<()>, ()> {
        match self.rx.poll() {
            Ok(Async::Ready(Some(fun))) => {
                fun(self);
                return Ok(Async::Ready(()));
            }
            Ok(Async::NotReady) => (),
            Ok(Async::Ready(None)) | Err(()) => {
                warn!("dropping state for peer {}", &self.node_id);
                return Err(());
            }
        }

        match self.step() {
            Async::Ready(maybe_new_state) => {
                if let Some(new_state) = maybe_new_state {
                    self.state = new_state;
                }
                return Ok(Async::Ready(()));
            }
            Async::NotReady => (),
        }

        let state_counter = match &self.state {
            PeerState::Disconnected => &*PEERS_DISCONNECTED_COUNTER,
            PeerState::Waiting { .. } | PeerState::Connecting { .. } => &*PEERS_CONNECTING_COUNTER,
            PeerState::Connected(_) => &*PEERS_CONNECTED_COUNTER,
        };
        self.state_counter.update(state_counter);

        Ok(Async::NotReady)
    }

    fn step(&mut self) -> Async<Option<PeerState>> {
        match &mut self.state {
            PeerState::Disconnected => self.connect(CONNECT_RETRY_INITIAL_DELAY),
            PeerState::Waiting { delay, max_delay } => {
                let max_delay = *max_delay;
                match delay.poll() {
                    Ok(Async::Ready(_)) => self.connect(max_delay),
                    Ok(Async::NotReady) => Async::NotReady,
                    Err(timer_error) => {
                        error!("tokio timer error in reconnect: {}", timer_error);
                        self.connect(max_delay)
                    }
                }
            }
            PeerState::Connecting {
                connect,
                address,
                max_delay,
            } => {
                let max_delay = *max_delay;
                match connect.poll() {
                    Ok(Async::Ready(stream)) => match PeerConnection::connect_with_tcp_stream(stream, *address, &self.tls_client) {
                        Ok(connection) => {
                            let new_state = self.connected(connection);
                            Async::Ready(Some(new_state))
                        }
                        Err(connect_error) => {
                            warn!(
                                "error connecting to peer at {}: {}",
                                util::OptionDisplay(self.address.as_ref()),
                                connect_error
                            );
                            let new_state = self.waiting(max_delay);
                            Async::Ready(Some(new_state))
                        }
                    },
                    Ok(Async::NotReady) => Async::NotReady,
                    Err(connect_error) => {
                        warn!(
                            "error connecting to peer at {}: {}",
                            util::OptionDisplay(self.address.as_ref()),
                            connect_error
                        );
                        let new_state = self.waiting(max_delay);
                        Async::Ready(Some(new_state))
                    }
                }
            }
            PeerState::Connected(connected_state) => {
                match connected_state.flush_queue() {
                    Ok(Async::Ready(())) => return Async::Ready(None),
                    Ok(Async::NotReady) => (),
                    Err(write_error) => {
                        warn!("error writing to socket for peer {}: {}", &self.node_id, write_error);
                        return Async::Ready(Some(PeerState::Disconnected));
                    }
                }

                match connected_state.framed.poll() {
                    Ok(Async::Ready(None)) => {
                        info!("connection closed to peer {}", &self.node_id);
                        return Async::Ready(Some(PeerState::Disconnected));
                    }
                    Ok(Async::Ready(Some(message))) => {
                        connected_state.reschedule_timeout();
                        let maybe_new_state = self.handle_incoming_message(message);
                        return Async::Ready(maybe_new_state);
                    }
                    Ok(Async::NotReady) => (),
                    Err(read_error) => {
                        warn!("error reading from socket for peer {}: {}", &self.node_id, read_error);
                        return Async::Ready(Some(PeerState::Disconnected));
                    }
                }

                match connected_state.timeout.poll() {
                    Ok(Async::Ready(())) => {
                        warn!("connection timed out for peer {}", &self.node_id);
                        return Async::Ready(Some(PeerState::Disconnected));
                    }
                    Ok(Async::NotReady) => (),
                    Err(timer_error) => {
                        error!("tokio timer error with timeout timer for peer {}: {}", &self.node_id, timer_error);
                        connected_state.reschedule_timeout();
                    }
                }

                if let Some(keepalive) = &mut connected_state.keepalive {
                    match keepalive.poll() {
                        Ok(Async::Ready(())) => {
                            let keepalive = Arc::new(PeerConnectionMessage { inner: None });
                            connected_state.enqueue(keepalive);
                            return Async::Ready(None);
                        }
                        Ok(Async::NotReady) => (),
                        Err(timer_error) => {
                            error!("tokio timer error with keepalive timer for peer {}: {}", &self.node_id, timer_error);
                            connected_state.keepalive = None;
                        }
                    }
                }

                Async::NotReady
            }
        }
    }

    fn connect(&self, max_delay: Duration) -> Async<Option<PeerState>> {
        if let Some(address) = &self.address {
            info!("connecting to peer {} at {}", &self.node_id, address);
            match util::to_socket_addr(address) {
                Ok(socket_addr) => Async::Ready(Some(PeerState::Connecting {
                    connect: TcpStream::connect(&socket_addr),
                    address: socket_addr,
                    max_delay,
                })),
                Err(error) => {
                    error!("invalid address to connect to peer {}: {}", &self.node_id, error);
                    let new_state = self.waiting(max_delay);
                    Async::Ready(Some(new_state))
                }
            }
        } else {
            debug!("no address to connect to peer {}!", &self.node_id);
            Async::NotReady
        }
    }

    fn waiting(&self, max_delay: Duration) -> PeerState {
        let delay_duration = util::duration::random(max_delay);
        let delay = timer::Delay::new(Instant::now() + max_delay + delay_duration);
        let max_delay = (max_delay * 2).min(CONNECT_RETRY_MAXIMUM_DELAY);

        PeerState::Waiting { delay, max_delay }
    }

    fn connected(&self, connection: PeerConnection) -> PeerState {
        let mut connected_state = PeerConnectedState::new(connection.framed, 1 + self.pending_outgoing.len());
        if !connection.sent_hello {
            connected_state.enqueue(Arc::new(PeerConnectionMessage {
                inner: Some(peer_connection_message::Inner::Hello(self.connection_hello())),
            }));
        }
        match self.pending_outgoing.len() {
            0 => (),
            pending_outgoing_len => {
                info!(
                    "resending {} pending outgoing messages to peer {}",
                    pending_outgoing_len, &self.node_id
                );
            }
        }
        for pending_message in &self.pending_outgoing {
            connected_state.enqueue(pending_message.data.clone());
        }
        PeerState::Connected(connected_state)
    }

    fn handle_incoming_message(&mut self, message: PeerConnectionMessage) -> Option<PeerState> {
        match message.inner {
            Some(peer_connection_message::Inner::Hello(hello)) => {
                if hello.node_id[..] != self.node_id[..] {
                    warn!(
                        "reconnected to node {} at {} but found node {} instead!",
                        &self.node_id,
                        util::OptionDisplay(self.address.as_ref()),
                        &util::ToHex(&hello.node_id)
                    );
                    self.address = None;
                    Some(PeerState::Disconnected)
                } else {
                    None
                }
            }
            Some(peer_connection_message::Inner::DataAck(ack)) => {
                self.handle_incoming_data_ack(ack);
                None
            }
            Some(peer_connection_message::Inner::Data(message)) => {
                MESSAGES_RECEIVED_COUNT_METER.mark();
                MESSAGES_RECEIVED_BYTES_METER.inc(message.data.len() as u64);
                self.handle_incoming_data(message);
                None
            }
            None => {
                // keepalive
                None
            }
        }
    }

    fn handle_incoming_data(&mut self, message: PeerConnectionData) {
        let message_id = message.id;
        if message_id == self.next_incoming_id {
            debug!("received message {} from peer {}", message_id, &self.node_id);
            match self.send_incoming(message) {
                Ok(()) => self.next_incoming_id = self.next_incoming_id.checked_add(1).expect("peer message id limit"),
                Err(()) => {
                    warn!("error sending incoming message to enclave for peer {}", &self.node_id);
                }
            }
        }

        if message_id < self.next_incoming_id {
            if let PeerState::Connected(connected_state) = &mut self.state {
                let ack = Arc::new(PeerConnectionMessage {
                    inner: Some(peer_connection_message::Inner::DataAck(PeerConnectionDataAck { id: message_id })),
                });
                connected_state.enqueue(ack);
            }
        } else {
            warn!(
                "dropping message {} (expected {}) from peer {}",
                message_id, self.next_incoming_id, &self.node_id
            );
        }
    }

    fn handle_incoming_data_ack(&mut self, ack: PeerConnectionDataAck) {
        let mut acked_count: u64 = 0;
        let mut acked_bytes: u64 = 0;
        while let Some(pending_message) = self.pending_outgoing.front() {
            if pending_message.id <= ack.id {
                if let Some(pending_message) = self.pending_outgoing.pop_front() {
                    acked_count += 1;
                    if let Some(peer_connection_message::Inner::Data(pending_message_data)) = &pending_message.data.inner {
                        acked_bytes += pending_message_data.data.len() as u64;
                    }
                }
            } else {
                break;
            }
        }
        MESSAGES_PENDING_COUNT_COUNTER.dec(acked_count);
        MESSAGES_PENDING_BYTES_COUNTER.dec(acked_bytes);
    }

    fn send_incoming(&self, message: PeerConnectionData) -> Result<(), ()> {
        let peer_node_id = self.node_id.to_vec();
        let enclave_name = self.enclave_name.clone();
        self.enclave_tx
            .cast(|enclave_manager: &mut EnclaveManager| {
                enclave_manager.untrusted_message(enclave_name, UntrustedMessage {
                    inner: Some(untrusted_message::Inner::NewMessageSignal(NewMessageSignal {
                        node_id: peer_node_id,
                        data:    message.data,
                        syn:     message.syn,
                    })),
                })
            })
            .map_err(|_| ())
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let mut pending_bytes: u64 = 0;
        for pending_message in &self.pending_outgoing {
            if let Some(peer_connection_message::Inner::Data(pending_message_data)) = &pending_message.data.inner {
                pending_bytes += pending_message_data.data.len() as u64;
            }
        }
        MESSAGES_PENDING_COUNT_COUNTER.dec(self.pending_outgoing.len() as u64);
        MESSAGES_PENDING_BYTES_COUNTER.dec(pending_bytes);
    }
}

//
// PeerConnectedState impls
//

impl PeerConnectedState {
    fn new(framed: PeerFramed, queue_capacity: usize) -> Self {
        let now = Instant::now();
        let timeout = timer::Delay::new(now + INACTIVITY_TIMEOUT);
        let keepalive = Some(timer::Delay::new(now + KEEPALIVE_INTERVAL));
        let queue = VecDeque::with_capacity(queue_capacity);
        Self {
            framed,
            queue,
            keepalive,
            timeout,
        }
    }

    fn enqueue(&mut self, message: Arc<PeerConnectionMessage>) {
        self.queue.push_back(message);
        self.keepalive = None;
    }

    fn flush_queue(&mut self) -> Result<Async<()>, io::Error> {
        let () = futures::try_ready!(self.framed.poll_complete());

        let start_send_result = if let Some(message) = self.queue.pop_front() {
            match self.framed.start_send(message)? {
                AsyncSink::Ready => Async::Ready(()),
                AsyncSink::NotReady(message) => {
                    self.queue.push_front(message);
                    Async::NotReady
                }
            }
        } else {
            Async::NotReady
        };
        self.schedule_keepalive();
        Ok(start_send_result)
    }

    fn schedule_keepalive(&mut self) {
        if self.queue.is_empty() {
            if self.keepalive.is_none() {
                self.keepalive = Some(timer::Delay::new(Instant::now() + KEEPALIVE_INTERVAL));
            }
        } else {
            self.keepalive = None;
        }
    }

    fn reschedule_timeout(&mut self) {
        self.timeout = timer::Delay::new(Instant::now() + INACTIVITY_TIMEOUT);
    }
}
