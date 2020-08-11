//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::io;

use futures::future;
use futures::future::Loop;
use futures::prelude::*;
use futures::stream;

use super::connection::*;
use super::manager::*;
use crate::protobufs::kbupd::*;
use crate::tls::*;
use crate::*;

#[must_use]
pub struct PartitionPeerDiscovery {
    range:      Option<PartitionKeyRangePb>,
    addresses:  Vec<String>,
    connecting: Vec<Box<dyn Future<Item = DiscoveredPeer, Error = ()> + Send>>,
    connected:  Vec<DiscoveredPeer>,
}

struct DiscoveredPeer {
    address:    String,
    peer_hello: PeerConnectionHello,
    connection: PeerConnection,
}

impl PartitionPeerDiscovery {
    pub fn new(range: Option<PartitionKeyRangePb>, addresses: Vec<String>, tls_client: &TlsClient) -> Self {
        info!(
            "discovering peers for partition with range {} and peers {}",
            util::OptionDisplay(range.as_ref()),
            util::ListDisplay(&addresses)
        );

        let mut connecting = Vec::new();
        for address in addresses.iter().cloned() {
            let tls_client = tls_client.clone();
            let reconnect_looper = ReconnectLooper::new(move || {
                let address_2 = address.clone();
                let connection = PeerConnection::connect(&address, tls_client);
                let peer_hello = connection.and_then(|connection: PeerConnection| connection.read_hello());
                let peer_hello = peer_hello.map_err(move |error: io::Error| {
                    warn!("error connecting to peer at {}: {}", address_2, error);
                });
                let discovered_peer = peer_hello.map(|(peer_hello, connection): (PeerConnectionHello, PeerConnection)| DiscoveredPeer {
                    address,
                    peer_hello,
                    connection,
                });
                discovered_peer
            });

            let connection: Box<dyn Future<Item = _, Error = _> + Send> = Box::new(reconnect_looper.into_future());
            connecting.push(connection);
        }

        Self {
            range,
            addresses,
            connecting,
            connected: Default::default(),
        }
    }

    pub fn discover(self) -> impl Future<Item = (PartitionConfig, Self), Error = ()> + Send + 'static {
        future::loop_fn(self, Self::discover_loop)
    }

    fn discover_loop(self) -> impl Future<Item = Loop<(PartitionConfig, Self), Self>, Error = ()> + Send + 'static {
        let Self {
            range,
            addresses,
            connecting,
            mut connected,
        } = self;

        let connection = future::select_all(connecting);
        let maybe_partition = connection.then(move |connection_result: Result<(DiscoveredPeer, usize, Vec<_>), _>| {
            let (discovered_peer, _index, connecting) = match connection_result {
                Ok(ok) => ok,
                Err(_) => {
                    error!("peer discovery failed for partition: {}", util::ListDisplay(&addresses));
                    return Err(());
                }
            };

            let peer_hello = discovered_peer.peer_hello.clone();
            let peer_address = discovered_peer.address.clone();

            connected.push(discovered_peer);

            match peer_hello.partition {
                Some(mut partition) => {
                    let node_ids = partition.node_ids.iter().map(|node_id: &Vec<u8>| util::ToHex(node_id));
                    info!(
                        "discovered group {} from {} with range {} and nodes {}",
                        util::ToHex(&partition.group_id),
                        peer_address,
                        util::OptionDisplay(partition.range.as_ref()),
                        util::ListDisplay(node_ids)
                    );
                    if partition.range != range {
                        warn!(
                            "group {} reported differing range {} than expected {}",
                            util::ToHex(&partition.group_id),
                            util::OptionDisplay(partition.range.as_ref()),
                            util::OptionDisplay(range.as_ref())
                        );
                        partition.range = range.clone();
                    }
                    Ok(Loop::Break((partition, Self {
                        range,
                        addresses,
                        connecting,
                        connected,
                    })))
                }
                None => {
                    info!("discovered no group from {}", peer_address);
                    if !connecting.is_empty() {
                        Ok(Loop::Continue(Self {
                            range,
                            addresses,
                            connecting,
                            connected,
                        }))
                    } else {
                        error!("discovered no groups from all replicas!");
                        Err(())
                    }
                }
            }
        });
        maybe_partition
    }

    #[must_use]
    pub fn finish(self, peer_manager_tx: PeerManagerSender) -> impl Future<Item = (), Error = ()> {
        let connections_rest = stream::futures_unordered(self.connecting);
        let connections = Box::new(connections_rest.select(stream::iter_ok(self.connected)));

        connections.for_each(move |discovered_peer: DiscoveredPeer| {
            let _ignore = peer_manager_tx.cast(|peer_manager: &mut PeerManager| {
                peer_manager.add_connection(
                    Some(discovered_peer.address),
                    discovered_peer.peer_hello,
                    discovered_peer.connection,
                );
            });
            Ok(())
        })
    }
}
