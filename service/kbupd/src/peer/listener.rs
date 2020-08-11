//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::net::ToSocketAddrs;
use std::path::PathBuf;

use futures::prelude::*;
use kbuptlsd::prelude::*;

use super::connection::*;
use super::manager::*;
use crate::*;

pub struct PeerListener {
    manager_tx: PeerManagerSender,
    server:     TlsProxyListener,
}

impl PeerListener {
    pub fn new(
        bind_address: impl ToSocketAddrs,
        kbuptlsd_bin_path: PathBuf,
        max_connections: usize,
        tls_arguments: TlsProxyListenerArguments,
        manager_tx: PeerManagerSender,
    ) -> Result<Self, failure::Error>
    {
        let server = TlsProxyListener::new(bind_address, kbuptlsd_bin_path, max_connections, tls_arguments)?;
        Ok(Self { manager_tx, server })
    }

    pub fn into_future(self) -> impl Future<Item = (), Error = ()> {
        let manager_tx = self.manager_tx;
        let connections = self.server.into_stream().map_err(|error: failure::Error| {
            error!("error starting peer listener: {}", error);
        });

        connections.for_each(move |stream: TlsProxyStream| {
            info!("accepted peer connection from: {}", stream.peer_addr());

            let connection = PeerConnection::new(stream);

            manager_tx.cast(move |manager: &mut PeerManager| manager.accept_connection(connection))
        })
    }
}
