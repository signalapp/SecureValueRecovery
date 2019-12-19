/*
 * Copyright (C) 2019 Open Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

use std::net::{ToSocketAddrs};
use std::path::{PathBuf};

use futures::prelude::*;
use kbuptlsd::prelude::*;

use crate::*;
use super::connection::*;
use super::manager::*;

pub struct PeerListener {
    manager_tx: PeerManagerSender,
    server:     TlsProxyListener,
}

impl PeerListener {
    pub fn new(bind_address: impl ToSocketAddrs, kbuptlsd_bin_path: PathBuf, max_connections: usize, tls_arguments: TlsProxyListenerArguments, manager_tx: PeerManagerSender) -> Result<Self, failure::Error> {
        let server = TlsProxyListener::new(bind_address, kbuptlsd_bin_path, max_connections, tls_arguments)?;
        Ok(Self {
            manager_tx,
            server,
        })
    }
    pub fn into_future(self) -> impl Future<Item = (), Error = ()> {
        let manager_tx  = self.manager_tx;
        let connections = self.server.into_stream().map_err(|error: failure::Error| {
            error!("error starting peer listener: {}", error);
        });

        connections.for_each(move |stream: TlsProxyStream| {
            info!("accepted peer connection from: {}", stream.peer_addr());

            let connection = PeerConnection::new(stream);

            manager_tx.cast(move |manager: &mut PeerManager| {
                manager.accept_connection(connection)
            })
        })
    }
}
