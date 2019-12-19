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

use std::sync::*;

use futures::prelude::*;
use futures::{try_ready};
use ::hyper::client::connect::{Connect, Connected, Destination};
use log::{warn, debug, log};
use tokio::net::{TcpStream};

use super::*;
use crate::child;
use crate::proxy_child::*;

pub struct TlsProxyConnector<T> {
    spawner:   Arc<TlsClientProxySpawner>,
    connector: T,
}

pub struct TlsProxyConnecting<T: Connect> {
    spawner: Arc<TlsClientProxySpawner>,
    connect: T::Future,
}

impl<T> TlsProxyConnector<T> {
    pub fn new(spawner: Arc<TlsClientProxySpawner>, connector: T) -> Self {
        Self { spawner, connector }
    }
}

impl<T> Connect for TlsProxyConnector<T>
where T:         Connect<Transport = TcpStream>,
      T::Future: Send,
      io::Error: From<<T::Future as Future>::Error>,
{
    type Transport = TlsProxyStream;
    type Error     = io::Error;
    type Future    = TlsProxyConnecting<T>;

    fn connect(&self, dst: Destination) -> Self::Future {
        Self::Future {
            spawner: Arc::clone(&self.spawner),
            connect: self.connector.connect(dst),
        }
    }
}

impl<T> Future for TlsProxyConnecting<T>
where T:         Connect<Transport = TcpStream>,
      io::Error: From<T::Error>,
{
    type Item  = (TlsProxyStream, Connected);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let (tcp_stream, _info) = try_ready!(self.connect.poll());
        let peer_addr           = tcp_stream.peer_addr()?;
        let (stdio, stderr)     = self.spawner.spawn(tcp_stream, peer_addr)?.into_streams()?;

        tokio::spawn(log_proxy_stderr(stderr, peer_addr));

        Ok(Async::Ready((stdio, Connected::new())))
    }
}

fn log_proxy_stderr(stderr_stream: TlsProxyStderrStream, address: SocketAddr) -> impl Future<Item = (), Error = ()> {
    let logger = stderr_stream.for_each(move |line: String| {
        let (mut log_level, line) = child::logger::parse_line(&line);
        // we don't want noisy INFO logs for hyper
        if log_level == log::Level::Info {
            log_level = log::Level::Debug;
        }
        log!(target: "kbuptlsd::child", log_level, "{} => {}", address, line);
        Ok(())
    });
    logger.then(move |result: Result<(), io::Error>| {
        match result {
            Ok(()) => {
                debug!("{} => child process died", address);
                Ok(())
            }
            Err(error) => {
                warn!("{} => error reading from child stderr: {}", address, error);
                Err(())
            }
        }
    })
}
