//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future;
use futures::prelude::*;
use kbuptlsd::prelude::*;
use tokio::net::TcpStream;
use tokio::timer;
use tokio_codec::{Decoder, Framed};
use try_future::try_future;

use super::codec::*;
use crate::protobufs::kbupd::*;
use crate::tls::*;
use crate::*;

pub const CONNECT_RETRY_INITIAL_DELAY: Duration = Duration::from_millis(200);
pub const CONNECT_RETRY_MAXIMUM_DELAY: Duration = Duration::from_secs(15);

pub type PeerFramed = Framed<TlsProxyStream, PeerCodec>;

pub struct PeerConnection {
    pub framed:     PeerFramed,
    pub sent_hello: bool,
}

impl PeerConnection {
    pub fn new(stream: TlsProxyStream) -> Self {
        let framed = PeerCodec.framed(stream);
        Self { framed, sent_hello: false }
    }

    pub fn connect(address: &str, tls_client: TlsClient) -> impl Future<Item = Self, Error = io::Error> {
        let socket_addr = try_future!(util::to_socket_addr(address));
        let stream = TcpStream::connect(&socket_addr);
        let framed = stream.and_then(move |stream: TcpStream| Self::connect_with_tcp_stream(stream, socket_addr, &tls_client));
        framed.into()
    }

    pub fn connect_with_tcp_stream(stream: TcpStream, address: SocketAddr, tls_client: &TlsClient) -> io::Result<Self> {
        let _ignore = stream.set_nodelay(true);
        let tls_stream = tls_client.spawn(stream, address)?;

        Ok(PeerConnection::new(tls_stream))
    }

    pub fn send_hello(self, our_hello: PeerConnectionHello) -> impl Future<Item = Self, Error = io::Error> {
        let Self { framed, sent_hello: _ } = self;

        let framed = framed.send(Arc::new(PeerConnectionMessage {
            inner: Some(peer_connection_message::Inner::Hello(our_hello)),
        }));
        let connection = framed.map(move |framed: PeerFramed| Self { framed, sent_hello: true });
        connection
    }

    pub fn read_hello(self) -> impl Future<Item = (PeerConnectionHello, Self), Error = io::Error> {
        let Self { framed, sent_hello } = self;

        let maybe_message = framed.into_future().map_err(|(error, _framed): (io::Error, PeerFramed)| error);
        let connection =
            maybe_message.and_then(
                move |(maybe_message, framed): (Option<PeerConnectionMessage>, PeerFramed)| match maybe_message {
                    Some(PeerConnectionMessage {
                        inner: Some(peer_connection_message::Inner::Hello(peer_hello)),
                    }) => Ok((peer_hello, Self { framed, sent_hello })),
                    Some(message) => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("first message on peer connection not a hello: {:?}", message),
                    )),
                    None => Err(io::Error::new(io::ErrorKind::Other, "eof before connection hello")),
                },
            );
        connection
    }
}

pub struct ReconnectLooper<F>
where F: Send + Clone
{
    connect_fn: F,
    max_delay:  Duration,
}

impl<F, Fut, T> ReconnectLooper<F>
where
    F: FnOnce() -> Fut + Send + Clone,
    Fut: Future<Item = T, Error = ()>,
{
    pub fn new(connect_fn: F) -> Self {
        Self {
            connect_fn,
            max_delay: CONNECT_RETRY_INITIAL_DELAY,
        }
    }

    pub fn into_future(self) -> impl Future<Item = T, Error = ()> {
        future::loop_fn(self, Self::connect)
    }

    fn connect(self) -> impl Future<Item = future::Loop<T, Self>, Error = ()> {
        let connect_result = (self.connect_fn.clone())();
        let loop_result = connect_result.then(|result: Result<T, ()>| match result {
            Ok(result) => future::Either::A(Ok(future::Loop::Break(result)).into_future()),
            Err(()) => {
                let delay_timer = timer::Delay::new(Instant::now() + util::duration::random(self.max_delay));
                let loop_result = delay_timer.map(|()| {
                    future::Loop::Continue(Self {
                        max_delay: (self.max_delay * 2).min(CONNECT_RETRY_MAXIMUM_DELAY),
                        ..self
                    })
                });
                future::Either::B(loop_result)
            }
        });

        loop_result.map_err(|error: timer::Error| {
            error!("tokio timer error: {}", error);
        })
    }
}
