//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::convert::TryInto;
use std::io;
use std::marker::PhantomData;
use std::net::ToSocketAddrs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::{Buf, BufMut, BytesMut, IntoBuf};
use failure::{format_err, ResultExt};
use futures::future;
use futures::prelude::*;
use futures::sync::mpsc;
use kbupd_api::entities::*;
use tk_listen::ListenExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_codec::Decoder;

use crate::metrics::*;
use crate::peer::manager::*;
use crate::protobufs::kbupd::*;
use crate::*;

const LISTEN_RETRY_DELAY: Duration = Duration::from_secs(5);

pub struct ControlListener {
    enclave_tx: EnclaveManagerSender,
    listener:   TcpListener,
}

impl ControlListener {
    pub fn new(bind_address: impl ToSocketAddrs, enclave_tx: EnclaveManagerSender) -> io::Result<Self> {
        let listener = TcpListener::bind(&util::to_socket_addr(bind_address)?)?;
        Ok(Self { enclave_tx, listener })
    }

    pub fn into_future(self) -> impl Future<Item = (), Error = ()> {
        let Self { enclave_tx, listener } = self;
        let connections = listener.incoming().sleep_on_error(LISTEN_RETRY_DELAY);

        connections.for_each(move |stream: TcpStream| {
            match stream.peer_addr() {
                Ok(socket_addr) => info!("accepted control connection from {}", socket_addr),
                Err(_) => info!("accepted control connection from unknown address"),
            }

            let _ignore = stream.set_nodelay(true);

            tokio::spawn(
                ControlConnection {
                    enclave_tx: enclave_tx.clone(),
                    stream,
                }
                .into_future(),
            );
            Ok(())
        })
    }
}

pub struct ControlConnection {
    enclave_tx: EnclaveManagerSender,
    stream:     TcpStream,
}

impl ControlConnection {
    pub fn into_future(self) -> impl Future<Item = (), Error = ()> {
        let Self { enclave_tx, stream } = self;

        let stream_peer_addr = match stream.peer_addr() {
            Ok(socket_addr) => socket_addr.to_string(),
            Err(_) => "unknown_address".to_string(),
        };

        let (sink, stream) = DaemonControlCodec::new().framed(stream).split();
        let (sink_tx, sink_rx) = mpsc::unbounded();

        let sink_future = sink_rx
            .map_err(|()| io::Error::from(io::ErrorKind::BrokenPipe))
            .forward(sink)
            .map(|_| ());

        let stream_future = stream.for_each(move |request: ControlRequest| {
            let reply_tx = sink_tx.clone();
            let future = handle_control_command(request, &enclave_tx).map(move |reply: ControlReply| {
                let _ignore = reply_tx.unbounded_send(reply);
            });
            tokio::spawn(future);
            Ok(())
        });

        let joined_future = sink_future.join(stream_future);

        joined_future.then(move |result: Result<_, io::Error>| {
            if let Err(error) = result {
                warn!("error in control connection at {}: {}", stream_peer_addr, error);
            } else {
                info!("control connection closed at {}", stream_peer_addr);
            }
            Ok(())
        })
    }
}

fn handle_control_command(
    request: ControlRequest,
    enclave_tx: &EnclaveManagerSender,
) -> Box<dyn Future<Item = ControlReply, Error = ()> + Send>
{
    let request_id = request.id;
    match request.data {
        Some(control_request::Data::GetStatusControlRequest(request)) => {
            let result = enclave_tx.call(|enclave_manager: &mut EnclaveManager, reply_tx| enclave_manager.get_status(request, reply_tx));

            let reply = result.then(move |result: Result<GetStatusControlReply, failure::Error>| {
                let reply_data = match result {
                    Ok(reply) => control_reply::Data::GetStatusControlReply(reply),
                    Err(error) => control_reply::Data::ControlErrorSignal(ControlErrorSignal {
                        reason: format!("{}", error),
                    }),
                };
                Ok(ControlReply {
                    id:   request_id,
                    data: Some(reply_data),
                })
            });

            Box::new(reply)
        }
        Some(control_request::Data::NegotiateClientRequest(mut negotiate_client_request)) => {
            debug!("got negotiate client request: {:?}", negotiate_client_request);

            let enclave_name = std::mem::replace(&mut negotiate_client_request.enclave_name, String::new());

            let request = match into_attestation_request(negotiate_client_request) {
                Ok(request) => request,
                Err(error) => {
                    let reply = ControlReply {
                        id:   request_id,
                        data: Some(control_reply::Data::ControlErrorSignal(ControlErrorSignal {
                            reason: format!("{}", error),
                        })),
                    };
                    return Box::new(Ok(reply).into_future());
                }
            };

            let result = enclave_tx
                .call(|enclave_manager: &mut EnclaveManager, reply_tx| enclave_manager.remote_attestation(enclave_name, request, reply_tx));
            let reply = result.then(move |result: Result<RemoteAttestationResponse, RemoteAttestationError>| {
                let reply_data = match result {
                    Ok(response) => control_reply::Data::NegotiateClientReply(NegotiateClientReply {
                        server_ephemeral_pubkey:      response.serverEphemeralPublic.to_vec(),
                        server_static_pubkey:         response.serverStaticPublic.to_vec(),
                        encrypted_pending_request_id: ClientEncryptedMessage {
                            iv:   response.iv.to_vec(),
                            mac:  response.tag.to_vec(),
                            data: response.ciphertext,
                        },
                    }),
                    Err(error) => control_reply::Data::ControlErrorSignal(ControlErrorSignal {
                        reason: format!("{}", error),
                    }),
                };
                Ok(ControlReply {
                    id:   request_id,
                    data: Some(reply_data),
                })
            });

            Box::new(reply)
        }
        Some(control_request::Data::ClientEncryptedRequest(mut client_encrypted_request)) => {
            debug!("got client request: {:?}", client_encrypted_request);

            let enclave_name = std::mem::replace(&mut client_encrypted_request.enclave_name, String::new());
            let backup_id = match client_encrypted_request.backup_id[..].try_into() {
                Ok(backup_id) => backup_id,
                Err(_) => {
                    let reply = ControlReply {
                        id:   request_id,
                        data: Some(control_reply::Data::ControlErrorSignal(ControlErrorSignal {
                            reason: format!("invalid backup id: {}", util::ToHex(&client_encrypted_request.backup_id)),
                        })),
                    };
                    return Box::new(Ok(reply).into_future());
                }
            };

            let request = match parse_client_request(client_encrypted_request) {
                Ok(request) => request,
                Err(error) => {
                    let reply = ControlReply {
                        id:   request_id,
                        data: Some(control_reply::Data::ControlErrorSignal(ControlErrorSignal {
                            reason: format!("{}", error),
                        })),
                    };
                    return Box::new(Ok(reply).into_future());
                }
            };

            let result = enclave_tx.call(move |enclave_manager: &mut EnclaveManager, reply_tx| {
                enclave_manager.key_backup(enclave_name, backup_id, request, reply_tx)
            });

            let reply = result.then(move |result: Result<KeyBackupResponse, KeyBackupError>| {
                let reply_data = match result {
                    Ok(key_backup_response) => control_reply::Data::ClientEncryptedReply(ClientEncryptedReply {
                        encrypted_message: ClientEncryptedMessage {
                            iv:   key_backup_response.iv.to_vec(),
                            mac:  key_backup_response.mac.to_vec(),
                            data: key_backup_response.data,
                        },
                    }),
                    Err(error) => control_reply::Data::ControlErrorSignal(ControlErrorSignal {
                        reason: format!("{}", error),
                    }),
                };
                Ok(ControlReply {
                    id:   request_id,
                    data: Some(reply_data),
                })
            });

            Box::new(reply)
        }
        Some(control_request::Data::TransactionControlRequest(mut transaction_control_request)) => {
            debug!("got transaction control request: {:?}", transaction_control_request);

            let enclave_name = std::mem::replace(&mut transaction_control_request.enclave_name, String::new());

            let result = if let Some(transaction_control_request_data) = transaction_control_request.data {
                let untrusted_transaction_request = match transaction_control_request_data {
                    transaction_control_request::Data::CreateBackupRequest(request) => {
                        untrusted_transaction_request::Data::CreateBackupRequest(request)
                    }
                    transaction_control_request::Data::DeleteBackupRequest(request) => {
                        untrusted_transaction_request::Data::DeleteBackupRequest(request)
                    }
                };
                let result = enclave_tx.call(|enclave_manager: &mut EnclaveManager, reply_tx| {
                    enclave_manager.transaction(enclave_name, untrusted_transaction_request, reply_tx)
                });
                future::Either::A(result)
            } else {
                future::Either::B(Err(EnclaveTransactionError::InvalidInput).into_future())
            };

            let reply = result.then(move |result: Result<untrusted_transaction_reply::Data, EnclaveTransactionError>| {
                let reply_data = match result {
                    Ok(untrusted_transaction_reply) => {
                        let transaction_control_reply_data = match untrusted_transaction_reply {
                            untrusted_transaction_reply::Data::CreateBackupReply(request) => {
                                transaction_control_reply::Data::CreateBackupReply(request)
                            }
                            untrusted_transaction_reply::Data::DeleteBackupReply(request) => {
                                transaction_control_reply::Data::DeleteBackupReply(request)
                            }
                        };
                        control_reply::Data::TransactionControlReply(TransactionControlReply {
                            data: Some(transaction_control_reply_data),
                        })
                    }
                    Err(error) => control_reply::Data::ControlErrorSignal(ControlErrorSignal {
                        reason: format!("{}", error),
                    }),
                };
                Ok(ControlReply {
                    id:   request_id,
                    data: Some(reply_data),
                })
            });

            Box::new(reply)
        }
        Some(control_request::Data::ForcePeerReconnectRequest(request)) => {
            let enclave_name = request.enclave_name.unwrap_or(String::new());
            let peer_node_id = parse_node_id(&request.node_id);
            let peer_address = request.address;

            let reset_peer_message = UntrustedMessage {
                inner: Some(untrusted_message::Inner::ResetPeerSignal(ResetPeerSignal {
                    peer_node_id: request.node_id,
                })),
            };

            let result = enclave_tx.call(|enclave_manager: &mut EnclaveManager, reply_tx| {
                enclave_manager.untrusted_message(enclave_name.clone(), reset_peer_message)?;
                enclave_manager.get_peer_manager(enclave_name, reply_tx)
            });

            let reply = result.then(move |result: Result<Option<PeerManagerSender>, futures::Canceled>| {
                if let Ok(Some(peer_manager_tx)) = result {
                    if let Some(peer_node_id) = peer_node_id {
                        let _ignore = peer_manager_tx
                            .cast(move |peer_manager: &mut PeerManager| peer_manager.force_reconnect(peer_node_id, peer_address));
                    }
                }
                Ok(ControlReply {
                    id:   request_id,
                    data: None,
                })
            });

            Box::new(reply)
        }
        Some(control_request::Data::PeerDisconnectRequest(request)) => {
            let enclave_name = request.enclave_name.unwrap_or(String::new());
            let peer_node_id = parse_node_id(&request.node_id);

            let result =
                enclave_tx.call(|enclave_manager: &mut EnclaveManager, reply_tx| enclave_manager.get_peer_manager(enclave_name, reply_tx));

            let reply = result.then(move |result: Result<Option<PeerManagerSender>, futures::Canceled>| {
                if let Ok(Some(peer_manager_tx)) = result {
                    if let Some(peer_node_id) = peer_node_id {
                        let _ignore = peer_manager_tx.cast(move |peer_manager: &mut PeerManager| peer_manager.disconnect(peer_node_id));
                    }
                }
                Ok(ControlReply {
                    id:   request_id,
                    data: None,
                })
            });

            Box::new(reply)
        }
        Some(control_request::Data::PeerPermanentDeleteRequest(request)) => {
            let enclave_name = request.enclave_name.unwrap_or(String::new());
            let peer_node_id = parse_node_id(&request.node_id);

            let result =
                enclave_tx.call(|enclave_manager: &mut EnclaveManager, reply_tx| enclave_manager.get_peer_manager(enclave_name, reply_tx));

            let reply = result.then(move |result: Result<Option<PeerManagerSender>, futures::Canceled>| {
                if let Ok(Some(peer_manager_tx)) = result {
                    if let Some(peer_node_id) = peer_node_id {
                        let _ignore =
                            peer_manager_tx.cast(move |peer_manager: &mut PeerManager| peer_manager.disconnect_permanently(peer_node_id));
                    }
                }
                Ok(ControlReply {
                    id:   request_id,
                    data: None,
                })
            });

            Box::new(reply)
        }
        Some(control_request::Data::XferControlRequest(xfer_control_request)) => {
            info!("got xfer control request: {:?}", xfer_control_request);

            let enclave_name = xfer_control_request.enclave_name.clone().unwrap_or_default();
            let xfer_command = XferControlCommand::from_i32(xfer_control_request.xfer_control_command).unwrap_or_default();

            let result = enclave_tx
                .call(move |enclave_manager: &mut EnclaveManager, reply_tx| enclave_manager.xfer(enclave_name, xfer_command, reply_tx));

            let reply = result.then(move |result: Result<XferControlReply, failure::Error>| {
                let reply_data = match result {
                    Ok(xfer_control_reply) => control_reply::Data::XferControlReply(xfer_control_reply),
                    Err(error) => control_reply::Data::ControlErrorSignal(ControlErrorSignal {
                        reason: format!("{}", error),
                    }),
                };
                Ok(ControlReply {
                    id:   request_id,
                    data: Some(reply_data),
                })
            });

            Box::new(reply)
        }
        Some(control_request::Data::GetMetricsControlRequest(_request)) => {
            let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(duration) => duration.as_secs(),
                Err(time_error) => {
                    warn!("couldn't determine current time: {}", time_error);
                    0
                }
            };

            let metrics_report = SubmitMetricsRequest::from_registry(
                &METRICS,
                "localhost",
                "local",
                &None,
                "kbupctl",
                now);

            let encoded_report = match serde_json::to_string(&metrics_report) {
                Ok(encoded_request) => encoded_request,
                Err(serde_error) => {
                    warn!("error encoding json metrics: {}", serde_error);
                    Default::default()
                }
            };
            let reply_data = control_reply::Data::GetMetricsControlReply(GetMetricsControlReply {
                metrics_json: encoded_report,
            });
            Box::new(
                Ok(ControlReply {
                    id:   request_id,
                    data: Some(reply_data),
                })
                .into_future(),
            )
        }
        None => {
            let reply = ControlReply {
                id:   request_id,
                data: None,
            };
            Box::new(Ok(reply).into_future())
        }
    }
}

fn parse_node_id(node_id_bytes: &[u8]) -> Option<NodeId> {
    match node_id_bytes.try_into() {
        Ok(node_id) => Some(node_id),
        Err(_) => {
            error!("invalid node id in control request: {}", util::ToHex(node_id_bytes));
            None
        }
    }
}

fn parse_client_request(request: ClientEncryptedRequest) -> Result<KeyBackupRequest, failure::Error> {
    let request_type = match ClientRequestType::from_i32(request.request_type) {
        Some(ClientRequestType::Backup) => KeyBackupRequestType::Backup,
        Some(ClientRequestType::Restore) => KeyBackupRequestType::Restore,
        Some(ClientRequestType::Delete) => KeyBackupRequestType::Delete,
        Some(ClientRequestType::None) | None => {
            return Err(format_err!("invalid client request type: {}", request.request_type));
        }
    };
    Ok(KeyBackupRequest {
        iv:        request.encrypted_message.iv[..]
            .try_into()
            .map_err(failure::Error::from)
            .context("iv")?,
        mac:       request.encrypted_message.mac[..]
            .try_into()
            .map_err(failure::Error::from)
            .context("mac")?,
        data:      request.encrypted_message.data,
        requestId: request.pending_request_id,
        r#type:    request_type,
    })
}

fn into_attestation_request(negotiate_client_request: NegotiateClientRequest) -> Result<RemoteAttestationRequest, failure::Error> {
    Ok(RemoteAttestationRequest {
        clientPublic: negotiate_client_request.client_pubkey[..]
            .try_into()
            .map_err(failure::Error::from)
            .context("negotiate_client client_pubkey")?,
    })
}

type DaemonControlCodec = ControlCodec<ControlReply, ControlRequest>;

pub struct ControlCodec<O, I> {
    _io: (PhantomData<O>, PhantomData<I>),
}
impl<O, I> ControlCodec<O, I> {
    pub fn new() -> Self {
        Self { _io: Default::default() }
    }
}
impl<O, I: prost::Message + Default> tokio_codec::Decoder for ControlCodec<O, I> {
    type Error = tokio::io::Error;
    type Item = I;

    fn decode(&mut self, buffer: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buffer.len() < 4 {
            return Ok(None);
        }

        let frame_length = buffer[..].into_buf().get_u32_be() as usize;
        let frame_remaining = frame_length.saturating_sub(buffer.len() - 4);
        if frame_remaining != 0 {
            buffer.reserve(frame_remaining + 4);
            return Ok(None);
        }

        buffer.advance(4);
        let data = buffer.split_to(frame_length);
        let frame = Self::Item::decode(&data)?;
        Ok(Some(frame))
    }
}
impl<O: prost::Message, I> tokio_codec::Encoder for ControlCodec<O, I> {
    type Error = tokio::io::Error;
    type Item = O;

    fn encode(&mut self, frame: Self::Item, output: &mut BytesMut) -> Result<(), Self::Error> {
        let frame_len = match frame.encoded_len() {
            frame_len if frame_len > u32::max_value() as usize - 4 => {
                return Err(tokio::io::Error::new(
                    tokio::io::ErrorKind::InvalidInput,
                    "control message size limit",
                ));
            }
            frame_len => frame_len as u32,
        };
        output.reserve(4 + frame_len as usize);
        output.put_u32_be(frame_len);
        frame.encode(output)?;
        Ok(())
    }
}
