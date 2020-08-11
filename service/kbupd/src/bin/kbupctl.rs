//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::collections::*;
use std::convert::TryInto;
use std::io;
use std::str::FromStr;

use failure::ResultExt;
use futures::future;
use futures::prelude::*;
use futures::stream::SplitSink;
use futures::sync::mpsc;
use futures::sync::oneshot;
use kbupd::protobufs::kbupd::*;
use kbupd::*;
use kbupd_util::{hex, ToHex};
use log::*;
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::net::TcpStream;
use tokio_codec::Decoder;

type ControlCodec = kbupd::ControlCodec<ControlRequest, ControlReply>;
type ControlFramed = tokio_codec::Framed<TcpStream, ControlCodec>;

fn main() -> Result<(), failure::Error> {
    let arguments = parse_arguments();

    let (subcommand_name, subcommand_arguments) = arguments.subcommand();
    let subcommand_arguments = subcommand_arguments.unwrap();

    let connect_address = arguments.value_of("connect_address").unwrap_or_default();
    let debug = arguments.is_present("debug");
    let enclave_name = subcommand_arguments.value_of("enclave_name").map(str::to_string);

    let log_level = if debug { log::Level::Debug } else { log::Level::Info };
    let (logger, logger_guard) = logger::Logger::new_with_guard(log_level);
    log::set_boxed_logger(Box::new(logger))?;
    log::set_max_level(log_level.to_level_filter());

    let connect_future = TcpStream::connect(&kbupd_util::to_socket_addr(connect_address)?)
        .map(|stream: TcpStream| {
            let _ignore = stream.set_nodelay(true);
            ControlCodec::new().framed(stream)
        })
        .map_err(|error: io::Error| {
            error!("error connecting: {}", error);
        });

    match subcommand_name {
        "info" | "status" => {
            let print_fun = match subcommand_name {
                "info" => print_info,
                "status" => print_status,
                _ => unreachable!(),
            };
            let control_request = ControlRequest {
                id:   Default::default(),
                data: Some(control_request::Data::GetStatusControlRequest(GetStatusControlRequest {
                    memory_status: subcommand_arguments.is_present("detailed_memory_status"),
                })),
            };
            let connection = connect_future
                .and_then(move |framed: ControlFramed| {
                    daemon_call(framed, control_request).map_err(|error: io::Error| {
                        error!("error sending command: {}", error);
                    })
                })
                .map(move |(reply, _framed): (ControlReply, ControlFramed)| {
                    if let Some(control_reply::Data::GetStatusControlReply(reply)) = reply.data {
                        print_fun(enclave_name, reply);
                    } else {
                        error!("error fetching status: {:?}", reply.data);
                    }
                });
            tokio::run(connection);
        }
        "metrics" => {
            let control_request = ControlRequest {
                id:   Default::default(),
                data: Some(control_request::Data::GetMetricsControlRequest(GetMetricsControlRequest {})),
            };
            let connection = connect_future
                .and_then(move |framed: ControlFramed| {
                    daemon_call(framed, control_request).map_err(|error: io::Error| {
                        error!("error sending command: {}", error);
                    })
                })
                .map(move |(reply, _framed): (ControlReply, ControlFramed)| {
                    if let Some(control_reply::Data::GetMetricsControlReply(reply)) = reply.data {
                        println!("{}", &reply.metrics_json);
                    } else {
                        error!("error fetching status: {:?}", reply.data);
                    }
                });
            tokio::run(connection);
        }
        "xfer" => {
            let (xfer_subcommand_name, xfer_subcommand_arguments) = subcommand_arguments.subcommand();
            let _xfer_subcommand_arguments = xfer_subcommand_arguments.unwrap();
            let xfer_control_command = match xfer_subcommand_name {
                "start" => XferControlCommand::Start,
                "pause" => XferControlCommand::Pause,
                "resume" => XferControlCommand::Resume,
                "finish" => XferControlCommand::Finish,
                _ => panic!("No subcommand"),
            };

            let control_request = ControlRequest {
                id:   Default::default(),
                data: Some(control_request::Data::XferControlRequest(XferControlRequest {
                    enclave_name,
                    xfer_control_command: xfer_control_command as i32,
                })),
            };

            let connection = connect_future
                .and_then(move |framed: ControlFramed| {
                    daemon_call(framed, control_request).map_err(|error: io::Error| {
                        error!("error sending command: {}", error);
                    })
                })
                .map(move |(reply, _framed): (ControlReply, ControlFramed)| {
                    let result = match reply.data {
                        Some(control_reply::Data::XferControlReply(reply)) => match UntrustedXferReplyStatus::from_i32(reply.status) {
                            Some(UntrustedXferReplyStatus::Ok) => Ok(()),
                            Some(UntrustedXferReplyStatus::NotLeader) => Err("not_leader"),
                            Some(UntrustedXferReplyStatus::InvalidState) => Err("invalid_state"),
                            Some(UntrustedXferReplyStatus::Unknown) | None => Err("unknown"),
                        },
                        _ => Err("unknown"),
                    };
                    match result {
                        Ok(()) => println!("ok"),
                        Err(status) => {
                            println!("{}", status);
                            error!("error fetching info: {}", status);
                        }
                    }
                });
            tokio::run(connection);
        }
        "reconnect-peer" => {
            let peer_node_id = hex::parse(subcommand_arguments.value_of("peer_node_id").unwrap())?;
            let peer_address = subcommand_arguments.value_of("peer_address");
            let control_request = ControlRequest {
                id:   Default::default(),
                data: Some(control_request::Data::ForcePeerReconnectRequest(ForcePeerReconnectRequest {
                    enclave_name,
                    node_id: peer_node_id,
                    address: peer_address.map(str::to_string),
                })),
            };
            let connection = connect_future
                .and_then(move |framed: ControlFramed| {
                    daemon_call(framed, control_request).map_err(|error: io::Error| {
                        error!("error sending command: {}", error);
                    })
                })
                .map(|(reply, _framed): (ControlReply, ControlFramed)| {
                    if reply.data.is_some() {
                        error!("error forcing reconnect: {:?}", reply.data);
                    }
                });
            tokio::run(connection);
        }
        "disconnect-peer" => {
            let peer_node_id = hex::parse(subcommand_arguments.value_of("peer_node_id").unwrap())?;
            let control_request = ControlRequest {
                id:   Default::default(),
                data: Some(control_request::Data::PeerDisconnectRequest(PeerDisconnectRequest {
                    enclave_name,
                    node_id: peer_node_id,
                })),
            };
            let connection = connect_future
                .and_then(move |framed: ControlFramed| {
                    daemon_call(framed, control_request).map_err(|error: io::Error| {
                        error!("error sending command: {}", error);
                    })
                })
                .map(|(reply, _framed): (ControlReply, ControlFramed)| {
                    if reply.data.is_some() {
                        error!("error forcing disconnect: {:?}", reply.data);
                    }
                });
            tokio::run(connection);
        }
        "client" => {
            let (client_subcommand_name, client_subcommand_arguments) = subcommand_arguments.subcommand();
            let client_subcommand_arguments = client_subcommand_arguments.unwrap();

            let request = ClientRequestParameters {
                enclave_name: enclave_name.unwrap_or_default(),
                subcommand:   client_subcommand_name.to_string(),
                service_id:   parse_argument(client_subcommand_arguments.value_of("service_id"), hex::parse)?,
                maybe_token:  parse_argument(client_subcommand_arguments.value_of("request_token"), hex::parse)?,
                backup_id:    parse_argument(client_subcommand_arguments.value_of("backup_id"), hex::parse)?,
                backup_data:  parse_argument(client_subcommand_arguments.value_of("backup_data"), hex::parse)?,
                backup_pin:   parse_argument(client_subcommand_arguments.value_of("backup_pin"), hex::parse)?,
                backup_tries: parse_argument(client_subcommand_arguments.value_of("backup_tries"), u32::from_str)?,
                valid_from:   parse_argument(client_subcommand_arguments.value_of("request_valid_from"), u64::from_str)?.unwrap_or(0),
            };

            let count = u64::from_str(client_subcommand_arguments.value_of("request_count").unwrap_or_default())?;
            let max_parallel = parse_argument(client_subcommand_arguments.value_of("max_parallel"), u64::from_str)?.unwrap_or(count);

            let connection = connect_future.and_then(move |framed: ControlFramed| {
                let (request_tx, request_rx) = mpsc::unbounded();
                let request_tx = ControlClientSender { request_tx };
                tokio::spawn(control_client(framed, request_rx));
                let future_count = count.min(max_parallel);
                let futures = (0..future_count).map(|request_id: u64| {
                    let request_tx = request_tx.clone();
                    let request = request.clone();
                    futures::future::loop_fn(request_id, move |request_id: u64| {
                        info!("request {}", request_id);
                        let future: Box<dyn Future<Item = (), Error = ()> + Send + 'static> = match request.subcommand.as_str() {
                            "create" => {
                                let create_backup_request = transaction_control_request::Data::CreateBackupRequest(CreateBackupRequest {
                                    backup_id: BackupId {
                                        id: unwrap_or_random_bytes(32, request.backup_id.clone()),
                                    },
                                });
                                let future = send_transaction_request(
                                    request_tx.clone(),
                                    request.enclave_name.clone(),
                                    request_id,
                                    create_backup_request,
                                )
                                .map(|_reply| ());
                                Box::new(future)
                            }
                            "delete" => {
                                let delete_backup_request = transaction_control_request::Data::DeleteBackupRequest(DeleteBackupRequest {
                                    backup_id: BackupId {
                                        id: unwrap_or_random_bytes(32, request.backup_id.clone()),
                                    },
                                });
                                let future = send_transaction_request(
                                    request_tx.clone(),
                                    request.enclave_name.clone(),
                                    request_id,
                                    delete_backup_request,
                                )
                                .map(|_reply| ());
                                Box::new(future)
                            }
                            _ => {
                                let future = client_request(request_tx.clone(), request.clone(), request_id);
                                Box::new(future)
                            }
                        };
                        future.map(move |()| {
                            let request_id = request_id + max_parallel;
                            if request_id < count {
                                futures::future::Loop::Continue(request_id)
                            } else {
                                futures::future::Loop::Break(())
                            }
                        })
                    })
                });
                futures::stream::futures_unordered(futures).for_each(|_| Ok(()))
            });
            let mut runtime = tokio::runtime::Runtime::new()?;
            let _ignore = runtime.block_on(connection);
        }
        _ => {}
    }
    drop(logger_guard);
    Ok(())
}

fn parse_argument<T, U, E, F>(maybe_argument: Option<T>, parse_fun: F) -> Result<Option<U>, E>
where F: Fn(T) -> Result<U, E> {
    if let Some(argument) = maybe_argument {
        Ok(Some(parse_fun(argument)?))
    } else {
        Ok(None)
    }
}

fn unwrap_or_random_bytes(size: usize, maybe_bytes: Option<Vec<u8>>) -> Vec<u8> {
    maybe_bytes.unwrap_or_else(|| {
        let mut bytes = vec![0; size];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    })
}

fn print_info(maybe_enclave_name: Option<String>, status: GetStatusControlReply) {
    let maybe_enclave_status = if let Some(enclave_name) = &maybe_enclave_name {
        status
            .enclaves
            .into_iter()
            .find(|enclave_status: &EnclaveStatus| &enclave_status.name == enclave_name)
    } else {
        status.enclaves.into_iter().next()
    };
    let enclave_status = match maybe_enclave_status {
        Some(enclave_status) => enclave_status,
        None => {
            if let Some(enclave_name) = &maybe_enclave_name {
                error!("enclave status reply did not contain requested enclave {}", enclave_name);
            } else {
                error!("enclave status reply did not contain an enclave");
            }
            return;
        }
    };

    println!("node_id={}", ToHex(&enclave_status.node_id));

    match enclave_status.status {
        Some(enclave_status::Status::ReplicaStatus(replica_status)) => {
            if let Some(partition_status) = &replica_status.partition {
                if let Some(service_id) = &partition_status.service_id {
                    println!("service_id={}", ToHex(service_id));
                }
                println!("group_id={}", ToHex(&partition_status.group_id));
            }
        }
        Some(enclave_status::Status::FrontendStatus(_frontend_status)) => {}
        None => (),
    }
}

fn print_status(maybe_enclave_name: Option<String>, status: GetStatusControlReply) {
    let enclave_statuses = status.enclaves.into_iter().filter(|enclave_status: &EnclaveStatus| {
        if let Some(enclave_name) = &maybe_enclave_name {
            &enclave_status.name == enclave_name
        } else {
            true
        }
    });

    for enclave_status in enclave_statuses {
        println!("{:#}", enclave_status);
    }
}

#[derive(Clone)]
struct ClientRequestParameters {
    enclave_name: String,
    subcommand:   String,
    service_id:   Option<Vec<u8>>,
    maybe_token:  Option<Vec<u8>>,
    backup_id:    Option<Vec<u8>>,
    backup_data:  Option<Vec<u8>>,
    backup_pin:   Option<Vec<u8>>,
    backup_tries: Option<u32>,
    valid_from:   u64,
}

fn client_request(
    request_tx: ControlClientSender,
    request: ClientRequestParameters,
    request_id: u64,
) -> impl Future<Item = (), Error = ()>
{
    let ClientRequestParameters {
        enclave_name,
        subcommand,
        service_id,
        maybe_token,
        backup_id,
        backup_data,
        backup_pin,
        backup_tries,
        valid_from,
    } = request;

    let mut random = OsRng::new().expect("rand error");
    let client = kbupd_client::Client::new(&mut random);
    let client_pubkey = client.client_pubkey().to_vec();
    let backup_id = unwrap_or_random_bytes(32, backup_id);

    let enclave_name_1 = enclave_name.clone();
    let request_tx_1 = request_tx.clone();
    let backup_id_1 = backup_id.clone();

    let create_backup_future = if let Some(token) = maybe_token {
        future::Either::A(Ok(token).into_future())
    } else {
        let create_backup_request = transaction_control_request::Data::CreateBackupRequest(CreateBackupRequest {
            backup_id: BackupId { id: backup_id.clone() },
        });
        let reply = send_transaction_request(request_tx.clone(), enclave_name.clone(), request_id, create_backup_request);
        let token = reply.and_then(|reply: TransactionControlReply| {
            if let Some(transaction_control_reply::Data::CreateBackupReply(create_backup_reply)) = reply.data {
                Ok(create_backup_reply.token)
            } else {
                error!("received wrong transaction reply: {:?}", reply);
                Err(())
            }
        });
        future::Either::B(token)
    };
    create_backup_future
        .map(move |token: Vec<u8>| {
            let request = match subcommand.as_str() {
                "backup" => kbupd_client::Request {
                    backup:  Some(kbupd_client::BackupRequest {
                        service_id,
                        backup_id: Some(backup_id_1),
                        valid_from: Some(valid_from),
                        token: Some(token),
                        data: Some(unwrap_or_random_bytes(32, backup_data)),
                        pin: Some(unwrap_or_random_bytes(32, backup_pin)),
                        tries: backup_tries,
                    }),
                    restore: None,
                    delete:  None,
                },
                "restore" => kbupd_client::Request {
                    backup:  None,
                    restore: Some(kbupd_client::RestoreRequest {
                        service_id,
                        backup_id: Some(backup_id_1),
                        token: Some(token),
                        valid_from: Some(valid_from),
                        pin: Some(unwrap_or_random_bytes(32, backup_pin)),
                    }),
                    delete:  None,
                },
                _ => Default::default(),
            };
            request
        })
        .and_then(move |request: kbupd_client::Request| {
            debug!("negotiating request {}", request_id);
            negotiate_client_request(request_tx, enclave_name, request_id, client_pubkey)
                .map(move |negotiation: kbupd_client::RequestNegotiation| (request, negotiation))
        })
        .and_then(
            move |(request, negotiation): (kbupd_client::Request, kbupd_client::RequestNegotiation)| {
                if let Some(backup_request) = &request.backup {
                    info!("sending backup request {}: {}", request_id, backup_request);
                }
                if let Some(restore_request) = &request.restore {
                    info!("sending restore request {}: {}", request_id, restore_request);
                }
                if let Some(delete_request) = &request.delete {
                    info!("sending delete request {}: {}", request_id, delete_request);
                }
                send_client_request(
                    request_tx_1,
                    enclave_name_1,
                    request_id,
                    backup_id,
                    client,
                    random,
                    negotiation,
                    request,
                )
            },
        )
        .map(move |response: kbupd_client::Response| {
            if let Some(backup_response) = &response.backup {
                println!("{}", &backup_response);
            }
            if let Some(restore_response) = &response.restore {
                println!("{}", &restore_response);
            }
        })
}

fn send_transaction_request(
    request_tx: ControlClientSender,
    enclave_name: String,
    request_id: u64,
    data: transaction_control_request::Data,
) -> impl Future<Item = TransactionControlReply, Error = ()>
{
    let control_request = ControlRequest {
        id:   request_id,
        data: Some(control_request::Data::TransactionControlRequest(TransactionControlRequest {
            enclave_name,
            data: Some(data),
        })),
    };
    request_tx.call(control_request).and_then(move |reply: ControlReply| {
        if let Some(control_reply::Data::TransactionControlReply(transaction_control_reply)) = reply.data {
            Ok(transaction_control_reply)
        } else {
            error!("error parsing reply {}: {:?}", request_id, reply);
            Err(())
        }
    })
}

fn negotiate_client_request(
    request_tx: ControlClientSender,
    enclave_name: String,
    request_id: u64,
    client_pubkey: Vec<u8>,
) -> impl Future<Item = kbupd_client::RequestNegotiation, Error = ()>
{
    let control_request = ControlRequest {
        id:   request_id,
        data: Some(control_request::Data::NegotiateClientRequest(NegotiateClientRequest {
            enclave_name,
            client_pubkey,
        })),
    };

    request_tx.call(control_request).and_then(move |reply: ControlReply| {
        parse_negotiate_client_reply(reply).map_err(|error: failure::Error| {
            error!("error parsing reply {}: {}", request_id, error);
        })
    })
}

#[rustfmt::skip]
fn parse_negotiate_client_reply(reply: ControlReply) -> Result<kbupd_client::RequestNegotiation, failure::Error> {
    match reply.data {
        Some(control_reply::Data::NegotiateClientReply(NegotiateClientReply {
            server_static_pubkey,
            server_ephemeral_pubkey,
            encrypted_pending_request_id,
        })) => {
            Ok(kbupd_client::RequestNegotiation {
                server_static_pubkey:         server_static_pubkey[..].try_into().map_err(failure::Error::from).context("bad client request negotiation reply server_static_pubkey")?,
                server_ephemeral_pubkey:      server_ephemeral_pubkey[..].try_into().map_err(failure::Error::from).context("bad client request negotiation reply server_ephemeral_pubkey")?,
                encrypted_pending_request_id: kbupd_client::EncryptedMessage {
                    iv:   encrypted_pending_request_id.iv[..].try_into().map_err(failure::Error::from).context("bad client request negotiation reply encrypted_pending_request_id.iv")?,
                    mac:  encrypted_pending_request_id.mac[..].try_into().map_err(failure::Error::from).context("bad client request negotiation reply encrypted_pending_request_id.mac")?,
                    data: encrypted_pending_request_id.data,
                },
            })
        }
        _ => {
            Err(failure::format_err!("bad client negotiation reply: {:?}", reply.data))
        }
    }
}

fn send_client_request(
    request_tx: ControlClientSender,
    enclave_name: String,
    request_id: u64,
    backup_id: Vec<u8>,
    client: kbupd_client::Client,
    mut random: OsRng,
    negotiation: kbupd_client::RequestNegotiation,
    request: kbupd_client::Request,
) -> impl Future<Item = kbupd_client::Response, Error = ()>
{
    let request_type = match &request {
        kbupd_client::Request { backup: Some(_), .. } => ClientRequestType::Backup,
        kbupd_client::Request { restore: Some(_), .. } => ClientRequestType::Restore,
        kbupd_client::Request { delete: Some(_), .. } => ClientRequestType::Delete,
        _ => unreachable!(),
    };
    client
        .request(&mut random, negotiation, request)
        .into_future()
        .map_err(move |error| {
            error!("error building client request {}: {}", request_id, error);
        })
        .and_then(
            move |(encrypted_request, pending_request): (kbupd_client::EncryptedRequest, kbupd_client::PendingRequest)| {
                let control_request = ControlRequest {
                    id:   request_id,
                    data: Some(control_request::Data::ClientEncryptedRequest(ClientEncryptedRequest {
                        enclave_name,
                        request_type: request_type.into(),
                        backup_id,
                        pending_request_id: encrypted_request.pending_request_id,
                        encrypted_message: ClientEncryptedMessage {
                            iv:   encrypted_request.encrypted_message.iv.to_vec(),
                            mac:  encrypted_request.encrypted_message.mac.to_vec(),
                            data: encrypted_request.encrypted_message.data,
                        },
                    })),
                };

                request_tx.call(control_request).map(|reply: ControlReply| (reply, pending_request))
            },
        )
        .and_then(move |(reply, pending_request): (ControlReply, kbupd_client::PendingRequest)| {
            parse_client_reply(reply)
                .map_err(|error: failure::Error| {
                    error!("error parsing client reply {}: {}", request_id, error);
                })
                .map(|encrypted_message: kbupd_client::EncryptedMessage| (encrypted_message, pending_request))
        })
        .and_then(
            move |(encrypted_message, pending_request): (kbupd_client::EncryptedMessage, kbupd_client::PendingRequest)| {
                pending_request
                    .decrypt_reply(encrypted_message)
                    .map(|response: kbupd_client::Response| response)
                    .map_err(|error| {
                        error!("error decrypting client response {}: {}", request_id, error);
                    })
            },
        )
}

#[rustfmt::skip]
fn parse_client_reply(reply: ControlReply) -> Result<kbupd_client::EncryptedMessage, failure::Error> {
    match reply.data {
        Some(control_reply::Data::ClientEncryptedReply(ClientEncryptedReply { encrypted_message })) => Ok(kbupd_client::EncryptedMessage {
            iv:   encrypted_message.iv[..].try_into().map_err(failure::Error::from).context("bad client reply iv")?,
            mac:  encrypted_message.mac[..].try_into().map_err(failure::Error::from).context("bad client reply mac")?,
            data: encrypted_message.data,
        }),
        _ => Err(failure::format_err!("bad client reply: {:?}", reply.data)),
    }
}

struct ControlClientState {
    framed_tx: SplitSink<ControlFramed>,
    requests:  BTreeMap<u64, oneshot::Sender<ControlReply>>,
}

#[derive(Clone)]
struct ControlClientSender {
    request_tx: mpsc::UnboundedSender<(ControlRequest, oneshot::Sender<ControlReply>)>,
}
impl ControlClientSender {
    fn call(&self, request: ControlRequest) -> impl Future<Item = ControlReply, Error = ()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ignore = self.request_tx.unbounded_send((request, reply_tx));
        reply_rx.map_err(|oneshot::Canceled| ())
    }
}

enum ControlMessage {
    Request(ControlRequest, oneshot::Sender<ControlReply>),
    Reply(ControlReply),
}

fn control_client(
    framed: ControlFramed,
    request_rx: mpsc::UnboundedReceiver<(ControlRequest, oneshot::Sender<ControlReply>)>,
) -> impl Future<Item = (), Error = ()>
{
    let (framed_tx, framed_rx) = framed.split();
    let state = ControlClientState {
        framed_tx,
        requests: Default::default(),
    };
    framed_rx
        .map(|reply: ControlReply| ControlMessage::Reply(reply))
        .select(
            request_rx
                .map(|(request, reply_tx): (ControlRequest, oneshot::Sender<ControlReply>)| ControlMessage::Request(request, reply_tx))
                .map_err(|()| unreachable!()),
        )
        .fold(state, |mut state: ControlClientState, message: ControlMessage| match message {
            ControlMessage::Request(request, reply_tx) => {
                let ControlClientState { framed_tx, mut requests } = state;
                let request_id = request.id;
                if let Some(_) = requests.insert(request.id, reply_tx) {
                    warn!("dropping pending request {}!", request_id);
                }
                let future = framed_tx
                    .send(request)
                    .map(move |framed_tx: SplitSink<ControlFramed>| ControlClientState { framed_tx, requests });
                future::Either::A(future)
            }
            ControlMessage::Reply(reply) => {
                if let Some(reply_tx) = state.requests.remove(&reply.id) {
                    let _ignore = reply_tx.send(reply);
                } else {
                    warn!("dropping reply {}!", reply.id);
                }
                future::Either::B(Ok(state).into_future())
            }
        })
        .map_err(|error: io::Error| {
            error!("error receiving replies: {}", error);
        })
        .map(|_| ())
}

fn daemon_call(framed: ControlFramed, request: ControlRequest) -> impl Future<Item = (ControlReply, ControlFramed), Error = io::Error> {
    framed.send(request).and_then(|framed: ControlFramed| {
        framed
            .into_future()
            .map_err(|(error, _framed): (io::Error, ControlFramed)| error)
            .and_then(|(reply, framed): (Option<ControlReply>, ControlFramed)| {
                reply
                    .ok_or(io::ErrorKind::UnexpectedEof.into())
                    .map(|reply: ControlReply| (reply, framed))
            })
    })
}

fn parse_arguments() -> clap::ArgMatches<'static> {
    let enclave_name_argument = clap::Arg::with_name("enclave_name")
        .takes_value(true)
        .long("enclave-name")
        .value_name("enclave_name")
        .help("Name of enclave to query, in a frontend kbupd instance");

    let info_subcommand = clap::SubCommand::with_name("info")
        .arg(enclave_name_argument.clone())
        .about("query and output basic information like node ID, service ID, and partition ID in a parsable format");

    let detailed_memory_status_argument = clap::Arg::with_name("detailed_memory_status")
        .long("detailed-memory-status")
        .help("run mallinfo in enclave to traverse all free memory blocks to calculate used memory");

    let status_subcommand = clap::SubCommand::with_name("status")
        .arg(enclave_name_argument.clone())
        .arg(detailed_memory_status_argument)
        .about("dump complete status information in a human-readable format");

    let metrics_subcommand = clap::SubCommand::with_name("metrics").about("dump a metrics snapshot in JSON");

    let xfer_start_subcommand = clap::SubCommand::with_name("start")
        .about("start an incoming transfer from a source partition described in the config this partition was started with");

    let xfer_pause_subcommand = clap::SubCommand::with_name("pause").about("pause an ongoing outgoing transfer");

    let xfer_resume_subcommand = clap::SubCommand::with_name("resume").about("resume a paused outgoing transfer");

    let xfer_finish_subcommand = clap::SubCommand::with_name("finish")
        .about("finish a transfer, tearing down its state, allowing acceptance of a new outgoing transfer");

    let xfer_subcommand = clap::SubCommand::with_name("xfer")
        .setting(clap::AppSettings::VersionlessSubcommands)
        .setting(clap::AppSettings::SubcommandRequiredElseHelp)
        .subcommand(xfer_start_subcommand)
        .subcommand(xfer_pause_subcommand)
        .subcommand(xfer_resume_subcommand)
        .subcommand(xfer_finish_subcommand)
        .arg(enclave_name_argument.clone())
        .about("control inter-partition key-space and data transfer");

    let peer_node_id_argument = clap::Arg::with_name("peer_node_id")
        .required(true)
        .takes_value(true)
        .long("peer-node-id")
        .value_name("node_id_hex")
        .help("Node ID of peer to force a reconnect to, as a hexadecimal byte string");

    let peer_address_argument = clap::Arg::with_name("peer_address")
        .takes_value(true)
        .long("peer-address")
        .value_name("address")
        .help("ip[:port] address of peer to reconnect to");

    let reconnect_peer_subcommand = clap::SubCommand::with_name("reconnect-peer")
        .arg(enclave_name_argument.clone())
        .arg(peer_node_id_argument.clone())
        .arg(peer_address_argument)
        .about("force reconnection to a specified peer");

    let disconnect_peer_subcommand = clap::SubCommand::with_name("disconnect-peer")
        .arg(enclave_name_argument.clone())
        .arg(peer_node_id_argument)
        .about("force disconnection from a specified peer");

    let backup_id_argument = clap::Arg::with_name("backup_id")
        .takes_value(true)
        .long("backup-id")
        .value_name("backup_id_hex")
        .help("Backup ID to use in client request, as a hexadecimal byte string. Randomly generated by default.");

    let request_count_argument = clap::Arg::with_name("request_count")
        .takes_value(true)
        .default_value("1")
        .long("request-count")
        .value_name("request_count")
        .help("Number of requests to perform, in decimal. For request parameters randomized by default, different values will be generated for each request.");

    let max_parallel_argument = clap::Arg::with_name("max_parallel")
        .takes_value(true)
        .long("max-parallel")
        .value_name("max_parallel")
        .help("Maximum number of requests to perform in parallel, in decimal.");

    let client_create_subcommand = clap::SubCommand::with_name("create")
        .arg(backup_id_argument.clone())
        .arg(request_count_argument.clone())
        .arg(max_parallel_argument.clone())
        .about("Key Backup Service Client - Create");

    let client_delete_subcommand = clap::SubCommand::with_name("delete")
        .arg(backup_id_argument.clone())
        .arg(request_count_argument.clone())
        .arg(max_parallel_argument.clone())
        .about("Key Backup Service Client - Delete");

    let service_id_argument = clap::Arg::with_name("service_id")
        .takes_value(true)
        .long("service-id")
        .value_name("service_id_hex")
        .help("Service ID to use in client request, as a hexadecimal byte string");

    let request_token_argument = clap::Arg::with_name("request_token")
        .takes_value(true)
        .long("request-token")
        .value_name("request_token_hex")
        .help("Token to use in client request, as a hexadecimal byte string");

    let request_valid_from_argument = clap::Arg::with_name("request_valid_from")
        .takes_value(true)
        .long("request-valid-from")
        .value_name("seconds_since_unix_epoch")
        .help("Time after which this request is valid, in seconds since unix epoch");

    let backup_data_argument = clap::Arg::with_name("backup_data")
        .takes_value(true)
        .long("backup-data")
        .value_name("backup_data_hex")
        .help("Backup Key to use in client request, as a hexadecimal byte string. Randomly generated by default.");

    let backup_pin_argument = clap::Arg::with_name("backup_pin")
        .takes_value(true)
        .long("backup-pin")
        .value_name("backup_pin_hex")
        .help("Backup PIN to use in client request, as a hexadecimal byte string. Randomly generated by default.");

    let backup_tries_argument = clap::Arg::with_name("backup_tries")
        .takes_value(true)
        .default_value("10")
        .long("backup-tries")
        .value_name("backup_tries")
        .help("Backup try count to use in client request, in decimal");

    let client_backup_subcommand = clap::SubCommand::with_name("backup")
        .arg(service_id_argument.clone())
        .arg(backup_id_argument.clone())
        .arg(request_token_argument.clone())
        .arg(request_valid_from_argument.clone())
        .arg(request_count_argument.clone())
        .arg(max_parallel_argument.clone())
        .arg(backup_data_argument)
        .arg(backup_pin_argument.clone())
        .arg(backup_tries_argument)
        .about("Key Backup Service Client - Backup");

    let client_restore_subcommand = clap::SubCommand::with_name("restore")
        .arg(service_id_argument)
        .arg(backup_id_argument)
        .arg(request_token_argument)
        .arg(request_valid_from_argument)
        .arg(request_count_argument)
        .arg(max_parallel_argument)
        .arg(backup_pin_argument)
        .about("Key Backup Service Client - Restore");

    let client_subcommand = clap::SubCommand::with_name("client")
        .setting(clap::AppSettings::VersionlessSubcommands)
        .setting(clap::AppSettings::SubcommandRequiredElseHelp)
        .subcommand(client_create_subcommand)
        .subcommand(client_delete_subcommand)
        .subcommand(client_backup_subcommand)
        .subcommand(client_restore_subcommand)
        .arg(enclave_name_argument.required(true))
        .about("Key Backup Service Client");

    let connect_argument = clap::Arg::with_name("connect_address")
        .takes_value(true)
        .default_value("127.0.0.1:31338")
        .long("connect")
        .value_name("connect_address")
        .help("ip[:port] address of kbupd to connect to");

    let debug_argument = clap::Arg::with_name("debug").long("debug").help("emit debug logging");

    clap::App::new("kbupctl")
        .version(clap::crate_version!())
        .about(format!("{} -- Control Utility", clap::crate_description!()).as_str())
        .author(clap::crate_authors!())
        .setting(clap::AppSettings::VersionlessSubcommands)
        .setting(clap::AppSettings::SubcommandRequiredElseHelp)
        .arg(connect_argument)
        .arg(debug_argument)
        .subcommand(client_subcommand)
        .subcommand(info_subcommand)
        .subcommand(status_subcommand)
        .subcommand(metrics_subcommand)
        .subcommand(reconnect_peer_subcommand)
        .subcommand(disconnect_peer_subcommand)
        .subcommand(xfer_subcommand)
        .get_matches()
}
