//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

mod peer_manager;
mod sgx_quote;

use crate::prelude::*;

use std::borrow::*;
use std::cell::*;
use std::fmt;
use std::marker::*;
use std::ops::*;
use std::rc::*;
use std::time::*;

use bytes::{BufMut};
use chrono::{DateTime, NaiveDateTime, Utc};
use num_traits::{ToPrimitive};
use prost::{self, Message};
use serde::{Deserialize};
use sgx_ffi::sgx;
use sgx_ffi::util::{SecretValue};
use sgxsd_ffi::{SHA256Context};
use snow;

use crate::{kbupd_send};
use crate::ffi::snow_resolver::*;
use crate::protobufs::kbupd::*;
use crate::protobufs::kbupd::enclave_message::{Inner as EnclaveMessageInner};
use crate::protobufs::kbupd_enclave::*;
use crate::util::{self, deserialize_base64};

use self::sgx_quote::*;

//
// public api
//

pub use self::peer_manager::*;

pub const NODE_ID_LEN: usize = 32;

#[derive(Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
pub enum NodeId {
    Valid([u8; NODE_ID_LEN]),
    Invalid(Vec<u8>),
}

#[derive(Clone)]
pub struct NodeParams {
    node_key:  Rc<[u8]>,
    node_id:   NodeId,
    node_type: NodeType,
}

pub struct RemoteSender<M>
where M: prost::Message + 'static,
{
    id:     NodeId,
    shared: Rc<RefCell<Shared<M>>>,
}

pub trait RemoteCommon {
    fn id(&self) -> &NodeId;
    fn attestation(&self) -> Option<AttestationParameters>;
}

pub trait RemoteMessageSender: RemoteCommon + fmt::Display {
    type Message: prost::Message;
    fn send(&self, message: Rc<Self::Message>) -> Result<(), ()>;
}

#[must_use]
pub enum RemoteRecvError {
    NeedsAttestation(GetAttestationRequest),
    DecodeError,
    InvalidState,
}

pub enum RemoteAuthorizationType {
    Mutual,
    RemoteOnly,
    SelfOnly,
}

pub trait Remote: RemoteCommon {
    fn connect(&mut self) -> Result<(), ()>;
    fn accept(&mut self, connect_request: PeerConnectRequest) -> Result<(), ()>;
    fn qe_info_reply(&self, sgx_qe_info: &GetQeInfoReply) -> Result<GetQuoteRequest, ()>;
    fn get_quote_reply(&mut self, sgx_quote: GetQuoteReply) -> Result<Option<GetAttestationRequest>, Option<EnclaveGetQuoteReply>>;
    fn attestation_reply(&mut self, ias_report: IasReport) -> Result<Option<AttestationParameters>, ()>;
}

pub struct RemoteState<M,R>
where M: prost::Message + 'static,
      R: prost::Message + Default + 'static
{
    node_params:    Rc<NodeParams>,
    remote_node_id: NodeId,
    remote_type:    NodeType,
    auth_type:      RemoteAuthorizationType,
    shared:         Rc<RefCell<Shared<M>>>,
    _reply:         PhantomData<R>,
}

#[derive(Clone, Default)]
pub struct SharedNoiseBuffers {
    inner: Rc<NoiseBuffers>,
}

//
// RemoteState impls
//

const NOISE_PARAMS: &str = "Noise_KK_25519_AESGCM_SHA256";

const NOISE_CHUNK_MAX_LENGTH: usize = 65535;

struct HandshakeHash {
    hash: [u8; 32],
}

struct Shared<M> {
    session:        SessionState,
    remote_node_id: NodeId,
    noise_buffer:   SharedNoiseBuffers,
    _message:       PhantomData<M>,
}

#[derive(Default)]
struct NoiseBuffers {
    read_buffer:  Cell<Option<SecretValue<Box<NoiseBuffer>>>>,
    write_buffer: RefCell<NoiseBuffer>,
}

struct NoiseBuffer([u8; NOISE_CHUNK_MAX_LENGTH]);

// initiator: Disconnected -> WaitingForAttestation -> Initiated -> Connected -> Authorized
// responder: Disconnected -> Accepted -> Responded -> Authorized
#[allow(clippy::large_enum_variant)]
enum SessionState {
    Disconnected,
    WaitingForAttestation {
        noise: snow::HandshakeState,
    },
    Initiated {
        noise: snow::HandshakeState,
    },
    Connected {
        noise:                snow::TransportState,
        their_handshake_hash: HandshakeHash,
        final_handshake_hash: HandshakeHash,
    },
    Accepted {
        noise:       snow::HandshakeState,
        attestation: Option<AttestationParameters>,
    },
    Responded {
        noise:          snow::TransportState,
        attestation:    Option<AttestationParameters>,
        handshake_hash: HandshakeHash,
    },
    Authorized {
        noise:          snow::TransportState,
        attestation:    Option<AttestationParameters>,
        handshake_hash: HandshakeHash,
    },
}

impl<M,R> RemoteState<M,R>
where M: prost::Message + 'static,
      R: prost::Message + Default + 'static
{
    pub fn new(node_params:    Rc<NodeParams>,
               remote_node_id: NodeId,
               remote_type:    NodeType,
               auth_type:      RemoteAuthorizationType,
               noise_buffer:   SharedNoiseBuffers)
               -> Self {
        let shared = Rc::new(RefCell::new(Shared {
            session:        SessionState::Disconnected,
            remote_node_id: remote_node_id.clone(),
            noise_buffer,
            _message:       Default::default(),
        }));
        Self {
            node_params,
            remote_type,
            remote_node_id,
            auth_type,
            shared,
            _reply: Default::default(),
        }
    }

    pub fn sender(&self) -> RemoteSender<M> {
        RemoteSender {
            id:     self.remote_node_id.clone(),
            shared: Rc::clone(&self.shared),
        }
    }

    fn create_noise_session<Res, BuildFun>(&self, initiator: bool, build_fun: BuildFun) -> Res
    where BuildFun: Fn(snow::Builder<'_>) -> Res {
        let mut prologue_buf = Vec::with_capacity(8);
        if initiator {
            prologue_buf.put_i32_le(self.node_params.node_type.into());
            prologue_buf.put_i32_le(self.remote_type.into());
        } else {
            prologue_buf.put_i32_le(self.remote_type.into());
            prologue_buf.put_i32_le(self.node_params.node_type.into());
        }
        let params  = NOISE_PARAMS.parse().unwrap_or_else(|_| unreachable!());
        let builder = snow::Builder::with_resolver(params, Box::new(SnowResolver))
            .prologue(&prologue_buf)
            .local_private_key(&self.node_params.node_key)
            .remote_public_key(&self.remote_node_id);
        build_fun(builder)
    }

    fn initiate_connection(&self) -> Result<snow::HandshakeState, snow::Error> {
        self.create_noise_session(true, |builder| builder.build_initiator())
    }

    fn connection_request(noise: &mut snow::HandshakeState) -> Result<Vec<u8>, snow::Error> {
        let mut msg_buf = vec![0; NOISE_CHUNK_MAX_LENGTH];
        let msg_len = noise.write_message(Default::default(), &mut msg_buf)?;
        msg_buf.truncate(msg_len);
        Ok(msg_buf)
    }

    fn accept_connection(&self, msg_data: &[u8]) -> Result<(snow::HandshakeState, HandshakeHash), snow::Error> {
        let mut noise = self.create_noise_session(false, |builder| builder.build_responder())?;

        let their_handshake_hash = get_handshake_hash(&noise)?;

        noise.read_message(msg_data, &mut [0; 0])?;

        Ok((noise, their_handshake_hash))
    }

    fn connection_response(mut noise: snow::HandshakeState) -> Result<(snow::TransportState, Vec<u8>, HandshakeHash), snow::Error> {
        let mut msg_buf = vec![0; NOISE_CHUNK_MAX_LENGTH];
        let msg_len = noise.write_message(&[0;0], &mut msg_buf)?;
        msg_buf.truncate(msg_len);

        let handshake_hash = get_handshake_hash(&noise)?;

        let noise = noise.into_transport_mode()?;

        Ok((noise, msg_buf, handshake_hash))
    }

    #[allow(clippy::type_complexity)]
    fn establish_connection(mut noise: snow::HandshakeState, encrypted_msg_data: &[u8])
                            -> Result<(snow::TransportState, Vec<u8>, HandshakeHash, HandshakeHash), snow::Error> {
        let their_handshake_hash = get_handshake_hash(&noise)?;

        let mut payload_buf = vec![0; encrypted_msg_data.len()];
        let payload_len     = noise.read_message(encrypted_msg_data, &mut payload_buf)?;
        payload_buf.truncate(payload_len);

        let final_handshake_hash = get_handshake_hash(&noise)?;

        let noise = noise.into_transport_mode()?;
        Ok((noise, payload_buf, their_handshake_hash, final_handshake_hash))
    }

    pub fn recv(&mut self, msg_data: &[u8]) -> Result<R, RemoteRecvError> {
        let mut shared_ref = self.shared.as_ref().borrow_mut();
        let shared         = &mut *shared_ref;
        match &mut shared.session {
            session @ SessionState::Disconnected |
            session @ SessionState::WaitingForAttestation { .. } |
            session @ SessionState::Connected { .. } |
            session @ SessionState::Accepted { .. } => {
                warn!("dropping message from {} in {} state", self.remote_node_id, session);
                Err(RemoteRecvError::InvalidState)
            }
            session @ SessionState::Initiated { .. } => {
                match PeerConnectReply::decode(msg_data) {
                    Ok(connect_reply) => {
                        let noise = match std::mem::replace(session, SessionState::Disconnected) {
                            SessionState::Initiated { noise } => noise,
                            _ => unreachable!(),
                        };
                        match Self::establish_connection(noise, &connect_reply.noise_data) {
                            Ok((noise, _payload, their_handshake_hash, final_handshake_hash)) => {
                                *session      = SessionState::Connected { noise, their_handshake_hash, final_handshake_hash };
                                let sgx_quote = connect_reply.sgx_quote;
                                Err(RemoteRecvError::NeedsAttestation(GetAttestationRequest {
                                    request_id: self.remote_node_id.to_vec(),
                                    sgx_quote,
                                }))
                            }
                            Err(err) => {
                                warn!("error decrypting connect reply from {}: {}", self.remote_node_id, err);
                                Err(RemoteRecvError::DecodeError)
                            }
                        }
                    }
                    Err(err) => {
                        warn!("error decoding connect reply from {}: {}", self.remote_node_id, err);
                        Err(RemoteRecvError::DecodeError)
                    }
                }
            }
            mut session @ SessionState::Responded { .. } |
            mut session @ SessionState::Authorized { .. } => {
                let noise = match &mut session {
                    SessionState::Responded { noise, .. } => noise,
                    SessionState::Authorized { noise, .. } => noise,
                    _ => static_unreachable!(),
                };
                match read_noise_message(noise, &shared.noise_buffer, msg_data) {
                    Ok(msg_data) => {
                        if let SessionState::Responded { .. } = &session {
                            *session = match std::mem::replace(session, SessionState::Disconnected) {
                                SessionState::Responded { noise, attestation, handshake_hash } =>
                                    SessionState::Authorized { noise, attestation, handshake_hash },
                                _ => unreachable!(),
                            };
                        }

                        match R::decode(&msg_data.get()[..]) {
                            Ok(reply) => {
                                Ok(reply)
                            }
                            Err(decode_error) => {
                                error!("error decoding message from {}: {}", &self.remote_node_id, decode_error);
                                Err(RemoteRecvError::DecodeError)
                            }
                        }
                    }
                    Err(err) => {
                        error!("error decrypting message from {}: {}", &self.remote_node_id, err);
                        Err(RemoteRecvError::DecodeError)
                    }
                }
            }
        }
    }
}

impl<M,R> RemoteCommon for RemoteState<M,R>
where M: prost::Message + 'static,
      R: prost::Message + Default + 'static
{
    fn id(&self) -> &NodeId {
        &self.remote_node_id
    }
    fn attestation(&self) -> Option<AttestationParameters> {
        self.shared.as_ref().borrow_mut().attestation()
    }
}

impl<M,R> Remote for RemoteState<M,R>
where M: prost::Message + 'static,
      R: prost::Message + Default + 'static
{
    fn connect(&mut self) -> Result<(), ()> {
        if self.node_params.node_id == self.remote_node_id {
            return Err(());
        }

        let mut shared = self.shared.as_ref().borrow_mut();
        let session    = match &mut shared.session {
            session @ SessionState::Disconnected |
            session @ SessionState::WaitingForAttestation { .. } |
            session @ SessionState::Initiated { .. } |
            session @ SessionState::Connected { .. } => {
                session
            }

            SessionState::Accepted { .. } |
            SessionState::Responded { .. } |
            SessionState::Authorized { .. } => {
                return Err(());
            }
        };

        match self.initiate_connection() {
            Ok(mut noise) => {
                match self.auth_type {
                    RemoteAuthorizationType::Mutual | RemoteAuthorizationType::SelfOnly => {
                        *session = SessionState::WaitingForAttestation { noise };
                    }
                    RemoteAuthorizationType::RemoteOnly => {
                        match Self::connection_request(&mut noise) {
                            Ok(noise_data) => {
                                let connect_req = PeerConnectRequest {
                                    node_type:  self.node_params.node_type.into(),
                                    ias_report: None,
                                    noise_data,
                                };
                                let mut connect_req_data = Vec::with_capacity(connect_req.encoded_len());
                                assert!(connect_req.encode(&mut connect_req_data).is_ok());

                                kbupd_send(EnclaveMessage {
                                    inner: Some(EnclaveMessageInner::SendMessageRequest(SendMessageRequest {
                                        node_id:   self.remote_node_id.to_vec(),
                                        data:      connect_req_data,
                                        syn:       true,
                                        debug_msg: None,
                                    })),
                                });
                                *session = SessionState::Initiated { noise };
                            }
                            Err(noise_error) => {
                                error!("noise error connecting to {}: {}", &self.remote_node_id, noise_error);
                            }
                        }
                    }
                }
            }
            Err(noise_error) => {
                error!("error initiating connection with {}: {}", self.remote_node_id, noise_error);
            }
        }
        Ok(())
    }

    fn accept(&mut self, connect_request: PeerConnectRequest) -> Result<(), ()> {
        if self.node_params.node_id == self.remote_node_id {
            return Err(());
        }

        let mut shared = self.shared.as_ref().borrow_mut();
        let session    = match &mut shared.session {
            session @ SessionState::Disconnected |
            session @ SessionState::WaitingForAttestation { .. } |
            session @ SessionState::Accepted { .. } |
            session @ SessionState::Responded { .. } => {
                session
            }

            session @ SessionState::Initiated { .. } => {
                if self.node_params.node_id < self.remote_node_id {
                    session
                } else {
                    warn!("dropping connect request from {} in {} state", self.remote_node_id, session);
                    return Err(());
                }
            }
            session @ SessionState::Connected { .. } |
            session @ SessionState::Authorized { .. } => {
                warn!("dropping connect request from {} in {} state", self.remote_node_id, session);
                return Err(());
            }
        };

        match self.accept_connection(&connect_request.noise_data) {
            Ok((noise, their_handshake_hash)) => {
                match self.auth_type {
                    RemoteAuthorizationType::Mutual | RemoteAuthorizationType::RemoteOnly => {
                        match validate_ias_report(connect_request.ias_report.as_ref(), &their_handshake_hash.hash) {
                            Ok(attestation) => {
                                *session = SessionState::Accepted { noise, attestation: Some(attestation) };
                                Ok(())
                            }
                            Err(attestation_error) => {
                                warn!("attestation error accepting peer {}: {}", self.remote_node_id, attestation_error);
                                Err(())
                            }
                        }
                    }
                    RemoteAuthorizationType::SelfOnly => {
                        *session = SessionState::Accepted { noise, attestation: None };
                        Ok(())
                    }
                }
            }
            Err(noise_error) => {
                error!("decrypt error accepting peer {}: {}", self.remote_node_id, noise_error);
                Err(())
            }
        }
    }

    fn qe_info_reply(&self, reply: &GetQeInfoReply) -> Result<GetQuoteRequest, ()> {
        let shared = self.shared.as_ref().borrow();

        let report_data: [u8; 32] = match &shared.session {
            SessionState::WaitingForAttestation { noise, .. } |
            SessionState::Accepted { noise, .. } => {
                match get_handshake_hash(noise) {
                    Ok(our_handshake_hash) => our_handshake_hash.hash,
                    Err(_)                 => return Err(()),
                }
            }
            SessionState::Authorized { handshake_hash, .. } => {
                handshake_hash.get_hash_for_node(&self.node_params.node_id)
            }
            _ => {
                return Err(());
            }
        };

        #[allow(clippy::cast_possible_truncation)]
        let qe_target_info = sgx::SgxTargetInfo {
            mrenclave:   &reply.mrenclave,
            flags:       reply.flags,
            xfrm:        reply.xfrm,
            misc_select: reply.misc_select,
            config_svn:  reply.config_svn as u16,
            config_id:   &reply.config_id,
        };
        match sgx::create_report(&qe_target_info, &report_data) {
            Ok(sgx_report) => {
                Ok(GetQuoteRequest {
                    request_id: self.remote_node_id.to_vec(),
                    sgx_report,
                })
            }
            Err(sgx_error) => {
                warn!("error generating sgx report: {}", sgx_error);
                Err(())
            }
        }
    }

    fn get_quote_reply(&mut self, reply: GetQuoteReply) -> Result<Option<GetAttestationRequest>, Option<EnclaveGetQuoteReply>> {
        let sgx_quote = reply.sgx_quote;
        match &mut self.shared.as_ref().borrow_mut().session {
            SessionState::WaitingForAttestation { .. } => {
                Ok(Some(GetAttestationRequest {
                    request_id: self.remote_node_id.to_vec(),
                    sgx_quote,
                }))
            }
            session @ SessionState::Accepted { .. } => {
                let (noise, attestation) = match std::mem::replace(session, SessionState::Disconnected) {
                    SessionState::Accepted { noise, attestation } => (noise, attestation),
                    _ => unreachable!(),
                };
                let (noise, noise_data, handshake_hash) = match Self::connection_response(noise) {
                    Ok(result)       => result,
                    Err(noise_error) => {
                        error!("error accepting connection request from {}: {}", self.remote_node_id, noise_error);
                        return Err(None);
                    }
                };
                *session = SessionState::Responded { noise, attestation, handshake_hash };

                let msg = PeerConnectReply {
                    sgx_quote,
                    noise_data
                };
                let mut encoded_msg_data = Vec::with_capacity(msg.encoded_len());
                assert!(msg.encode(&mut encoded_msg_data).is_ok());

                kbupd_send(EnclaveMessage {
                    inner: Some(EnclaveMessageInner::SendMessageRequest(SendMessageRequest {
                        node_id:   self.remote_node_id.to_vec(),
                        data:      encoded_msg_data,
                        syn:       false,
                        debug_msg: None,
                    })),
                });

                Ok(None)
            }
            SessionState::Authorized { .. } => {
                Err(Some(EnclaveGetQuoteReply { sgx_quote }))
            }
            _ => Ok(None),
        }
    }

    fn attestation_reply(&mut self, ias_report: IasReport) -> Result<Option<AttestationParameters>, ()> {
        match &mut self.shared.as_ref().borrow_mut().session {
            session @ SessionState::WaitingForAttestation { .. } => {
                let mut noise = match std::mem::replace(session, SessionState::Disconnected) {
                    SessionState::WaitingForAttestation { noise } => noise,
                    _ => unreachable!(),
                };
                match Self::connection_request(&mut noise) {
                    Ok(noise_data) => {
                        let connect_req = PeerConnectRequest {
                            node_type:  self.node_params.node_type.into(),
                            ias_report: Some(ias_report),
                            noise_data,
                        };
                        let mut connect_req_data = Vec::with_capacity(connect_req.encoded_len());
                        assert!(connect_req.encode(&mut connect_req_data).is_ok());

                        kbupd_send(EnclaveMessage {
                            inner: Some(EnclaveMessageInner::SendMessageRequest(SendMessageRequest {
                                node_id:   self.remote_node_id.to_vec(),
                                data:      connect_req_data,
                                syn:       true,
                                debug_msg: None,
                            })),
                        });
                        *session = SessionState::Initiated { noise };
                        Ok(None)
                    }
                    Err(noise_error) => {
                        error!("noise error connecting to {}: {}", &self.remote_node_id, noise_error);
                        Err(())
                    }
                }
            }
            session @ SessionState::Connected { .. } => {
                let (noise, their_handshake_hash, final_handshake_hash) = match std::mem::replace(session, SessionState::Disconnected) {
                    SessionState::Connected { noise, their_handshake_hash, final_handshake_hash } =>
                        (noise, their_handshake_hash, final_handshake_hash),
                    _ => unreachable!(),
                };
                match validate_ias_report(Some(&ias_report), &their_handshake_hash.hash) {
                    Ok(attestation) => {
                        let handshake_hash = final_handshake_hash;
                        *session = SessionState::Authorized { noise, attestation: Some(attestation), handshake_hash };
                        Ok(Some(attestation))
                    }
                    Err(attestation_error) => {
                        error!("error validating attestation report for {}: {}", &self.remote_node_id, attestation_error);
                        Err(())
                    }
                }
            }
            SessionState::Authorized { attestation, handshake_hash, .. } => {
                match validate_ias_report(Some(&ias_report), &handshake_hash.get_hash_for_node(&self.remote_node_id)) {
                    Ok(new_attestation) => {
                        verbose!("validated attestation report for {}: {}", &self.remote_node_id, &new_attestation);
                        *attestation = Some(new_attestation);
                        Ok(None)
                    }
                    Err(attestation_error) => {
                        error!("error validating attestation report for {}: {}", &self.remote_node_id, attestation_error);
                        Err(())
                    }
                }
            }
            _ => {
                Err(())
            }
        }
    }
}

impl<M,R> RemoteMessageSender for RemoteState<M,R>
where M: prost::Message + 'static,
      R: prost::Message + Default + 'static,
{
    type Message = M;
    fn send(&self, message: Rc<Self::Message>) -> Result<(), ()> {
        self.shared.as_ref().borrow_mut().send(message)
    }
}

impl<M,R> fmt::Display for RemoteState<M,R>
where M: prost::Message + 'static,
      R: prost::Message + Default + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RemoteState")
         .field(&self.remote_node_id)
         .field(&self.remote_type)
         .finish()
    }
}

fn get_handshake_hash(noise: &snow::HandshakeState) -> Result<HandshakeHash, snow::Error> {
    let handshake_hash_slice = noise.get_handshake_hash();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(handshake_hash_slice);
    Ok(HandshakeHash { hash })
}

fn write_noise_message(noise: &mut snow::TransportState, noise_buffers: &SharedNoiseBuffers, payload: &[u8]) -> Result<Vec<u8>, snow::Error> {
    let mut noise_buffer_ref = RefCell::borrow_mut(&noise_buffers.inner.write_buffer);
    let chunk_buffer         = &mut noise_buffer_ref.0;

    let payload_chunks = payload.chunks(65519);
    let encrypted_msg_buf_len = payload_chunks.len().saturating_mul(NOISE_CHUNK_MAX_LENGTH);
    let mut encrypted_msg_buf = Vec::with_capacity(encrypted_msg_buf_len);
    for payload_chunk in payload_chunks {
        let encrypted_chunk_len = noise.write_message(payload_chunk, chunk_buffer)?;
        let encrypted_chunk_buf = chunk_buffer.get_mut(..encrypted_chunk_len).unwrap_or_else(|| unreachable!());
        encrypted_msg_buf.extend_from_slice(encrypted_chunk_buf);
        noise.rekey_outgoing();
    }
    Ok(encrypted_msg_buf)
}

fn read_noise_message(noise: &mut snow::TransportState, shared_noise_buffers: &SharedNoiseBuffers, encrypted: &[u8]) -> Result<SecretValue<Vec<u8>>, snow::Error> {
    let mut noise_buffer = shared_noise_buffers.inner.read_buffer.take().unwrap_or_default();
    match read_noise_message_with_buffer(noise, &mut noise_buffer.get_mut().0, encrypted) {
        Ok(msg_data) => {
            noise_buffer.clear_to(msg_data.get().len());
            shared_noise_buffers.inner.read_buffer.set(Some(noise_buffer));
            Ok(msg_data)
        }
        Err(error) => {
            noise_buffer.clear();
            shared_noise_buffers.inner.read_buffer.set(Some(noise_buffer));
            Err(error)
        }
    }
}

fn read_noise_message_with_buffer(noise: &mut snow::TransportState, chunk_buffer: &mut [u8; NOISE_CHUNK_MAX_LENGTH], encrypted: &[u8]) -> Result<SecretValue<Vec<u8>>, snow::Error> {
    let encrypted_chunks = encrypted.chunks(NOISE_CHUNK_MAX_LENGTH);
    let msg_buf_len = encrypted_chunks.len().saturating_mul(65519);
    let mut msg_buf = SecretValue::new(Vec::with_capacity(msg_buf_len));
    for encrypted_chunk in encrypted_chunks {
        let decrypted_chunk_len = noise.read_message(encrypted_chunk, chunk_buffer)?;
        let decrypted_chunk_buf = chunk_buffer.get_mut(..decrypted_chunk_len).unwrap_or_else(|| unreachable!());
        msg_buf.get_mut().extend_from_slice(decrypted_chunk_buf);
        noise.rekey_incoming();
    }
    Ok(msg_buf)
}

impl fmt::Display for SessionState {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionState::Disconnected                 => write!(fmt, "Disconnected"),
            SessionState::WaitingForAttestation { .. } => write!(fmt, "WaitingForAttestation"),
            SessionState::Initiated             { .. } => write!(fmt, "Initiated"),
            SessionState::Connected             { .. } => write!(fmt, "Connected"),
            SessionState::Accepted              { .. } => write!(fmt, "Accepted"),
            SessionState::Responded             { .. } => write!(fmt, "Responded"),
            SessionState::Authorized            { .. } => write!(fmt, "Authorized"),
        }
    }
}

static IAS_TRUST_ANCHORS: &webpki::TLSServerTrustAnchors<'_> = &webpki::TLSServerTrustAnchors(&[
    webpki::TrustAnchor {
        subject: &[49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 11, 48, 9, 6, 3, 85, 4, 8, 12, 2, 67, 65, 49, 20, 48, 18, 6, 3, 85, 4, 7, 12, 11, 83, 97, 110, 116, 97, 32, 67, 108, 97, 114, 97, 49, 26, 48, 24, 6, 3, 85, 4, 10, 12, 17, 73, 110, 116, 101, 108, 32, 67, 111, 114, 112, 111, 114, 97, 116, 105, 111, 110, 49, 48, 48, 46, 6, 3, 85, 4, 3, 12, 39, 73, 110, 116, 101, 108, 32, 83, 71, 88, 32, 65, 116, 116, 101, 115, 116, 97, 116, 105, 111, 110, 32, 82, 101, 112, 111, 114, 116, 32, 83, 105, 103, 110, 105, 110, 103, 32, 67, 65],
        spki:    &[48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 143, 0, 48, 130, 1, 138, 2, 130, 1, 129, 0, 159, 60, 100, 126, 181, 119, 60, 187, 81, 45, 39, 50, 192, 215, 65, 94, 187, 85, 160, 250, 158, 222, 46, 100, 145, 153, 230, 130, 29, 185, 16, 213, 49, 119, 55, 9, 119, 70, 106, 106, 94, 71, 134, 204, 210, 221, 235, 212, 20, 157, 106, 47, 99, 37, 82, 157, 209, 12, 201, 135, 55, 176, 119, 156, 26, 7, 226, 156, 71, 161, 174, 0, 73, 72, 71, 108, 72, 159, 69, 165, 161, 93, 122, 200, 236, 198, 172, 198, 69, 173, 180, 61, 135, 103, 157, 245, 156, 9, 59, 197, 162, 233, 105, 108, 84, 120, 84, 27, 151, 158, 117, 75, 87, 57, 20, 190, 85, 211, 47, 244, 192, 157, 223, 39, 33, 153, 52, 205, 153, 5, 39, 179, 249, 46, 215, 143, 191, 41, 36, 106, 190, 203, 113, 36, 14, 243, 156, 45, 113, 7, 180, 71, 84, 90, 127, 251, 16, 235, 6, 10, 104, 169, 133, 128, 33, 158, 54, 145, 9, 82, 104, 56, 146, 214, 165, 226, 168, 8, 3, 25, 62, 64, 117, 49, 64, 78, 54, 179, 21, 98, 55, 153, 170, 130, 80, 116, 64, 151, 84, 162, 223, 232, 245, 175, 213, 254, 99, 30, 31, 194, 175, 56, 8, 144, 111, 40, 167, 144, 217, 221, 159, 224, 96, 147, 155, 18, 87, 144, 197, 128, 93, 3, 125, 245, 106, 153, 83, 27, 150, 222, 105, 222, 51, 237, 34, 108, 193, 32, 125, 16, 66, 181, 201, 171, 127, 64, 79, 199, 17, 192, 254, 71, 105, 251, 149, 120, 177, 220, 14, 196, 105, 234, 26, 37, 224, 255, 153, 20, 136, 110, 242, 105, 155, 35, 91, 180, 132, 125, 214, 255, 64, 182, 6, 230, 23, 7, 147, 194, 251, 152, 179, 20, 88, 127, 156, 253, 37, 115, 98, 223, 234, 177, 11, 59, 210, 217, 118, 115, 161, 164, 189, 68, 196, 83, 170, 244, 127, 193, 242, 211, 208, 243, 132, 247, 74, 6, 248, 156, 8, 159, 13, 166, 205, 183, 252, 238, 232, 201, 130, 26, 142, 84, 242, 92, 4, 22, 209, 140, 70, 131, 154, 95, 128, 18, 251, 221, 61, 199, 77, 37, 98, 121, 173, 194, 192, 213, 90, 255, 111, 6, 34, 66, 93, 27, 2, 3, 1, 0, 1],
        name_constraints: None,
    },
]);
static IAS_CHAIN_ALGOS: &'static [&webpki::SignatureAlgorithm] = &[
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
];

#[derive(Debug)]
enum AttestationVerificationError {
    NoAttestationReport,
    InvalidJson(serde_json::Error),
    InvalidCertificate(webpki::Error),
    InvalidSignature(webpki::Error),
    WrongVersion(u64),
    InvalidTimestamp(String),
    StaleRevocationList,
    InvalidQuote(SgxQuoteDecodeError),
    #[cfg(not(feature = "insecure"))]
    IsDebugQuote,
    InvalidQuoteReportData,
    InvalidMrenclave([u8; 32]),
    CreateReportError(u32),
    AttestationError(String),
}

fn parse_ias_timestamp(timestamp: &str) -> Result<u64, AttestationVerificationError> {
    (NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%S%.f").ok())
        .map(|naive_datetime: NaiveDateTime| DateTime::from_utc(naive_datetime, Utc))
        .and_then(|utc_datetime: DateTime<Utc>| utc_datetime.timestamp().to_u64())
        .ok_or_else(|| AttestationVerificationError::InvalidTimestamp(timestamp.to_owned()))
}

fn validate_ias_report(maybe_ias_report:     Option<&IasReport>,
                       expected_report_data: &[u8])
                       -> Result<AttestationParameters, AttestationVerificationError> {
    #[cfg(feature = "insecure")] {
        match maybe_ias_report.as_ref() {
            Some(ias_report) if ias_report.body.is_empty() => {
                return Ok(AttestationParameters { unix_timestamp_seconds: 0 });
            }
            _ => (),
        }
    }

    let ias_report = match maybe_ias_report {
        Some(ias_report) => ias_report,
        None => {
            return Err(AttestationVerificationError::NoAttestationReport);
        }
    };

    let body: IasReportBody = serde_json::from_slice(&ias_report.body[..])
        .map_err(AttestationVerificationError::InvalidJson)?;

    if body.version != 3 {
        return Err(AttestationVerificationError::WrongVersion(body.version));
    }

    match body.isvEnclaveQuoteStatus.as_str() {
        "OK" => {
        }
        #[cfg(feature = "insecure")]
        "GROUP_OUT_OF_DATE" | "CONFIGURATION_NEEDED" => {
        }
        "SIGRL_VERSION_MISMATCH" => {
            return Err(AttestationVerificationError::StaleRevocationList);
        }
        _ => {
            return Err(AttestationVerificationError::AttestationError(body.isvEnclaveQuoteStatus));
        }
    }

    let quote = SgxQuote::decode(&mut &body.isvEnclaveQuoteBody[..])
        .map_err(AttestationVerificationError::InvalidQuote)?;

    if &quote.report_data.0[0..32] != expected_report_data {
        return Err(AttestationVerificationError::InvalidQuoteReportData);
    }

    let our_report = sgx::create_report_raw(None, &[0; 64])
        .map_err(AttestationVerificationError::CreateReportError)?;
    if quote.mrenclave != our_report.body.mr_enclave.m {
        return Err(AttestationVerificationError::InvalidMrenclave(quote.mrenclave));
    }

    if quote.is_debug_quote() {
        #[cfg(not(feature = "insecure"))] {
            return Err(AttestationVerificationError::IsDebugQuote);
        }
    }

    let unix_timestamp_seconds = parse_ias_timestamp(&body.timestamp)?;
    let certificate = (ias_report.certificates.get(0).ok_or(webpki::Error::BadDER))
        .and_then(|certificate: &Vec<u8>| webpki::EndEntityCert::from(certificate))
        .map_err(AttestationVerificationError::InvalidCertificate)?;
    let chain       = (ias_report.certificates.get(1..).unwrap_or_default().iter())
        .map(|cert: &Vec<u8>| &cert[..])
        .collect::<Vec<_>>();
    certificate.verify_is_valid_tls_server_cert(IAS_CHAIN_ALGOS, IAS_TRUST_ANCHORS, &chain, webpki::Time::from_seconds_since_unix_epoch(unix_timestamp_seconds))
               .map_err(AttestationVerificationError::InvalidCertificate)?;
    certificate.verify_signature(&webpki::RSA_PKCS1_2048_8192_SHA256, &ias_report.body, &ias_report.signature)
               .map_err(AttestationVerificationError::InvalidSignature)?;
    Ok(AttestationParameters { unix_timestamp_seconds })
}

#[allow(non_snake_case)]
#[derive(Deserialize)]
pub struct IasReportBody {
    pub isvEnclaveQuoteStatus: String,

    #[serde(deserialize_with = "deserialize_base64")]
    pub isvEnclaveQuoteBody: Vec<u8>,

    pub version: u64,

    pub timestamp: String,
}

impl fmt::Display for AttestationVerificationError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, fmt)
    }
}

//
// NodeId impls
//

impl<T: AsRef<[u8]>> From<T> for NodeId {
    fn from(from: T) -> Self {
        let from = from.as_ref();
        if from.len() == NODE_ID_LEN {
            let mut id = [0; NODE_ID_LEN];
            id.copy_from_slice(from);
            NodeId::Valid(id)
        } else {
            NodeId::Invalid(from.to_vec())
        }
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&util::ToHex(self), fmt)
    }
}
impl fmt::Debug for NodeId {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

impl Deref for NodeId {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            NodeId::Valid(id)   => id,
            NodeId::Invalid(id) => id,
        }
    }
}

//
// NodeParams impls
//

impl NodeParams {
    pub fn generate(node_type: NodeType) -> Self {
        let params  = NOISE_PARAMS.parse().unwrap_or_else(|_| unreachable!());
        let builder = snow::Builder::with_resolver(params, Box::new(SnowResolver));
        let keypair = builder.generate_keypair().unwrap_or_else(|_| unreachable!());
        assert_eq!(keypair.public.len(), 32);
        Self {
            node_key:  keypair.private.into(),
            node_id:   keypair.public.into(),
            node_type,
        }
    }
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }
}

//
// NodeType impls
//

impl fmt::Display for NodeType {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeType::None     => write!(fmt, "none"),
            NodeType::Replica  => write!(fmt, "replica"),
            NodeType::Frontend => write!(fmt, "frontend"),
        }
    }
}

//
// HandshakeHash impls
//

impl HandshakeHash {
    fn get_hash_for_node(&self, node_id: &NodeId) -> [u8; 32] {
        let mut hasher = SHA256Context::default();
        let mut output = [0u8; 32];
        hasher.update(&self.hash);
        hasher.update(node_id);
        hasher.result(&mut output);
        output
    }
}

//
// AttestationParameters impls
//

impl AttestationParameters {
    pub fn new(unix_timestamp: Duration) -> Self {
        Self {
            unix_timestamp_seconds: unix_timestamp.as_secs(),
        }
    }
}

//
// Shared impls
//

impl<M> Shared<M>
where M: prost::Message + 'static,
{
    fn attestation(&self) -> Option<AttestationParameters> {
        match &self.session {
            SessionState::Authorized { attestation, .. } => *attestation,
            _ => None,
        }
    }

    pub fn send(&mut self, msg: impl Borrow<M>) -> Result<(), ()> {
        match &mut self.session {
            SessionState::Authorized { noise, .. } => {
                let mut encoded_msg_data = SecretValue::new(Vec::with_capacity(msg.borrow().encoded_len()));
                assert!(msg.borrow().encode(encoded_msg_data.get_mut()).is_ok());
                match write_noise_message(noise, &self.noise_buffer, encoded_msg_data.get()) {
                    Ok(encrypted_msg_data) => {
                        #[allow(unused_assignments, unused_mut)]
                        let mut debug_msg = None;
                        #[cfg(feature = "insecure")]
                        #[cfg(feature = "trace")]
                        {
                            debug_msg = Some(format!("{:?}", msg.borrow()).into());
                        }
                        kbupd_send(EnclaveMessage {
                            inner: Some(EnclaveMessageInner::SendMessageRequest(SendMessageRequest {
                                node_id: self.remote_node_id.to_vec(),
                                debug_msg,
                                data: encrypted_msg_data,
                                syn:  false,
                            }))
                        });
                        Ok(())
                    }
                    Err(err) => {
                        error!("unexpected error encrypting message to {}: {}", &self.remote_node_id, err);
                        Err(())
                    }
                }
            }
            _ => {
                verbose!("dropped message to remote {} in {} state", &self.remote_node_id, &self.session);
                Err(())
            }
        }
    }
}

//
// NoiseBuffer impls
//

impl Default for NoiseBuffer {
    fn default() -> Self {
        Self([0; NOISE_CHUNK_MAX_LENGTH])
    }
}

impl AsMut<[u8]> for Box<NoiseBuffer> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

//
// RemoteSender impls
//

impl<M> RemoteCommon for RemoteSender<M>
where M: prost::Message + 'static,
{
    fn id(&self) -> &NodeId {
        &self.id
    }
    fn attestation(&self) -> Option<AttestationParameters> {
        self.shared.as_ref().borrow_mut().attestation()
    }
}

impl<M> RemoteMessageSender for RemoteSender<M>
where M: prost::Message + 'static,
{
    type Message = M;
    fn send(&self, message: Rc<Self::Message>) -> Result<(), ()> {
        self.shared.as_ref().borrow_mut().send(message)
    }
}

impl<M> fmt::Display for RemoteSender<M>
where M: prost::Message + 'static,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.id(), fmt)
    }
}

impl<M> Clone for RemoteSender<M>
where M: prost::Message + 'static,
{
    fn clone(&self) -> Self {
        Self {
            id:     self.id.clone(),
            shared: Rc::clone(&self.shared),
        }
    }
}

//
// AttestationParameters impls
//

impl Copy for AttestationParameters {}
impl Eq for AttestationParameters {}
impl PartialOrd for AttestationParameters {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(Ord::cmp(self, other))
    }
}
impl Ord for AttestationParameters {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.unix_timestamp_seconds.cmp(&other.unix_timestamp_seconds)
    }
}
impl fmt::Display for AttestationParameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_ias_timestamp() {
        assert!(parse_ias_timestamp("2020-08-01T15:18:06.123456789").is_ok());
        assert!(parse_ias_timestamp("2020-08-01T15:18:06.12345678").is_ok());
        assert!(parse_ias_timestamp("2020-08-01T15:18:06.1234567").is_ok());
        assert!(parse_ias_timestamp("2020-08-01T15:18:06.123456").is_ok());
        assert!(parse_ias_timestamp("2020-08-01T15:18:06.12345").is_ok());
        assert!(parse_ias_timestamp("2020-08-01T15:18:06.1234").is_ok());
        assert!(parse_ias_timestamp("2020-08-01T15:18:06.123").is_ok());
        assert!(parse_ias_timestamp("2020-08-01T15:18:06.12").is_ok());
        assert!(parse_ias_timestamp("2020-08-01T15:18:06.1").is_ok());
        assert!(parse_ias_timestamp("2020-08-01T15:18:06").is_ok());
    }
}
