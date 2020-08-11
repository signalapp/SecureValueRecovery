//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::fmt;
use std::mem;
use std::os::raw::*;

use sgx_sdk_ffi::*;

use crate::protobufs::kbupd::*;

use super::ocalls;

use super::bindgen_wrapper::{
    sgx_quote_t, sgx_status_t, sgxsd_enclave_get_next_report, sgxsd_enclave_negotiate_request, sgxsd_enclave_node_init,
    sgxsd_enclave_server_call, sgxsd_enclave_server_start, sgxsd_enclave_set_current_quote, sgxsd_msg_tag__bindgen_ty_1, sgxsd_msg_tag_t,
    sgxsd_node_init_args_t, sgxsd_request_negotiation_response_t, sgxsd_server_init_args_t,
};

pub use super::bindgen_wrapper::{
    sgxsd_aes_gcm_iv_t as SgxsdAesGcmIv, sgxsd_aes_gcm_mac_t as SgxsdAesGcmMac, sgxsd_curve25519_public_key_t as SgxsdCurve25519PublicKey,
    sgxsd_msg_header_t as SgxsdMessageHeader, sgxsd_pending_request_id_t as SgxsdPendingRequestId,
    sgxsd_request_negotiation_request as SgxsdRequestNegotiationRequest,
    sgxsd_request_negotiation_response as SgxsdRequestNegotiationResponse, sgxsd_server_handle_call_args_t as SgxsdServerCallArgs,
    sgxsd_server_state_handle_t as SgxsdServerHandle, KBUPD_REQUEST_TYPE_ANY, KBUPD_REQUEST_TYPE_BACKUP, KBUPD_REQUEST_TYPE_DELETE,
    KBUPD_REQUEST_TYPE_RESTORE,
};

pub struct MessageReply {
    pub iv:   SgxsdAesGcmIv,
    pub mac:  SgxsdAesGcmMac,
    pub data: Vec<u8>,
}

pub struct MessageTag {
    pub callback: Box<dyn FnOnce(SgxsdResult<MessageReply>) + Send>,
}

pub struct SgxQuote {
    pub gid:  u32,
    pub data: Vec<u8>,
}

pub type SgxsdResult<T> = Result<T, SgxsdError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SgxsdErrorKind {
    Returned,
    Sgx,
}

#[derive(Clone, Copy, failure::Fail)]
pub struct SgxsdError {
    pub kind:   SgxsdErrorKind,
    pub status: SgxStatus,
    pub name:   &'static str,
}

pub trait SgxResultExt<T> {
    fn sgxsd_context(self, name: &'static str) -> SgxsdResult<T>;
}

//
// MessageTag impls
//

impl MessageTag {
    fn into_tag(self) -> sgxsd_msg_tag_t {
        sgxsd_msg_tag_t {
            __bindgen_anon_1: sgxsd_msg_tag__bindgen_ty_1 {
                p_tag: Box::into_raw(Box::new(self)) as *mut c_void,
            },
        }
    }

    pub unsafe fn from_tag(raw_tag: sgxsd_msg_tag_t) -> Option<MessageTag> {
        let p_tag = raw_tag.__bindgen_anon_1.p_tag;
        if !p_tag.is_null() {
            Some(*Box::from_raw(p_tag as *mut MessageTag))
        } else {
            None
        }
    }
}

//
// SgxsdErrorKind impls
//

impl SgxsdErrorKind {
    fn as_str(&self) -> &'static str {
        match self {
            SgxsdErrorKind::Returned => "returned error",
            SgxsdErrorKind::Sgx => "call failed",
        }
    }
}

//
// SgxsdError impls
//

impl fmt::Debug for SgxsdError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        if let Some(sgx_error) = self.status.err() {
            write!(fmt, "{} {}: {}", self.name, self.kind.as_str(), sgx_error)
        } else {
            write!(fmt, "{} {}", self.name, self.kind.as_str())
        }
    }
}
impl fmt::Display for SgxsdError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, fmt)
    }
}

//
// SgxResultExt impls
//

impl<T> SgxResultExt<T> for SgxResult<T> {
    fn sgxsd_context(self, name: &'static str) -> SgxsdResult<T> {
        match self {
            Ok(value) => Ok(value),
            Err(status) => Err(SgxsdError {
                kind: SgxsdErrorKind::Sgx,
                status,
                name,
            }),
        }
    }
}

//
// SgxQuote impls
//

impl SgxQuote {
    pub const SIZE: usize = mem::size_of::<sgx_quote_t>() - 4;
}

//
// plain functions
//

pub fn sgxsd_res<F>(ecall: F, name: &'static str) -> SgxsdResult<()>
where F: FnOnce(&mut sgx_status_t) -> sgx_status_t {
    let mut res: sgx_status_t = SgxStatus::Success.into();
    match SgxStatus::from(ecall(&mut res)) {
        SgxStatus::Success => match SgxStatus::from(res) {
            SgxStatus::Success => Ok(()),
            status => Err(SgxsdError {
                kind: SgxsdErrorKind::Returned,
                status,
                name,
            }),
        },
        status => Err(SgxsdError {
            kind: SgxsdErrorKind::Sgx,
            status,
            name,
        }),
    }
}

pub fn sgxsd_node_init(enclave_id: SgxEnclaveId, pending_requests_table_order: u8) -> SgxsdResult<()> {
    let args = sgxsd_node_init_args_t {
        pending_requests_table_order,
    };
    sgxsd_res(
        |res| unsafe { sgxsd_enclave_node_init(enclave_id, res, &args) },
        "sgxsd_enclave_node_init",
    )
}

pub fn sgxsd_negotiate_request(
    enclave_id: SgxEnclaveId,
    request: &SgxsdRequestNegotiationRequest,
) -> SgxsdResult<SgxsdRequestNegotiationResponse>
{
    let mut response: sgxsd_request_negotiation_response_t = Default::default();
    sgxsd_res(
        |res| unsafe { sgxsd_enclave_negotiate_request(enclave_id, res, request, &mut response) },
        "sgxsd_enclave_negotiate_request",
    )
    .map(|_| response)
}

pub fn sgxsd_get_next_quote(enclave_id: SgxEnclaveId, spid: &[u8; 16], sig_rl: &[u8]) -> SgxsdResult<SgxQuote> {
    let (gid, qe_target_info) = sgx_sdk_ffi::init_quote().sgxsd_context("sgx_init_quote")?;
    let mut report: SgxReport = Default::default();
    sgxsd_res(
        |res| unsafe { sgxsd_enclave_get_next_report(enclave_id, res, qe_target_info, &mut report) },
        "sgxsd_enclave_get_next_quote",
    )?;
    let data = sgx_sdk_ffi::get_quote(report, spid, sig_rl).sgxsd_context("sgx_get_quote")?;
    Ok(SgxQuote { gid, data })
}

pub fn sgxsd_set_current_quote(enclave_id: SgxEnclaveId) -> SgxsdResult<()> {
    sgxsd_res(
        |res| unsafe { sgxsd_enclave_set_current_quote(enclave_id, res) },
        "sgxsd_set_current_quote",
    )
}

pub fn sgxsd_server_start(enclave_id: SgxEnclaveId, server_handle: SgxsdServerHandle) -> SgxsdResult<Vec<EnclaveMessage>> {
    let args = sgxsd_server_init_args_t {};
    sgxsd_res(
        |res| unsafe { sgxsd_enclave_server_start(enclave_id, res, &args, server_handle) },
        "sgxsd_enclave_server_start",
    )?;
    Ok(ocalls::take_enclave_messages())
}
pub fn sgxsd_server_call(
    enclave_id: SgxEnclaveId,
    args: SgxsdServerCallArgs,
    msg_header: &SgxsdMessageHeader,
    msg_data: &[u8],
    reply_fun: impl FnOnce(SgxsdResult<MessageReply>) + Send + 'static,
    server_handle: SgxsdServerHandle,
) -> SgxsdResult<Vec<EnclaveMessage>>
{
    let tag = MessageTag {
        callback: Box::new(reply_fun),
    }
    .into_tag();
    sgxsd_res(
        |res| unsafe {
            sgxsd_enclave_server_call(
                enclave_id,
                res,
                &args,
                msg_header,
                msg_data.as_ptr() as *mut u8,
                msg_data.len(),
                tag,
                server_handle,
            )
        },
        "sgxsd_enclave_server_call",
    )
    .map(|()| ocalls::take_enclave_messages())
    .map_err(|error: SgxsdError| {
        if let Some(message_tag) = unsafe { MessageTag::from_tag(tag) } {
            (message_tag.callback)(Err(error.clone()));
        }
        error
    })
}
