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

use std::fmt;
use std::mem;
use std::os::raw::*;

use byteorder::{ByteOrder};

use crate::protobufs::kbupd::*;

use super::ocalls;
use super::sgx::*;

use super::bindgen_wrapper::{
    sgx_calc_quote_size,
    sgx_get_quote,
    sgx_init_quote,
    sgx_target_info_t,
    sgx_report_t,
    sgx_spid_t,
    sgx_status_t,
    sgx_quote_t,
    sgxsd_enclave_get_next_report,
    sgxsd_enclave_negotiate_request,
    sgxsd_enclave_node_init,
    sgxsd_enclave_set_current_quote,
    sgxsd_enclave_server_start,
    sgxsd_enclave_server_call,
    sgxsd_msg_tag_t,
    sgxsd_msg_tag__bindgen_ty_1,
    sgxsd_node_init_args_t,
    sgxsd_request_negotiation_response_t,
    sgxsd_server_init_args_t,
    SGX_UNLINKABLE_SIGNATURE,
};

pub use super::bindgen_wrapper::{
    sgxsd_server_state_handle_t as SgxsdServerHandle,
    sgxsd_server_handle_call_args_t as SgxsdServerCallArgs,
    sgxsd_request_negotiation_request as SgxsdRequestNegotiationRequest,
    sgxsd_request_negotiation_response as SgxsdRequestNegotiationResponse,
    sgxsd_curve25519_public_key_t as SgxsdCurve25519PublicKey,
    sgxsd_msg_header_t as SgxsdMessageHeader,
    sgxsd_aes_gcm_iv_t as SgxsdAesGcmIv,
    sgxsd_aes_gcm_mac_t as SgxsdAesGcmMac,
    sgxsd_pending_request_id_t as SgxsdPendingRequestId,
    KBUPD_REQUEST_TYPE_ANY,
    KBUPD_REQUEST_TYPE_BACKUP,
    KBUPD_REQUEST_TYPE_RESTORE,
    KBUPD_REQUEST_TYPE_DELETE,
};

pub struct MessageReply {
    pub iv: SgxsdAesGcmIv,
    pub mac: SgxsdAesGcmMac,
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

//
// MessageTag impls
//

impl MessageTag {
    fn into_tag(self) -> sgxsd_msg_tag_t {
        sgxsd_msg_tag_t {
            __bindgen_anon_1: sgxsd_msg_tag__bindgen_ty_1 {
                p_tag: Box::into_raw(Box::new(self)) as *mut c_void
            }
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
            SgxsdErrorKind::Sgx      => "call failed",
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
        SgxStatus::Success => {
            match SgxStatus::from(res) {
                SgxStatus::Success => Ok(()),
                status             => Err(SgxsdError { kind: SgxsdErrorKind::Returned, status, name }),
            }
        }
        status => Err(SgxsdError { kind: SgxsdErrorKind::Sgx, status, name }),
    }
}

pub fn sgxsd_node_init(enclave_id: SgxEnclaveId, pending_requests_table_order: u8) -> SgxsdResult<()> {
    let args = sgxsd_node_init_args_t { pending_requests_table_order };
    sgxsd_res(|res| unsafe { sgxsd_enclave_node_init(enclave_id, res, &args) }, "sgxsd_enclave_node_init")
}

pub fn sgxsd_negotiate_request(enclave_id: SgxEnclaveId, request: &SgxsdRequestNegotiationRequest)
                               -> SgxsdResult<SgxsdRequestNegotiationResponse> {
    let mut response: sgxsd_request_negotiation_response_t = Default::default();
    sgxsd_res(|res| unsafe { sgxsd_enclave_negotiate_request(enclave_id, res, request, &mut response) },
              "sgxsd_enclave_negotiate_request")
        .map(|_| response)
}

pub fn sgxsd_get_next_quote(enclave_id: SgxEnclaveId, spid: &[u8; 16], sig_rl: &[u8]) -> SgxsdResult<SgxQuote> {
    let mut quote_size: u32 = 0;
    let (p_sig_rl, sig_rl_size) = get_sig_rl_ptr(sig_rl);
    sgxsd_res(|_| unsafe { sgx_calc_quote_size(p_sig_rl, sig_rl_size, &mut quote_size) }, "sgx_calc_quote_size")
        .and_then(|_| {
            let mut quote: Vec<u8> = vec![0; quote_size as usize];
            sgxsd_get_next_quote_sized(enclave_id, spid, sig_rl, &mut quote[..])
                .map(|gid| SgxQuote {
                    gid,
                    data: quote,
                })
        })
}

fn sgxsd_get_next_quote_sized(enclave_id: SgxEnclaveId, spid: &[u8; 16], sig_rl: &[u8],
                              p_quote: &mut [u8]) -> SgxsdResult<u32> {
    // NB: sgx_init_quote expects qe_target_info to be zeroed (undocumented!)
    let mut qe_target_info: sgx_target_info_t = Default::default();
    let mut gid:            [u8; 4]           = Default::default();
    sgxsd_res(|_| unsafe { sgx_init_quote(&mut qe_target_info, &mut gid) }, "sgx_init_quote")
        .and_then(|_| {
            let mut report: sgx_report_t = Default::default();
            sgxsd_res(|res| unsafe { sgxsd_enclave_get_next_report(
                enclave_id, res, qe_target_info, &mut report
            )}, "sgxsd_enclave_get_next_quote")?;
            Ok(report)
        })
        .and_then(|report| {
            let quote_size = p_quote.len() as u32;
            let spid_struct = sgx_spid_t { id: *spid };
            let p_nonce = std::ptr::null_mut();
            let (p_sig_rl, sig_rl_size) = get_sig_rl_ptr(sig_rl);
            let p_qe_report = std::ptr::null_mut();
            sgxsd_res(|_| unsafe { sgx_get_quote(
                &report, SGX_UNLINKABLE_SIGNATURE,
                &spid_struct, p_nonce, p_sig_rl, sig_rl_size, p_qe_report, p_quote.as_mut_ptr() as *mut sgx_quote_t, quote_size
            )}, "sgx_get_quote")
        })
        .map(|()| byteorder::LittleEndian::read_u32(&gid))
}

pub fn sgxsd_set_current_quote(enclave_id: SgxEnclaveId) -> SgxsdResult<()> {
    sgxsd_res(|res| unsafe { sgxsd_enclave_set_current_quote(enclave_id, res) },
              "sgxsd_set_current_quote")
}

pub fn sgxsd_server_start(enclave_id: SgxEnclaveId, server_handle: SgxsdServerHandle) -> SgxsdResult<Vec<EnclaveMessage>> {
    let args = sgxsd_server_init_args_t {};
    sgxsd_res(|res| unsafe { sgxsd_enclave_server_start(enclave_id, res, &args, server_handle) },
              "sgxsd_enclave_server_start")?;
    Ok(ocalls::take_enclave_messages())
}
pub fn sgxsd_server_call(enclave_id:    SgxEnclaveId,
                         args:          SgxsdServerCallArgs,
                         msg_header:    &SgxsdMessageHeader,
                         msg_data:      &[u8],
                         reply_fun:     impl FnOnce(SgxsdResult<MessageReply>) + Send + 'static,
                         server_handle: SgxsdServerHandle)
                         -> SgxsdResult<Vec<EnclaveMessage>>
{
    let tag = MessageTag {
        callback: Box::new(reply_fun),
    }.into_tag();
    sgxsd_res(|res| unsafe { sgxsd_enclave_server_call(
        enclave_id, res, &args, msg_header,
        msg_data.as_ptr() as *mut u8, msg_data.len(),
        tag, server_handle)
    }, "sgxsd_enclave_server_call")
        .map(|()| ocalls::take_enclave_messages())
        .map_err(|error: SgxsdError| {
            if let Some(message_tag) = unsafe { MessageTag::from_tag(tag) } {
                (message_tag.callback)(Err(error.clone()));
            }
            error
        })
}
