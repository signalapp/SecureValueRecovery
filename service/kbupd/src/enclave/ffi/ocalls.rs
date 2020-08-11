//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::mem;

use prost::Message;
use sgx_sdk_ffi::*;

use crate::protobufs::kbupd::*;
use crate::*;

use super::sgxsd::*;

use super::bindgen_wrapper::{sgx_status_t, sgxsd_msg_tag_t};

//
// kbupd-specific ocalls
//

thread_local! {
    static ENCLAVE_MESSAGES: std::cell::RefCell<Vec<EnclaveMessage>> = Default::default();
}

#[must_use]
pub fn take_enclave_messages() -> Vec<EnclaveMessage> {
    ENCLAVE_MESSAGES.with(|cell| mem::replace(&mut *cell.borrow_mut(), Default::default()))
}

#[no_mangle]
pub extern "C" fn kbupd_enclave_ocall_recv_enclave_msg(p_data: *const u8, data_size: usize) {
    let data = unsafe { std::slice::from_raw_parts(p_data, data_size) };

    match EnclaveMessageBatch::decode(data) {
        Ok(batch) => {
            ENCLAVE_MESSAGES.with(|cell| cell.borrow_mut().extend(batch.messages));
        }
        Err(err) => {
            error!("enclave message decode error: {:?}", err);
        }
    }
}

#[no_mangle]
pub extern "C" fn kbupd_enclave_ocall_alloc(p_size: *mut usize) -> *mut libc::c_void {
    if p_size.is_null() {
        return std::ptr::null_mut();
    }
    let want_size = unsafe { *p_size };
    info!("allocating enclave storage of size {}", want_size);

    let mut data_vec: Vec<u8> = Vec::with_capacity(want_size);
    let data: *mut u8 = data_vec.as_mut_ptr();
    let size: usize = data_vec.capacity();
    std::mem::forget(data_vec);

    match unsafe { libc::mlock(data as *const libc::c_void, size) } {
        0 => (),
        mlock_res => {
            warn!("could not mlock enclave storage: {}", mlock_res);
        }
    }

    unsafe { *p_size = size };
    data as *mut libc::c_void
}

#[no_mangle]
pub extern "C" fn kbupd_enclave_ocall_panic(p_msg: *const u8, msg_size: usize) {
    use std::io::Write;

    let msg = if !p_msg.is_null() {
        unsafe { std::slice::from_raw_parts(p_msg, msg_size) }
    } else {
        b"enclave panic"
    };

    let mut stderr = std::io::stderr();
    let _ignore = write!(stderr, "{}", String::from_utf8_lossy(msg));
    let _ignore = stderr.flush();
}

//
// sgxsd ocalls
//

#[no_mangle]
pub extern "C" fn sgxsd_ocall_reply(
    p_header: *const SgxsdMessageHeader,
    p_data: *const u8,
    data_size: usize,
    raw_tag: sgxsd_msg_tag_t,
) -> sgx_status_t
{
    // note: we take ownership of MessageTag here and release it
    match (
        unsafe { MessageTag::from_tag(raw_tag) },
        unsafe { p_header.as_ref() },
        p_data.is_null(),
    ) {
        (Some(MessageTag { callback }), Some(header), false) => {
            let data = unsafe { std::slice::from_raw_parts(p_data, data_size) }.to_vec();
            callback(Ok(MessageReply {
                iv: header.iv,
                mac: header.mac,
                data,
            }));
            SgxStatus::Success.into()
        }
        _ => SgxError::InvalidParameter.into(),
    }
}
