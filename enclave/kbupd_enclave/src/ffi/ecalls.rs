//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use crate::prelude::*;

use std::cell::*;
use std::ptr::NonNull;
use std::slice;

use prost::Message;
use sgx_ffi::untrusted_slice::UntrustedSlice;

use super::bindgen_wrapper::{kbupd_enclave_ocall_alloc, kbupd_enclave_ocall_recv_enclave_msg};
pub use super::bindgen_wrapper::{
    sgxsd_server_handle_call_args_t as CallArgs, sgxsd_server_init_args_t as StartArgs, sgxsd_server_terminate_args_t as StopArgs,
    KBUPD_REQUEST_TYPE_ANY, KBUPD_REQUEST_TYPE_BACKUP, KBUPD_REQUEST_TYPE_DELETE, KBUPD_REQUEST_TYPE_RESTORE,
};

use crate::protobufs::kbupd::{EnclaveMessage, EnclaveMessageBatch, UntrustedMessage, UntrustedMessageBatch};

pub trait KbupdService {
    fn untrusted_message(&mut self, message: UntrustedMessage);
}

const ENCLAVE_MESSAGE_BUFFER_SIZE: usize = 10240;

#[cfg(not(any(test, feature = "test")))]
pub fn with_buffer<F, R>(fun: F) -> R
where F: FnOnce(&RefCell<Option<Vec<u8>>>) -> R {
    #[thread_local]
    static ENCLAVE_MESSAGE_BUFFER: RefCell<Option<Vec<u8>>> = RefCell::new(None);

    fun(&ENCLAVE_MESSAGE_BUFFER)
}

#[cfg(any(test, feature = "test"))]
pub fn with_buffer<F, R>(fun: F) -> R
where F: FnOnce(&RefCell<Option<Vec<u8>>>) -> R {
    thread_local! {
        static ENCLAVE_MESSAGE_BUFFER: RefCell<Option<Vec<u8>>> = RefCell::new(None);
    }
    ENCLAVE_MESSAGE_BUFFER.with(fun)
}

pub fn kbupd_enclave_alloc_untrusted(mut size: usize) -> Result<UntrustedSlice<'static>, ()> {
    let mut p_data: *mut libc::c_void = std::ptr::null_mut();
    match unsafe { kbupd_enclave_ocall_alloc(&mut p_data, &mut size) } {
        0 => UntrustedSlice::new(p_data as *mut u8, size),
        error => {
            error!("ocall error allocating {} bytes from untrusted: {}", size, error);
            Err(())
        }
    }
}

pub fn kbupd_enclave_recv_untrusted_msg<S>(service: &mut S, p_data: *const u8, data_size: usize)
where S: KbupdService {
    let data = ECallSlice(NonNull::new(p_data as *mut _), data_size);

    match UntrustedMessageBatch::decode(data.as_ref()) {
        Ok(batch) => {
            for message in batch.messages {
                service.untrusted_message(message);
            }
        }
        Err(decode_error) => {
            error!("error decoding untrusted messages: {}", decode_error);
        }
    }
    kbupd_send_flush();
}

pub fn kbupd_send(message: EnclaveMessage) {
    let batch = EnclaveMessageBatch { messages: vec![message] };
    let buffer_len = with_buffer(|buffer| buffer.borrow().as_ref().map(Vec::len).unwrap_or(0));
    if buffer_len.saturating_add(batch.encoded_len()) > ENCLAVE_MESSAGE_BUFFER_SIZE {
        kbupd_send_flush();
    }
    with_buffer(|buffer| {
        let mut buffer_ref_mut = RefMut::map(buffer.borrow_mut(), |maybe_buffer: &mut Option<Vec<u8>>| {
            maybe_buffer.get_or_insert_with(|| Vec::with_capacity(ENCLAVE_MESSAGE_BUFFER_SIZE))
        });
        let buffer_mut: &mut Vec<u8> = buffer_ref_mut.as_mut();
        assert!(batch.encode(buffer_mut).is_ok());
    });
}

pub fn kbupd_send_flush() {
    let maybe_buffer = with_buffer(|buffer_tls| std::mem::replace(&mut *buffer_tls.borrow_mut(), Default::default()));
    let mut buffer = match maybe_buffer {
        Some(buffer) => buffer,
        None => return,
    };
    if !buffer.is_empty() {
        let ocall_res = unsafe { kbupd_enclave_ocall_recv_enclave_msg(buffer.as_ptr(), buffer.len()) };
        assert_eq!(ocall_res, 0);
    }
    buffer.truncate(0);

    with_buffer(|buffer_tls| {
        if buffer_tls.borrow().as_ref().map(Vec::is_empty).unwrap_or(true) {
            if buffer.capacity() == ENCLAVE_MESSAGE_BUFFER_SIZE {
                *buffer_tls.borrow_mut() = Some(buffer);
            }
        }
    });
}

struct ECallSlice(Option<NonNull<u8>>, usize);
impl AsRef<[u8]> for ECallSlice {
    fn as_ref(&self) -> &[u8] {
        if self.1 != 0 {
            if let Some(ptr) = self.0 {
                unsafe { slice::from_raw_parts(ptr.as_ptr(), self.1) }
            } else {
                &[]
            }
        } else {
            &[]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::mocks;
    use super::*;
    use mockers::*;

    struct MockKbupdService {}
    impl KbupdService for MockKbupdService {
        fn untrusted_message(&mut self, _message: UntrustedMessage) {}
    }

    #[test]
    fn kbupd_enclave_recv_untrusted_msg_empty() {
        let mut kbupd_service = MockKbupdService {};
        kbupd_enclave_recv_untrusted_msg(&mut kbupd_service, std::ptr::null(), 0);
    }

    #[test]
    fn kbupd_enclave_recv_untrusted_msg_bad() {
        let bad_requests: &[&[u8]] = &[
            // bad tag 0, types 0..=7, truncated
            &[0x00],
            &[0x01],
            &[0x02],
            &[0x03],
            &[0x04],
            &[0x05],
            &[0x06],
            &[0x07],
            // tag 1, bad types 0..=1, truncated
            &[0x08],
            &[0x09],
            // tag 1, type 2, truncated
            &[0x0A],
            // tag 1, bad types 3..=7, truncated
            &[0x0B],
            &[0x0C],
            &[0x0D],
            &[0x0E],
            &[0x0F],
            // tag 2, types 0..=7, truncated
            &[0x10],
            &[0x11],
            &[0x12],
            &[0x13],
            &[0x14],
            &[0x15],
            &[0x16],
            &[0x17],
            // tag 1, bad type 0
            &[0x08, 0x00],
            // tag 1, type 2, length 1, truncated
            &[0x0A, 0x01],
            // tag 1, type 2, length 2^64-1, truncated
            &[0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01],
            // tag 1, type 2, length 1 (overlong varint), truncated
            &[0x0A, 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00],
            &[0x0A, 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02],
            // tag 2, type 0, bad varints
            &[0x10, 0x80],
            &[0x10, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80],
            &[0x10, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00],
            // bad tag 0 (overlong varint), type 0
            &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00, 0x00],
            &[0x80, 0x80, 0x80, 0x00, 0x00],
            // bad tag 2^32, type 0
            &[0x80, 0x80, 0x80, 0x80, 0x10, 0x00],
            // bad tag 2^64-1, type 0
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00],
            // bad tag (bad varint)
            &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80],
            &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00],
        ];
        let null_requests: &[&[u8]] = &[
            // empty
            &[],
            // tag 1, type 2, length 0 (overlong varint)
            &[0x0A, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00],
            // tag 1, type 2, length 0 (overlong varint, extra bits ignored)
            &[0x0A, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02],
            // tag 1 (overlong varint), type 2, length 0
            &[0x8A, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00, 0x00],
            // tag 2 (overlong varint), type 0
            &[0x90, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00, 0x00],
            // tag 2 (overlong varint, extra bits ignored), type 0
            &[0x90, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02, 0x00],
        ];
        let requests = bad_requests.iter().chain(null_requests.iter());
        for request in requests.into_iter() {
            let scenario = Scenario::new();
            mocks::expect_enclave_messages(&scenario, vec![]);
            let mut kbupd_service = MockKbupdService {};
            kbupd_enclave_recv_untrusted_msg(&mut kbupd_service, request.as_ptr(), request.len());
            drop(scenario);
        }
    }
}
