//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std;
use std::cell::RefCell;

use mockers::matchers::*;
use mockers::*;
use mockers_derive::mocked;
use prost::Message;

use crate::protobufs;

use super::bindgen_wrapper::sgx_status_t;

//
// mock extern "C" functions
//

thread_local! {
    pub static KBUPD_ENCLAVE_OCALL_RECV_ENCLAVE_MSG: RefCell<Option<KbupdEnclaveOcallRecvEnclaveMsgMock>> = RefCell::new(None);
    pub static KBUPD_ENCLAVE_OCALL_ALLOC:            RefCell<Option<KbupdEnclaveOcallAllocMock>>          = RefCell::new(None);
}

#[mocked]
pub trait KbupdEnclaveOcallRecvEnclaveMsg {
    fn enclave_message(&self, msg: protobufs::kbupd::enclave_message::Inner);
    fn kbupd_enclave_ocall_recv_enclave_msg(&self) -> sgx_status_t;
}

#[mocked]
pub trait KbupdEnclaveOcallAlloc {
    fn kbupd_enclave_ocall_alloc(&self, size: usize) -> Result<(*mut ::std::os::raw::c_void, usize), sgx_status_t>;
}

impl MatchArg<protobufs::kbupd::enclave_message::Inner> for Box<dyn MatchArg<protobufs::kbupd::enclave_message::Inner>> {
    fn matches(&self, arg: &protobufs::kbupd::enclave_message::Inner) -> Result<(), String> {
        (**self).matches(arg)
    }

    fn describe(&self) -> String {
        (**self).describe()
    }
}
pub fn expect_enclave_messages(
    scenario: &Scenario,
    matchers: impl IntoIterator<Item = Box<dyn MatchArg<protobufs::kbupd::enclave_message::Inner>>>,
)
{
    let mock = test_ffi::mock_for(&KBUPD_ENCLAVE_OCALL_RECV_ENCLAVE_MSG, &scenario);
    for matcher in matchers {
        scenario.expect(mock.enclave_message(matcher).and_return(()));
    }
    scenario.expect(mock.kbupd_enclave_ocall_recv_enclave_msg().and_return_clone(0).times(..));
}

pub fn expect_kbupd_enclave_ocall_alloc(scenario: &Scenario, request_size: usize, returned_ptr: *mut libc::c_void, returned_size: usize) {
    assert_ne!(request_size, 0);
    let mock = test_ffi::mock_for(&KBUPD_ENCLAVE_OCALL_ALLOC, &scenario);
    scenario.expect(
        mock.kbupd_enclave_ocall_alloc(eq(request_size))
            .and_return(Ok((returned_ptr, returned_size))),
    );

    sgx_ffi::mocks::expect_sgx_is_outside_enclave(scenario, returned_ptr as *const libc::c_void, returned_size, true);
}

//
// mock extern "C" function implementations
//

pub mod impls {
    use super::*;

    struct OCallSlice(*const u8, usize);
    impl AsRef<[u8]> for OCallSlice {
        fn as_ref(&self) -> &[u8] {
            if self.1 != 0 {
                assert!(!self.0.is_null());
                unsafe { std::slice::from_raw_parts(self.0, self.1) }
            } else {
                unsafe { std::slice::from_raw_parts(1 as *const u8, 0) }
            }
        }
    }

    #[no_mangle]
    pub extern "C" fn kbupd_enclave_ocall_recv_enclave_msg(data: *const u8, data_size: usize) -> sgx_status_t {
        let data = OCallSlice(data, data_size);
        let batch = protobufs::kbupd::EnclaveMessageBatch::decode(data.as_ref()).expect("bad EnclaveMessageBatch from enclave");
        KBUPD_ENCLAVE_OCALL_RECV_ENCLAVE_MSG.with(|mock_cell| {
            let mock_ref = mock_cell.borrow();
            let mock = mock_ref.as_ref().expect("no mock for kbupd_enclave_ocall_recv_enclave_msg");
            for msg in batch.messages {
                match msg.inner.expect("empty EnclaveMessage from enclave") {
                    protobufs::kbupd::enclave_message::Inner::EnclaveLogSignal(log) => {
                        eprintln!("enclave log: {}", std::str::from_utf8(&log.message).unwrap());
                    }
                    msg_inner => {
                        mock.enclave_message(msg_inner);
                    }
                }
            }
            mock.kbupd_enclave_ocall_recv_enclave_msg()
        })
    }

    #[no_mangle]
    pub extern "C" fn kbupd_enclave_ocall_alloc(p_ptr_out: *mut *mut ::std::os::raw::c_void, p_size_in_out: *mut usize) -> sgx_status_t {
        assert!(!p_ptr_out.is_null());
        assert!(!p_size_in_out.is_null());
        let size = unsafe { *p_size_in_out };
        assert_ne!(size, 0);
        let res = KBUPD_ENCLAVE_OCALL_ALLOC
            .with(|mock| (mock.borrow().as_ref().expect("no mock for kbupd_enclave_ocall_alloc")).kbupd_enclave_ocall_alloc(size));
        match res {
            Ok((ptr, size)) => {
                unsafe {
                    *p_ptr_out = ptr;
                    *p_size_in_out = size;
                }
                0
            }
            Err(error) => error,
        }
    }

    #[no_mangle]
    pub extern "C" fn curve25519_donna(
        arg1: *mut ::std::os::raw::c_uchar,
        arg2: *const ::std::os::raw::c_uchar,
        arg3: *const ::std::os::raw::c_uchar,
    ) -> ::std::os::raw::c_int
    {
        let arg1 = unsafe { std::slice::from_raw_parts_mut(arg1, 32) };
        let arg2 = unsafe { std::slice::from_raw_parts(arg2, 32) };
        let arg3 = unsafe { std::slice::from_raw_parts(arg3, 32) };
        test_ffi::read_rand(arg1);
        arg2.iter().for_each(|p| unsafe {
            std::ptr::read_volatile(p);
        });
        arg3.iter().for_each(|p| unsafe {
            std::ptr::read_volatile(p);
        });
        0
    }
}
