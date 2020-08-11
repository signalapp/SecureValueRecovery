//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use prost::Message;
use sgx_sdk_ffi::*;

use crate::protobufs::kbupd::*;

use super::ocalls;
use super::sgxsd::*;

use super::bindgen_wrapper::kbupd_enclave_recv_untrusted_msg;

pub fn kbupd_send(enclave_id: SgxEnclaveId, messages: Vec<UntrustedMessage>) -> SgxsdResult<Vec<EnclaveMessage>> {
    let batch = UntrustedMessageBatch { messages };
    let mut data = Vec::with_capacity(batch.encoded_len());
    batch.encode(&mut data).unwrap();
    kbupd_send_raw(enclave_id, &data)
}
pub fn kbupd_send_raw(enclave_id: SgxEnclaveId, data: &[u8]) -> SgxsdResult<Vec<EnclaveMessage>> {
    sgxsd_res(
        |_| unsafe { kbupd_enclave_recv_untrusted_msg(enclave_id, data.as_ptr(), data.len()) },
        "kbupd_enclave_recv_untrusted_msg",
    )?;
    Ok(ocalls::take_enclave_messages())
}
