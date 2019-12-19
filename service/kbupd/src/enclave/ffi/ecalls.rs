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

use prost::{Message};

use crate::protobufs::kbupd::*;

use super::ocalls;
use super::sgx::*;
use super::sgxsd::*;

use super::bindgen_wrapper::{kbupd_enclave_recv_untrusted_msg};

pub fn kbupd_send(enclave_id: SgxEnclaveId, messages: Vec<UntrustedMessage>) -> SgxsdResult<Vec<EnclaveMessage>> {
    let batch = UntrustedMessageBatch {
        messages,
    };
    let mut data = Vec::with_capacity(batch.encoded_len());
    batch.encode(&mut data).unwrap();
    kbupd_send_raw(enclave_id, &data)
}
pub fn kbupd_send_raw(enclave_id: SgxEnclaveId, data: &[u8]) -> SgxsdResult<Vec<EnclaveMessage>> {
    sgxsd_res(|_| unsafe { kbupd_enclave_recv_untrusted_msg(enclave_id, data.as_ptr(), data.len()) },
              "kbupd_enclave_recv_untrusted_msg")?;
    Ok(ocalls::take_enclave_messages())
}
