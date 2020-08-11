//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use crate::prelude::*;

use std::convert::TryInto;
use std::mem;
use std::num::NonZeroU16;

use bytes::{Buf, BufMut};
use sgx_ffi::util::{SecretValue, ToUsize};

use super::BackupEntry;

pub struct BackupEntrySecrets {
    pub tries: NonZeroU16,
    data:      SecretValue<Box<[u8]>>,
}

//
// BackupEntry impls
//

impl BackupEntrySecrets {
    pub fn new(tries: NonZeroU16, pin: &[u8; BackupEntry::PIN_LENGTH], data: &[u8]) -> Self {
        assert!(data.len() <= std::u32::MAX.to_usize());

        let mut combined = SecretValue::new(Vec::with_capacity(pin.len() + data.len()));
        combined.get_mut().extend_from_slice(pin);
        combined.get_mut().extend_from_slice(data);

        Self {
            tries,
            data: SecretValue::new(mem::replace(combined.get_mut(), Vec::new()).into_boxed_slice()),
        }
    }

    pub fn encode_opt<B: BufMut>(value: Option<&Self>, buf: &mut B) {
        if let Some(value) = value {
            value.encode(buf);
        } else {
            buf.put_u16_le(0);
        }
    }

    pub const fn encoded_len(data_len: u32) -> u32 {
        2 + 4 + (BackupEntry::PIN_LENGTH as u32) + data_len
    }

    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_u16_le(self.tries.get());
        let data_len: u32 = (self.data.get().len())
            .checked_sub(32)
            .and_then(|data_len: usize| data_len.try_into().ok())
            .unwrap_or_else(|| unreachable!());
        buf.put_u32_le(data_len);
        buf.put_slice(self.data.get())
    }

    pub fn decode<B: Buf>(buf: &mut B) -> Option<Self> {
        if let Some(tries) = NonZeroU16::new(buf.get_u16_le()) {
            let data_len = buf.get_u32_le().to_usize() + BackupEntry::PIN_LENGTH;

            let data = if let Some(buf_data) = buf.bytes().get(..data_len) {
                let mut data = SecretValue::new(Vec::with_capacity(data_len));
                data.get_mut().extend_from_slice(buf_data);
                buf.advance(data_len);
                SecretValue::new(mem::replace(data.get_mut(), Vec::new()).into_boxed_slice())
            } else {
                let mut data = SecretValue::new(vec![0; data_len].into_boxed_slice());
                buf.copy_to_slice(data.get_mut());
                data
            };

            Some(Self { tries, data })
        } else {
            None
        }
    }

    pub fn pin_consttime_eq(&self, other: &impl AsRef<[u8]>) -> bool {
        sgx_ffi::util::consttime_eq(&self.data.get()[..BackupEntry::PIN_LENGTH], other)
    }

    pub fn data(&mut self) -> &[u8] {
        &self.data.get()[BackupEntry::PIN_LENGTH..]
    }
}
