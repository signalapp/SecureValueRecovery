//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use crate::prelude::*;

use std::convert::TryInto;
use std::num::*;

use sgx_ffi::untrusted_slice::*;
use sgx_ffi::util::SecretValue;
use sgxsd_ffi::{AesGcmIv, AesGcmKey, AesGcmMac};

use crate::ffi::ecalls::kbupd_enclave_alloc_untrusted;

const TAG_LENGTH: usize = StorageData::tag_len() as usize;

pub struct StorageData {
    data:   UntrustedSlice<'static>,
    cipher: AesGcmKey,
    nonce:  NonZeroU64,
}

#[derive(Clone, Copy)]
pub struct StorageDataNonce(NonZeroU64);

//
// StorageData impls
//

impl StorageData {
    pub fn new(data_size: usize) -> Result<Self, ()> {
        let data = if let Some(data_size) = NonZeroUsize::new(data_size) {
            kbupd_enclave_alloc_untrusted(data_size.get())?
        } else {
            UntrustedSlice::Empty
        };
        Ok(Self {
            cipher: Default::default(),
            data,
            nonce: NonZeroU64::new(1).unwrap_or_else(|| static_unreachable!()),
        })
    }

    pub const fn tag_len() -> u8 {
        16
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn read(&self, offset: usize, read_len: usize, nonce: StorageDataNonce) -> Result<SecretValue<Vec<u8>>, ()> {
        let data_len = read_len.checked_sub(TAG_LENGTH).ok_or(())?;
        let mut data = self.data.offset(offset).read_bytes(read_len)?;

        let mac_data: &[u8] = data.get(data_len..read_len).unwrap_or_else(|| unreachable!());
        let mac_data: &[u8; TAG_LENGTH] = mac_data.try_into().unwrap_or_else(|_| unreachable!());
        let mac = AesGcmMac { data: *mac_data };

        let mut iv = AesGcmIv::default();
        let iv_data: &mut [u8] = iv.data.get_mut(4..).unwrap_or_else(|| static_unreachable!());
        let iv_data: &mut [u8; 8] = iv_data.try_into().unwrap_or_else(|_| static_unreachable!());
        *iv_data = nonce.0.get().to_be_bytes();

        data.truncate(data_len);

        let mut data = SecretValue::new(data);
        match self.cipher.decrypt(data.get_mut(), &[], &iv, &mac) {
            Ok(()) => Ok(data),
            Err(error) => {
                error!("error decrypting storage data at offset {} length {}: {}", offset, read_len, error);
                Err(())
            }
        }
    }

    pub fn write(&mut self, offset: usize, mut data: SecretValue<Vec<u8>>) -> Result<StorageDataNonce, ()> {
        let nonce = self.nonce;
        self.nonce = NonZeroU64::new(self.nonce.get().checked_add(1).ok_or(())?).unwrap_or_else(|| unreachable!());

        let mut iv = AesGcmIv::default();
        let iv_data: &mut [u8] = iv.data.get_mut(4..).unwrap_or_else(|| static_unreachable!());
        let iv_data: &mut [u8; 8] = iv_data.try_into().unwrap_or_else(|_| static_unreachable!());
        *iv_data = nonce.get().to_be_bytes();

        let mut mac = AesGcmMac { data: Default::default() };

        match self.cipher.encrypt(data.get_mut(), &[], &iv, &mut mac) {
            Ok(()) => {
                self.data.offset(offset).write_bytes(data.get())?;
                self.data.offset(offset.saturating_add(data.get().len())).write_bytes(&mac.data)?;
                // no need to erase, as data is encrypted now
                data.get_mut().clear();
                Ok(StorageDataNonce(nonce))
            }
            Err(error) => {
                error!(
                    "error encrypting storage data at offset {} length {}: {}",
                    offset,
                    data.get().len(),
                    error
                );
                Err(())
            }
        }
    }
}

impl StorageDataNonce {
    pub fn new(value: NonZeroU64) -> Self {
        Self(value)
    }
}

impl From<StorageDataNonce> for u64 {
    fn from(from: StorageDataNonce) -> Self {
        from.0.get()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ffi::mocks;
    use mockers::*;

    struct TestStorageData {
        storage: Option<StorageData>,
        data:    Option<(*mut u8, usize)>,
    }

    impl TestStorageData {
        fn new(scenario: &Scenario, want_size: usize) -> Self {
            if want_size != 0 {
                let mut data_vec: Vec<u8> = Vec::with_capacity(want_size);
                let data: *mut u8 = data_vec.as_mut_ptr();
                let size: usize = data_vec.capacity();
                std::mem::forget(data_vec);

                mocks::expect_kbupd_enclave_ocall_alloc(scenario, size, data as *mut libc::c_void, size);
                let storage = StorageData::new(size).unwrap();
                assert_eq!(storage.len(), size);
                Self {
                    storage: Some(storage),
                    data:    Some((data, size)),
                }
            } else {
                let storage = StorageData::new(0).unwrap();
                assert_eq!(storage.len(), 0);
                Self {
                    storage: Some(storage),
                    data:    None,
                }
            }
        }

        fn get_mut(&mut self) -> &mut StorageData {
            self.storage.as_mut().unwrap()
        }
    }

    impl Drop for TestStorageData {
        fn drop(&mut self) {
            drop(self.storage.take());
            if let Some((data, size)) = self.data.take() {
                unsafe { Vec::from_raw_parts(data, 0, size) };
            }
        }
    }

    #[test]
    fn test_storage_data_invalid_empty() {
        let scenario = Scenario::new();
        let nonce = StorageDataNonce::new(NonZeroU64::new(1).unwrap());
        let mut storage = TestStorageData::new(&scenario, 0);

        for &offset in &[0, 1, usize::max_value()] {
            for &length in &[0, 1, usize::max_value()] {
                assert!(storage.get_mut().read(offset, length, nonce).is_err());
            }
            for &length in &[0, 1] {
                assert!(storage.get_mut().write(offset, SecretValue::new(vec![0; length])).is_err());
            }
        }
    }

    #[test]
    fn test_storage_data_valid() {
        let scenario = Scenario::new();
        let nonce = StorageDataNonce::new(NonZeroU64::new(1).unwrap());
        let mut storage = TestStorageData::new(&scenario, 2 + TAG_LENGTH);

        for &offset in &[0, 1] {
            for &length in &[0, 1] {
                assert!(storage.get_mut().write(offset, SecretValue::new(vec![0; length])).is_ok());
                assert_eq!(
                    storage.get_mut().read(offset, length + TAG_LENGTH, nonce).unwrap().get().len(),
                    length
                );
            }
        }
        assert!(storage.get_mut().write(2, SecretValue::new(vec![])).is_ok());
        assert_eq!(storage.get_mut().read(2, TAG_LENGTH, nonce).unwrap().get().len(), 0);
    }

    #[test]
    fn test_storage_invalid_overflow() {
        let scenario = Scenario::new();
        let nonce = StorageDataNonce::new(NonZeroU64::new(1).unwrap());
        let mut storage = TestStorageData::new(&scenario, TAG_LENGTH - 1);

        assert!(storage.get_mut().read(0, 0, nonce).is_err());
        assert!(storage.get_mut().read(0, TAG_LENGTH - 1, nonce).is_err());

        assert!(storage.get_mut().write(0, SecretValue::new(vec![])).is_err());
        assert!(storage.get_mut().read(0, TAG_LENGTH, nonce).is_err());

        let scenario = Scenario::new();
        let mut storage = TestStorageData::new(&scenario, TAG_LENGTH);

        assert!(storage.get_mut().write(0, SecretValue::new(vec![])).is_ok());
        assert!(storage.get_mut().read(0, TAG_LENGTH, nonce).is_ok());

        assert!(storage.get_mut().write(0, SecretValue::new(vec![0; 1])).is_err());
        assert!(storage.get_mut().read(0, TAG_LENGTH + 1, nonce).is_err());
        assert!(storage.get_mut().read(0, usize::max_value(), nonce).is_err());
    }

    #[test]
    fn test_storage_invalid_integer_overflow() {
        let scenario = Scenario::new();
        let nonce = StorageDataNonce::new(NonZeroU64::new(1).unwrap());

        let data: *mut u8 = unsafe { std::ptr::NonNull::dangling().as_mut() };
        let size: usize = usize::max_value() - 1;

        mocks::expect_kbupd_enclave_ocall_alloc(&scenario, size, data as *mut libc::c_void, size);
        let storage = StorageData::new(size).unwrap();

        assert!(storage.read(0, usize::max_value(), nonce).is_err());

        assert!(storage.read(size - TAG_LENGTH + 1, TAG_LENGTH, nonce).is_err());
        assert!(storage.read(size, TAG_LENGTH, nonce).is_err());
        assert!(storage.read(usize::max_value(), TAG_LENGTH, nonce).is_err());

        assert!(storage.read(usize::max_value(), usize::max_value(), nonce).is_err());
    }
}
