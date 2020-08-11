//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use core::convert::TryInto;

use crate::prelude::*;

use rand_core::{CryptoRng, RngCore};
use sgxsd_ffi::*;
use snow::params::*;
use snow::resolvers::*;
use snow::types::*;

#[derive(Default)]
pub struct SnowResolver;

#[derive(Default)]
struct SnowRdRand;

#[derive(Default)]
struct SnowDh25519 {
    key: Curve25519Key,
}

#[derive(Default)]
struct SnowHashSHA256 {
    context: SHA256Context,
}

#[derive(Default)]
struct SnowCipherAESGCM {
    key: AesGcmKey,
}

//
// SnowResolver impls
//

impl CryptoResolver for SnowResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(SnowRdRand))
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        match *choice {
            DHChoice::Curve25519 => Some(Box::new(SnowDh25519::default())),
            _ => None,
        }
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        match *choice {
            HashChoice::SHA256 => Some(Box::new(SnowHashSHA256::default())),
            _ => None,
        }
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        match *choice {
            CipherChoice::AESGCM => Some(Box::new(SnowCipherAESGCM::default())),
            _ => None,
        }
    }
}

//
// SnowRdRand impls
//

impl Random for SnowRdRand {}
impl CryptoRng for SnowRdRand {}
impl RngCore for SnowRdRand {
    fn next_u32(&mut self) -> u32 {
        RdRand.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        RdRand.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        RdRand.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        RdRand.try_fill_bytes(dest)
    }
}

//
// SnowDh25519 impls
//

impl Dh for SnowDh25519 {
    fn name(&self) -> &'static str {
        "25519"
    }

    fn pub_len(&self) -> usize {
        32
    }

    fn priv_len(&self) -> usize {
        32
    }

    fn set(&mut self, privkey: &[u8]) {
        let privkey: &[u8; 32] = privkey.try_into().unwrap_or_else(|_| panic!("overflow"));
        self.key.set_key(privkey);
    }

    fn generate(&mut self, rng: &mut dyn Random) {
        self.key.generate(rng);
    }

    fn pubkey(&self) -> &[u8] {
        self.key.pubkey()
    }

    fn privkey(&self) -> &[u8] {
        self.key.privkey()
    }

    fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), ()> {
        let pubkey: &[u8] = pubkey.get(..32).unwrap_or_else(|| panic!("overflow"));
        let pubkey: &[u8; 32] = pubkey.try_into().unwrap_or_else(|_| static_unreachable!());
        let out: &mut [u8] = out.get_mut(..32).unwrap_or_else(|| panic!("overflow"));
        let out: &mut [u8; 32] = out.try_into().unwrap_or_else(|_| static_unreachable!());
        self.key.dh(pubkey, out);
        Ok(())
    }
}

//
// SnowCipherAESGCM impls
//

impl Cipher for SnowCipherAESGCM {
    fn name(&self) -> &'static str {
        "AESGCM"
    }

    fn set(&mut self, key: &[u8]) {
        let key: &[u8; 32] = key.try_into().unwrap_or_else(|_| panic!("overflow"));
        self.key.set_key(key);
    }

    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
        let (text_in_out, out) = out.split_at_mut(plaintext.len());
        let out: &mut [u8] = out.get_mut(..16).unwrap_or_else(|| panic!("overflow"));
        let out: &mut [u8; 16] = out.try_into().unwrap_or_else(|_| static_unreachable!());
        text_in_out.copy_from_slice(plaintext);

        let mut mac = AesGcmMac::default();
        let mut iv = AesGcmIv::default();
        let iv_data: &mut [u8] = iv.data.get_mut(4..).unwrap_or_else(|| static_unreachable!());
        let iv_data: &mut [u8; 8] = iv_data.try_into().unwrap_or_else(|_| static_unreachable!());
        *iv_data = nonce.to_be_bytes();

        match self.key.encrypt(text_in_out, authtext, &iv, &mut mac) {
            Ok(()) => {
                *out = mac.data;
                text_in_out.len().saturating_add(mac.data.len())
            }
            Err(_) => {
                sgx_ffi::util::clear(text_in_out);
                0
            }
        }
    }

    fn decrypt(&self, nonce: u64, authtext: &[u8], ciphertext: &[u8], out: &mut [u8]) -> Result<usize, ()> {
        let ciphertext_len = ciphertext.len().checked_sub(16).unwrap_or_else(|| panic!("overflow"));
        let (ciphertext, ciphertext_mac_data) = ciphertext.split_at(ciphertext_len);
        let ciphertext_mac_data: &[u8; 16] = ciphertext_mac_data.try_into().unwrap_or_else(|_| unreachable!());
        let (in_out_text, _) = out.split_at_mut(ciphertext.len());
        in_out_text.copy_from_slice(ciphertext);

        let mac = AesGcmMac {
            data: *ciphertext_mac_data,
        };
        let mut iv = AesGcmIv::default();
        let iv_data: &mut [u8] = iv.data.get_mut(4..).unwrap_or_else(|| static_unreachable!());
        let iv_data: &mut [u8; 8] = iv_data.try_into().unwrap_or_else(|_| static_unreachable!());
        *iv_data = nonce.to_be_bytes();

        self.key
            .decrypt(in_out_text, authtext, &iv, &mac)
            .map(|()| in_out_text.len())
            .map_err(drop)
    }
}

//
// SnowHashSHA256 impls
//

impl Hash for SnowHashSHA256 {
    fn name(&self) -> &'static str {
        "SHA256"
    }

    fn block_len(&self) -> usize {
        64
    }

    fn hash_len(&self) -> usize {
        SHA256Context::hash_len()
    }

    fn reset(&mut self) {
        self.context.reset();
    }

    fn input(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        let out: &mut [u8] = out.get_mut(..SHA256Context::hash_len()).unwrap_or_else(|| panic!("overflow"));
        let out: &mut [u8; SHA256Context::hash_len()] = out.try_into().unwrap_or_else(|_| static_unreachable!());
        self.context.result(out);
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use mockers::matchers::*;
    use mockers::*;

    #[test]
    fn resolve_rng_test() {
        let rand = SnowResolver.resolve_rng();
        assert!(rand.is_some());
        if let Some(mut rand) = rand {
            let mut data = vec![0; 100];
            rand.fill_bytes(&mut data[..0]);
            assert_eq!(&data[..], &vec![0; data.len()][..]);
            rand.fill_bytes(&mut data);
            assert_ne!(&data[..], &vec![0; data.len()][..]);
        }
    }

    #[test]
    fn resolve_dh_test() {
        let dh = SnowResolver.resolve_dh(&DHChoice::Curve25519);
        let rand = SnowResolver.resolve_rng();
        assert!(dh.is_some());
        assert!(rand.is_some());
        if let (Some(mut dh), Some(mut rand)) = (dh, rand) {
            dh.generate(&mut *rand);
            let mut privkey = [0; 32];
            let mut pubkey = [0; 32];
            privkey.copy_from_slice(dh.privkey());
            pubkey.copy_from_slice(dh.pubkey());
            assert_ne!(&privkey, &[0; 32]);
            assert_ne!(&pubkey, &[0; 32]);

            dh.set(&test_ffi::rand_bytes([0; 32]));
            assert_ne!(dh.privkey(), privkey);
            assert_ne!(dh.pubkey(), pubkey);

            let mut res = vec![0; 32];
            dh.dh(&test_ffi::rand_bytes(vec![0; 32]), &mut res).unwrap();
            assert_ne!(&res[..], &[0; 32][..]);
        }
    }

    #[test]
    #[should_panic]
    fn test_dh_set_overflow() {
        let dh = SnowResolver.resolve_dh(&DHChoice::Curve25519);
        if let Some(mut dh) = dh {
            dh.set(&[0; 31]);
        }
    }

    #[test]
    #[should_panic]
    fn test_dh_pubkey_overflow() {
        let dh = SnowResolver.resolve_dh(&DHChoice::Curve25519);
        if let Some(dh) = dh {
            let _ignore = dh.dh(&test_ffi::rand_bytes(vec![0; 31]), &mut vec![0; 32]);
        }
    }

    #[test]
    #[should_panic]
    fn test_dh_out_overflow() {
        let dh = SnowResolver.resolve_dh(&DHChoice::Curve25519);
        if let Some(dh) = dh {
            let _ignore = dh.dh(&test_ffi::rand_bytes(vec![0; 32]), &mut vec![0; 31]);
        }
    }

    #[test]
    fn resolve_hash_test() {
        let hash = SnowResolver.resolve_hash(&HashChoice::SHA256);
        assert!(hash.is_some());
        if let Some(mut hash) = hash {
            hash.reset();
            hash.input(&[]);
            hash.input(&[0]);
            hash.input(&test_ffi::rand_bytes(vec![0; 100]));
            let mut result = vec![0; hash.hash_len()];
            hash.result(&mut result);
            assert_ne!(&result[..], &vec![0; hash.hash_len()][..]);
        }
    }

    macro_rules! eq_vec {
        ($vec:expr) => {{
            let vec: Vec<u8> = $vec.clone();
            check(move |slice: &&[u8]| slice == &&vec[..])
        }};
    }

    #[test]
    fn resolve_cipher_test() {
        let cipher = SnowResolver.resolve_cipher(&CipherChoice::AESGCM);
        assert!(cipher.is_some());
        if let Some(mut cipher) = cipher {
            let privkey = test_ffi::rand_bytes(vec![0; 32]);
            cipher.set(&privkey);

            test_ffi::clear(&sgxsd_ffi::mocks::SGXSD_AES_GCM_ENCRYPT);

            let authtext = vec![0; 100];
            let plaintext = vec![0; 100];
            let mut out = vec![0; plaintext.len() + 16];
            assert_eq!(cipher.encrypt(0, &authtext, &plaintext, &mut out), out.len());
            assert_ne!(&vec![0; 8][..], &out[..8]);
            assert_ne!(&vec![0; 8][..], &out[(out.len() - 8)..]);

            test_ffi::clear(&sgxsd_ffi::mocks::SGXSD_AES_GCM_DECRYPT);

            let ciphertext = vec![0; plaintext.len() + 16];
            let mut out = vec![0; plaintext.len()];
            assert_eq!(cipher.decrypt(0, &authtext, &ciphertext, &mut out), Ok(out.len()));
            assert_ne!(&out[..], &vec![0; out.len()][..]);
        }
    }

    #[test]
    fn resolve_cipher_success() {
        let scenario = Scenario::new();
        let mut cipher = SnowResolver.resolve_cipher(&CipherChoice::AESGCM).unwrap();
        let privkey = test_ffi::rand_bytes(vec![0; 32]);
        let authtext = test_ffi::rand_bytes(vec![0; 100]);
        let plaintext = test_ffi::rand_bytes(vec![0; 100]);
        let ciphertext = test_ffi::rand_bytes(vec![0; 100]);

        cipher.set(&privkey);

        let mock = test_ffi::mock_for(&sgxsd_ffi::mocks::SGXSD_AES_GCM_ENCRYPT, &scenario);
        scenario.expect(
            mock.sgxsd_aes_gcm_encrypt(eq_vec!(privkey), eq_vec!(plaintext), any(), eq_vec!(authtext))
                .and_return(Ok(ciphertext.clone())),
        );

        let mut ciphertext_and_tag_out = vec![0; plaintext.len() + 16];
        assert_eq!(
            cipher.encrypt(0, &authtext, &plaintext, &mut ciphertext_and_tag_out),
            ciphertext_and_tag_out.len()
        );
        assert_eq!(&ciphertext_and_tag_out[..ciphertext.len()], &ciphertext[..]);

        let mock = test_ffi::mock_for(&sgxsd_ffi::mocks::SGXSD_AES_GCM_DECRYPT, &scenario);
        scenario.expect(
            mock.sgxsd_aes_gcm_decrypt(eq_vec!(privkey), eq_vec!(ciphertext), any(), eq_vec!(authtext))
                .and_return(Ok(plaintext.clone())),
        );

        let mut plaintext_out = vec![0; plaintext.len()];
        assert_eq!(
            cipher.decrypt(0, &authtext, &ciphertext_and_tag_out, &mut plaintext_out),
            Ok(plaintext_out.len())
        );
        assert_eq!(&plaintext_out, &plaintext);
    }

    #[test]
    fn resolve_cipher_fail() {
        let scenario = Scenario::new();
        let mut cipher = SnowResolver.resolve_cipher(&CipherChoice::AESGCM).unwrap();
        let privkey = test_ffi::rand_bytes(vec![0; 32]);
        let authtext = test_ffi::rand_bytes(vec![0; 100]);
        let plaintext = test_ffi::rand_bytes(vec![0; 100]);
        let ciphertext = test_ffi::rand_bytes(vec![0; 100]);

        cipher.set(&privkey);

        let mock = test_ffi::mock_for(&sgxsd_ffi::mocks::SGXSD_AES_GCM_ENCRYPT, &scenario);
        scenario.expect(
            mock.sgxsd_aes_gcm_encrypt(eq_vec!(privkey), eq_vec!(plaintext), any(), eq_vec!(authtext))
                .and_return(Err(())),
        );

        let mut ciphertext_and_tag_out = vec![0; plaintext.len() + 16];
        assert_eq!(cipher.encrypt(0, &authtext, &plaintext, &mut ciphertext_and_tag_out), 0);
        assert_eq!(&ciphertext_and_tag_out, &vec![0; ciphertext_and_tag_out.len()]);

        let mock = test_ffi::mock_for(&sgxsd_ffi::mocks::SGXSD_AES_GCM_DECRYPT, &scenario);
        scenario.expect(
            mock.sgxsd_aes_gcm_decrypt(eq_vec!(privkey), eq_vec!(ciphertext), any(), eq_vec!(authtext))
                .and_return(Err(())),
        );

        ciphertext_and_tag_out[..ciphertext.len()].copy_from_slice(&ciphertext);
        let mut plaintext_out = ciphertext.clone();
        assert_eq!(cipher.decrypt(0, &authtext, &ciphertext_and_tag_out, &mut plaintext_out), Err(()));
        assert_eq!(&plaintext_out, &ciphertext);
    }
}
