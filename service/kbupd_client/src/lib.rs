//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

mod protobufs;
mod protobufs_impl;

use failure::ResultExt;
use prost::Message;
use rand::Rng;

pub use crate::protobufs::kbupd_client::*;

pub struct Client {
    client_privkey: x25519_dalek::StaticSecret,
    client_pubkey:  x25519_dalek::PublicKey,
}

#[derive(Default)]
pub struct RequestNegotiation {
    pub server_ephemeral_pubkey:      [u8; 32],
    pub server_static_pubkey:         [u8; 32],
    pub encrypted_pending_request_id: EncryptedMessage,
}

pub struct EncryptedRequest {
    pub pending_request_id: Vec<u8>,
    pub encrypted_message:  EncryptedMessage,
}

#[derive(Default)]
pub struct EncryptedMessage {
    pub iv:   [u8; 12],
    pub mac:  [u8; 16],
    pub data: Vec<u8>,
}

impl Client {
    pub fn new(random: &mut (impl rand::RngCore + rand::CryptoRng)) -> Self {
        let client_privkey = x25519_dalek::StaticSecret::new(random);
        let client_pubkey = x25519_dalek::PublicKey::from(&client_privkey);
        Self {
            client_privkey,
            client_pubkey,
        }
    }

    pub fn client_pubkey(&self) -> &[u8; 32] {
        self.client_pubkey.as_bytes()
    }

    pub fn request(
        self,
        random: &mut (impl rand::RngCore + rand::CryptoRng),
        negotiation: RequestNegotiation,
        request: Request,
    ) -> Result<(EncryptedRequest, PendingRequest), failure::Error>
    {
        let (client_key, server_key) = key_agreement(
            &self.client_privkey,
            &self.client_pubkey,
            &negotiation.server_ephemeral_pubkey,
            &negotiation.server_static_pubkey,
        );

        let ring_server_key = ring::aead::OpeningKey::new(&ring::aead::AES_256_GCM, &server_key).context("invalid server_key")?;
        let ring_client_key = ring::aead::SealingKey::new(&ring::aead::AES_256_GCM, &client_key).context("invalid client_key")?;

        let pending_request_id_len = negotiation.encrypted_pending_request_id.data.len();
        let mut pending_request_id = negotiation.encrypted_pending_request_id.data;
        pending_request_id.extend_from_slice(&negotiation.encrypted_pending_request_id.mac);
        let nonce = ring::aead::Nonce::assume_unique_for_key(negotiation.encrypted_pending_request_id.iv);
        ring::aead::open_in_place(&ring_server_key, nonce, ring::aead::Aad::empty(), 0, &mut pending_request_id)
            .context("decrypt error")?;
        pending_request_id.truncate(pending_request_id_len);

        let request_data_len = request.encoded_len();
        let mut encrypted_message = EncryptedMessage {
            iv:   [0; 12],
            mac:  [0; 16],
            data: Vec::with_capacity(request_data_len + 16),
        };
        request.encode(&mut encrypted_message.data)?;
        encrypted_message.data.extend_from_slice(&encrypted_message.mac);

        random.fill(&mut encrypted_message.iv);
        let nonce = ring::aead::Nonce::assume_unique_for_key(encrypted_message.iv);
        ring::aead::seal_in_place(
            &ring_client_key,
            nonce,
            ring::aead::Aad::from(&pending_request_id),
            &mut encrypted_message.data,
            encrypted_message.mac.len(),
        )
        .context("encrypt error")?;
        encrypted_message.mac.copy_from_slice(&encrypted_message.data[request_data_len..]);
        encrypted_message.data.truncate(request_data_len);

        let encrypted_request = EncryptedRequest {
            pending_request_id,
            encrypted_message,
        };
        let pending_request = PendingRequest { server_key };

        Ok((encrypted_request, pending_request))
    }
}

pub struct PendingRequest {
    server_key: [u8; 32],
}

impl PendingRequest {
    pub fn decrypt_reply(self, mut reply: EncryptedMessage) -> Result<Response, failure::Error> {
        let reply_data_len = reply.data.len();
        reply.data.extend_from_slice(&reply.mac);
        let ring_server_key = ring::aead::OpeningKey::new(&ring::aead::AES_256_GCM, &self.server_key).context("invalid server_key")?;
        let nonce = ring::aead::Nonce::assume_unique_for_key(reply.iv);
        ring::aead::open_in_place(&ring_server_key, nonce, ring::aead::Aad::empty(), 0, &mut reply.data).context("decrypt error")?;
        let reply_data = &reply.data[..reply_data_len];

        Ok(Response::decode(reply_data)?)
    }
}

fn key_agreement(
    client_privkey: &x25519_dalek::StaticSecret,
    client_pubkey: &x25519_dalek::PublicKey,
    server_ephemeral_pubkey: &[u8; 32],
    server_static_pubkey: &[u8; 32],
) -> ([u8; 32], [u8; 32])
{
    let server_ephemeral_pubkey = x25519_dalek::PublicKey::from(*server_ephemeral_pubkey);
    let server_static_pubkey = x25519_dalek::PublicKey::from(*server_static_pubkey);
    let hkdf_secret = {
        let mut hkdf_secret: [u8; 64] = [0; 64];
        let ephemeral_dh_key = client_privkey.diffie_hellman(&server_ephemeral_pubkey);
        let static_dh_key = client_privkey.diffie_hellman(&server_static_pubkey);
        hkdf_secret[0..32].copy_from_slice(ephemeral_dh_key.as_bytes());
        hkdf_secret[32..64].copy_from_slice(static_dh_key.as_bytes());
        hkdf_secret
    };
    let hkdf_salt = {
        let mut hkdf_salt_bytes: [u8; 96] = [0; 96];
        hkdf_salt_bytes[0..32].copy_from_slice(client_pubkey.as_bytes());
        hkdf_salt_bytes[32..64].copy_from_slice(server_ephemeral_pubkey.as_bytes());
        hkdf_salt_bytes[64..96].copy_from_slice(server_static_pubkey.as_bytes());
        ring::hmac::SigningKey::new(&ring::digest::SHA256, &hkdf_salt_bytes)
    };

    let mut keys: [u8; 64] = [0; 64];
    let mut client_key: [u8; 32] = [0; 32];
    let mut server_key: [u8; 32] = [0; 32];

    ring::hkdf::extract_and_expand(&hkdf_salt, &hkdf_secret, &[0; 0], &mut keys);
    client_key.copy_from_slice(&keys[0..32]);
    server_key.copy_from_slice(&keys[32..64]);
    (client_key, server_key)
}
