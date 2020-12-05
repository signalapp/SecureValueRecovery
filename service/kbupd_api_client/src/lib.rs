//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use cookie::Cookie;
use failure::{format_err, Fail, ResultExt};
use futures::prelude::*;
use http::header;
use http::header::HeaderValue;
use http::response;
use http::Uri;
use hyper::client::HttpConnector;
use hyper::{Body, Chunk, Method, Request, Response};
use hyper_tls::HttpsConnector;
use kbupd_api::entities::*;
use log::debug;
use native_tls::{Protocol, TlsConnector};
use serde::{Deserialize, Serialize};
use try_future::{try_future, TryFuture};

#[derive(Clone)]
pub struct KeyBackupApiClient {
    client:   hyper::Client<HttpsConnector<HttpConnector>, Body>,
    base_uri: Uri,
}

#[derive(Clone)]
pub struct KeyBackupApiCredentials {
    pub username: String,
    pub password: String,
}

impl KeyBackupApiClient {
    pub fn new(base_uri: Uri, insecure_ssl: bool) -> Result<Self, failure::Error> {
        let tls_connector = TlsConnector::builder()
            .min_protocol_version(Some(Protocol::Tlsv12))
            .danger_accept_invalid_certs(insecure_ssl)
            .build()
            .context("error creating tls connector")?;

        let mut http_connector = HttpConnector::new(1);
        http_connector.enforce_http(false);

        let client = hyper::Client::builder().build((http_connector, tls_connector).into());
        Ok(Self { client, base_uri })
    }

    pub fn get_token(
        &self,
        credentials: &KeyBackupApiCredentials,
        enclave_name: &str,
    ) -> impl Future<Item = GetTokenResponse, Error = failure::Error> + Send + 'static
    {
        let mut uri_parts = self.base_uri.clone().into_parts();
        let uri_path_and_query = try_future!(
            format!("/v1/token/{}", enclave_name)
                .parse::<http::uri::PathAndQuery>()
                .context("error creating request path")
        );
        uri_parts.path_and_query = Some(uri_path_and_query);
        let uri = try_future!(Uri::from_parts(uri_parts).context("error creating request uri"));
        let response_with_parts = self.get_request(uri, credentials);
        let response = response_with_parts.map(|(_parts, response)| response);

        response.into()
    }

    pub fn delete_backups(
        &self,
        credentials: &KeyBackupApiCredentials
    ) -> impl Future<Item = (), Error = failure::Error> + Send + 'static
    {
        let mut uri_parts = self.base_uri.clone().into_parts();
        let uri_path_and_query = try_future!(
                "/v1/backup"
                .parse::<http::uri::PathAndQuery>()
                .context("error creating request path")
        );
        uri_parts.path_and_query = Some(uri_path_and_query);
        let uri = try_future!(Uri::from_parts(uri_parts).context("error creating request uri"));
        let response_with_parts = self.delete_request(uri, credentials);
        let response = response_with_parts.map(|(_parts, response)| response);

        response.into()
    }

    pub fn backup_request(
        &self,
        credentials: &KeyBackupApiCredentials,
        enclave_name: &str,
        request: kbupd_client::Request,
    ) -> impl Future<Item = kbupd_client::Response, Error = failure::Error> + Send + 'static
    {
        let client = kbupd_client::Client::new(&mut rand::thread_rng());

        let request_type = match &request {
            kbupd_client::Request { backup: Some(_), .. } => KeyBackupRequestType::Backup,
            kbupd_client::Request { restore: Some(_), .. } => KeyBackupRequestType::Restore,
            kbupd_client::Request { delete: Some(_), .. } => KeyBackupRequestType::Delete,
            _ => {
                return try_future::TryFuture::from_error(failure::err_msg("invalid empty client request"));
            }
        };

        let attestation_request = RemoteAttestationRequest {
            clientPublic: *client.client_pubkey(),
        };
        let attestation_response = self
            .get_attestation(credentials, enclave_name, attestation_request)
            .map_err(|error| error.context("error during attestation request").into());

        let state = self.clone();
        let credentials = credentials.clone();
        let enclave_name = enclave_name.to_string();

        let response = attestation_response.and_then(
            move |(attestation_response_cookies, attestation_response): (Vec<Cookie>, RemoteAttestationResponse)| {
                debug!("got attestation: {:?}", &attestation_response);
                let negotiation = kbupd_client::RequestNegotiation {
                    server_ephemeral_pubkey:      attestation_response.serverEphemeralPublic,
                    server_static_pubkey:         attestation_response.serverStaticPublic,
                    encrypted_pending_request_id: kbupd_client::EncryptedMessage {
                        iv:   attestation_response.iv,
                        mac:  attestation_response.tag,
                        data: attestation_response.ciphertext,
                    },
                };
                let (encrypted_request, pending_request) = try_future!(client.request(&mut rand::thread_rng(), negotiation, request));

                let key_backup_request = KeyBackupRequest {
                    requestId: encrypted_request.pending_request_id,
                    iv:        encrypted_request.encrypted_message.iv,
                    mac:       encrypted_request.encrypted_message.mac,
                    data:      encrypted_request.encrypted_message.data,
                    r#type:    request_type,
                };
                let key_backup_response = state
                    .put_backup_request(&credentials, &enclave_name, attestation_response_cookies, key_backup_request)
                    .map_err(|error| error.context("error during key backup request").into());

                let response = key_backup_response.and_then(move |key_backup_response: KeyBackupResponse| {
                    let encrypted_response = kbupd_client::EncryptedMessage {
                        iv:   key_backup_response.iv,
                        mac:  key_backup_response.mac,
                        data: key_backup_response.data,
                    };
                    pending_request.decrypt_reply(encrypted_response)
                });
                response.into()
            },
        );

        response.into()
    }

    pub fn get_attestation(
        &self,
        credentials: &KeyBackupApiCredentials,
        enclave_name: &str,
        request: RemoteAttestationRequest,
    ) -> impl Future<Item = (Vec<Cookie<'static>>, RemoteAttestationResponse), Error = failure::Error> + Send + 'static
    {
        let mut uri_parts = self.base_uri.clone().into_parts();
        let uri_path_and_query = try_future!(
            format!("/v1/attestation/{}", enclave_name)
                .parse::<http::uri::PathAndQuery>()
                .context("error creating request path")
        );
        uri_parts.path_and_query = Some(uri_path_and_query);
        let uri = try_future!(Uri::from_parts(uri_parts).context("error creating request uri"));
        let cookies = Vec::new();

        let response_with_parts = self.put_request(uri, credentials, cookies, request);
        let response_with_cookies =
            response_with_parts.and_then(|(response_parts, response): (response::Parts, RemoteAttestationResponse)| {
                let cookie_headers = response_parts.headers.get_all(header::SET_COOKIE);
                let cookies = cookie_headers
                    .into_iter()
                    .map(|cookie_header: &HeaderValue| -> Result<Cookie<'static>, failure::Error> {
                        let cookie_str = cookie_header.to_str()?;
                        let cookie = Cookie::parse(cookie_str)?;
                        Ok(cookie.into_owned())
                    });
                let cookies_vec = cookies.collect::<Result<Vec<Cookie>, _>>()?;
                Ok((cookies_vec, response))
            });

        response_with_cookies.into()
    }

    pub fn put_backup_request(
        &self,
        credentials: &KeyBackupApiCredentials,
        enclave_name: &str,
        cookies: Vec<Cookie<'static>>,
        request: KeyBackupRequest,
    ) -> impl Future<Item = KeyBackupResponse, Error = failure::Error> + Send + 'static
    {
        let mut uri_parts = self.base_uri.clone().into_parts();
        let uri_path_and_query = try_future!(
            format!("/v1/backup/{}", enclave_name)
                .parse::<http::uri::PathAndQuery>()
                .context("error creating request path")
        );
        uri_parts.path_and_query = Some(uri_path_and_query);
        let uri = try_future!(Uri::from_parts(uri_parts).context("error creating request uri"));
        let response_with_parts = self.put_request(uri, credentials, cookies, request);
        let response = response_with_parts.map(|(_parts, response)| response);
        response.into()
    }

    fn get_request<ResponseTy>(
        &self,
        uri: Uri,
        credentials: &KeyBackupApiCredentials,
    ) -> impl Future<Item = (response::Parts, ResponseTy), Error = failure::Error> + Send + 'static
    where
        ResponseTy: for<'de> Deserialize<'de> + Send + 'static,
    {
        let mut hyper_request = Request::new(Body::empty());

        *hyper_request.uri_mut() = uri;
        hyper_request.headers_mut().insert("Authorization", credentials.into());

        let response = self.client.request(hyper_request).map_err(failure::Error::from);
        let decoded_response = response.and_then(Self::decode_response);
        decoded_response
    }

    fn delete_request<ResponseTy>(
        &self,
        uri: Uri,
        credentials: &KeyBackupApiCredentials,
    ) -> impl Future<Item = (response::Parts, ResponseTy), Error = failure::Error> + Send + 'static
        where
            ResponseTy: for<'de> Deserialize<'de> + Send + 'static,
    {
        let mut hyper_request = Request::new(Body::empty());

        *hyper_request.method_mut() = Method::DELETE;
        *hyper_request.uri_mut() = uri;
        hyper_request.headers_mut().insert("Authorization", credentials.into());

        let response = self.client.request(hyper_request).map_err(failure::Error::from);
        let decoded_response = response.and_then(Self::decode_response);
        decoded_response
    }

    fn put_request<RequestTy, ResponseTy>(
        &self,
        uri: Uri,
        credentials: &KeyBackupApiCredentials,
        cookies: Vec<Cookie<'static>>,
        request: RequestTy,
    ) -> impl Future<Item = (response::Parts, ResponseTy), Error = failure::Error> + Send + 'static
    where
        RequestTy: Serialize + 'static,
        ResponseTy: for<'de> Deserialize<'de> + Send + 'static,
    {
        let encoded_request = try_future!(serde_json::to_vec(&request).context("error serializing request as json"));
        debug!(
            "sending backup request: {}",
            std::str::from_utf8(&encoded_request).unwrap_or("<invalid utf8>")
        );
        let mut hyper_request = Request::new(Body::from(encoded_request));

        *hyper_request.method_mut() = Method::PUT;
        *hyper_request.uri_mut() = uri;
        hyper_request
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        hyper_request.headers_mut().insert(header::AUTHORIZATION, credentials.into());

        for cookie in cookies {
            let cookie_header_value = try_future!(
                HeaderValue::from_str(&format!("{}={}", cookie.name(), cookie.value()))
                    .context("invalid cookie from server attestation response")
            );
            hyper_request.headers_mut().insert(header::COOKIE, cookie_header_value);
        }

        let response = self.client.request(hyper_request).map_err(failure::Error::from);
        let decoded_response = response.and_then(Self::decode_response);
        decoded_response.into()
    }

    fn decode_response<ResponseTy>(
        response: Response<Body>,
    ) -> impl Future<Item = (response::Parts, ResponseTy), Error = failure::Error> + Send + 'static
    where ResponseTy: for<'de> Deserialize<'de> + Send + 'static {
        let (response_parts, response_body) = response.into_parts();

        if !response_parts.status.is_success() {
            return TryFuture::from_error(format_err!("non-successful response code: {}", &response_parts.status));
        }
        let response_data = response_body.concat2().map_err(failure::Error::from);
        let decoded_response = response_data.and_then(|full_response: Chunk| match serde_json::from_slice(&full_response) {
            Ok(decoded_response) => Ok((response_parts, decoded_response)),
            Err(error) => {
                debug!(
                    "invalid server response: {}\n{}",
                    &error,
                    String::from_utf8_lossy(&full_response.to_vec())
                );
                Err(error.context("invalid server response").into())
            }
        });
        decoded_response.into()
    }
}

//
// KeyBackupApiCredentials impls
//

impl From<&KeyBackupApiCredentials> for HeaderValue {
    fn from(from: &KeyBackupApiCredentials) -> Self {
        let joined_credentials = format!("{}:{}", from.username, from.password);

        let mut authorization_header = "Basic ".to_string();
        base64::encode_config_buf(&joined_credentials, base64::STANDARD, &mut authorization_header);
        HeaderValue::from_str(&authorization_header).unwrap_or_else(|error| panic!("invalid authorization header: {}", error))
    }
}
