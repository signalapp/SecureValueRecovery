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

use std::fmt;
use std::mem;

use failure::{format_err, ResultExt};
use futures::prelude::*;
use http::header::HeaderValue;
use http::uri::PathAndQuery;
use http::{self, HeaderMap, Uri};
use hyper::client::connect::Connect;
use hyper::{Body, Chunk, Client, Method, Request, Response};
use kbupd_util::base64;
use serde_derive::{Deserialize, Serialize};
use serde_json;
use sgx_sdk_ffi::SgxQuote;
use try_future::{try_future, TryFuture};

pub struct IasClient<C> {
    base_uri: Uri,
    api_key:  Option<HeaderValue>,
    client:   Client<C, Body>,
}

#[derive(Debug, failure::Fail)]
pub enum GetQuoteSignatureError {
    #[fail(display = "error fetching signed quote: {:?}", _0)]
    FetchError(#[cause] failure::Error),
    #[fail(display = "quote verification error: {:?}", _0)]
    QuoteVerificationError(#[cause] QuoteVerificationError),
}

#[derive(Clone, Default)]
pub struct SignatureRevocationList(pub Vec<u8>);

impl<C> IasClient<C>
where
    C: Connect + 'static,
    C::Transport: 'static,
    C::Future: 'static,
{
    pub fn new(base_uri: &str, api_key: Option<&str>, connector: C) -> Result<Self, failure::Error> {
        let base_uri = if api_key.is_some() {
            uri_path_join(base_uri.parse()?, format_args!("/attestation/v3"))?
        } else {
            uri_path_join(base_uri.parse()?, format_args!("/attestation/sgx/v3"))?
        };
        let client = Client::builder().build(connector);
        let api_key = match api_key {
            Some(api_key) => Some(HeaderValue::from_bytes(api_key.as_bytes()).context("invalid IAS API key value")?),
            None          => None,
        };
        Ok(Self { base_uri, api_key, client })
    }

    pub fn get_signature_revocation_list(&self, gid: u32) -> impl Future<Item = SignatureRevocationList, Error = failure::Error> {
        let uri = try_future!(self.request_uri(format_args!("/sigrl/{:08x}", gid)));

        let mut hyper_request = Request::new(Body::empty());

        *hyper_request.method_mut() = Method::GET;
        *hyper_request.uri_mut() = uri;

        if let Some(api_key) = &self.api_key {
            hyper_request.headers_mut().insert("Ocp-Apim-Subscription-Key", api_key.clone());
        }

        let response = self.client.request(hyper_request);
        let response_data = response.from_err().and_then(|response: Response<Body>| {
            if !response.status().is_success() {
                return TryFuture::from_error(format_err!("HTTP error: {}", response.status().as_str()));
            }
            response.into_body().concat2().from_err().into()
        });

        let decoded_response =
            response_data.and_then(|data: Chunk| base64::decode(&data).map(SignatureRevocationList).into_future().from_err());

        decoded_response.into()
    }

    fn fetch_quote_signature(&self, quote: &[u8]) -> impl Future<Item = (http::response::Parts, Chunk), Error = failure::Error> {
        let uri = try_future!(self.request_uri(format_args!("/report")));

        let request = QuoteSignatureRequest { isvEnclaveQuote: quote };
        let encoded_request = try_future!(serde_json::to_vec(&request));
        let mut hyper_request = Request::new(Body::from(encoded_request));

        *hyper_request.method_mut() = Method::POST;
        *hyper_request.uri_mut() = uri;
        hyper_request
            .headers_mut()
            .insert("Content-Type", HeaderValue::from_static("application/json"));

        if let Some(api_key) = &self.api_key {
            hyper_request.headers_mut().insert("Ocp-Apim-Subscription-Key", api_key.clone());
        }

        let response = self.client.request(hyper_request);
        let full_response = response.and_then(move |response: Response<Body>| {
            let (response_parts, response_body) = response.into_parts();

            let response_data = response_body.concat2();

            response_data.map(|response_data| (response_parts, response_data))
        });
        full_response.from_err().into()
    }

    pub fn get_quote_signature(
        &self,
        quote: Vec<u8>,
        accept_group_out_of_date: bool,
    ) -> impl Future<Item = SignedQuote, Error = GetQuoteSignatureError>
    {
        let response = self.fetch_quote_signature(&quote);
        let signed_quote = response.then(move |response_result: Result<(http::response::Parts, Chunk), failure::Error>| {
            let (response_parts, response_data) = response_result.map_err(GetQuoteSignatureError::FetchError)?;

            let signed_quote_result = validate_quote_signature(response_parts, response_data, quote, accept_group_out_of_date);
            signed_quote_result.map_err(GetQuoteSignatureError::QuoteVerificationError)
        });

        signed_quote
    }

    fn request_uri(&self, request_path: fmt::Arguments<'_>) -> Result<Uri, failure::Error> {
        uri_path_join(self.base_uri.clone(), request_path)
    }
}

impl<C> Clone for IasClient<C> {
    fn clone(&self) -> Self {
        Self {
            base_uri: self.base_uri.clone(),
            api_key:  self.api_key.clone(),
            client:   self.client.clone(),
        }
    }
}

fn uri_path_join(uri: Uri, append_path: fmt::Arguments<'_>) -> Result<Uri, failure::Error> {
    let mut parts = uri.into_parts();
    let path_base = parts
        .path_and_query
        .as_ref()
        .map(PathAndQuery::path)
        .unwrap_or_default()
        .trim_end_matches('/');
    parts.path_and_query = Some(format!("{}{}", path_base, append_path).parse::<http::uri::PathAndQuery>()?);
    let uri = Uri::from_parts(parts)?;
    Ok(uri)
}

fn validate_quote_signature(
    response_parts: http::response::Parts,
    response_body_data: Chunk,
    quote: Vec<u8>,
    accept_group_out_of_date: bool,
) -> Result<SignedQuote, QuoteVerificationError>
{
    if !response_parts.status.is_success() {
        let response_body_string = String::from_utf8_lossy(&response_body_data).to_string();
        return Err(QuoteVerificationError::HttpError(
            response_parts.status,
            response_parts,
            response_body_string,
        ));
    }

    let base64_signature = get_header_str(&response_parts.headers, "X-IASReport-Signature")?;
    let pem_certificates = get_header_str(&response_parts.headers, "X-IASReport-Signing-Certificate")?;

    let signature =
        base64::decode(base64_signature.as_bytes()).map_err(|_| QuoteVerificationError::InvalidSignature(base64_signature.to_string()))?;

    let certificates = kbupd_util::pem::decode(&kbupd_util::percent::decode(pem_certificates.as_bytes()));

    if certificates.is_empty() {
        return Err(QuoteVerificationError::InvalidCertificates(pem_certificates.to_string()));
    }

    let body = response_body_data.to_vec();

    let parsed_body: QuoteSignatureResponseBody =
        serde_json::from_slice(&body).map_err(|parse_error| QuoteVerificationError::InvalidJson(parse_error.into()))?;

    if parsed_body.version != 3 {
        return Err(QuoteVerificationError::WrongVersion(parsed_body.version));
    }

    if Some(&parsed_body.isvEnclaveQuoteBody[..]) != quote.get(..mem::size_of::<SgxQuote>() - 4) {
        return Err(QuoteVerificationError::WrongQuote);
    }

    match parsed_body.isvEnclaveQuoteStatus.as_str() {
        "OK" => {}
        "GROUP_OUT_OF_DATE" | "CONFIGURATION_NEEDED" => {
            if !accept_group_out_of_date {
                return Err(QuoteVerificationError::GroupOutOfDate(
                    parsed_body.isvEnclaveQuoteStatus.clone(),
                    parsed_body,
                ));
            }
        }
        "GROUP_REVOKED"                              => {
            return Err(QuoteVerificationError::GroupOutOfDate(
                parsed_body.isvEnclaveQuoteStatus.clone(),
                parsed_body,
            ));
        }
        "SIGRL_VERSION_MISMATCH" => {
            return Err(QuoteVerificationError::StaleRevocationList);
        }
        _ => {
            return Err(QuoteVerificationError::AttestationError(parsed_body.isvEnclaveQuoteStatus));
        }
    }

    // XXX validate timestamp

    Ok(SignedQuote {
        quote,
        body,
        signature,
        certificates,
    })
}

fn get_header_str<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str, QuoteVerificationError> {
    if let Some(header) = headers.get(name) {
        match header.to_str() {
            Ok(header) => Ok(header),
            Err(_)     => Err(QuoteVerificationError::InvalidHeaderValue(name, header.clone())),
        }
    } else {
        Err(QuoteVerificationError::MissingHeader(name))
    }
}

impl std::ops::Deref for SignatureRevocationList {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(failure::Fail)]
pub enum QuoteVerificationError {
    #[fail(display = "attestation http error: {}", _0)]
    HttpError(http::status::StatusCode, http::response::Parts, String),
    #[fail(display = "missing attestation http header {}", _0)]
    MissingHeader(&'static str),
    #[fail(display = "invalid attestation http header value for {}: {:?}", _0, _1)]
    InvalidHeaderValue(&'static str, HeaderValue),
    #[fail(display = "invalid attestation signature: {}", _0)]
    InvalidSignature(String),
    #[fail(display = "invalid attestation certificates: {}", _0)]
    InvalidCertificates(String),
    #[fail(display = "invalid attestation report json: {}", _0)]
    InvalidJson(#[cause] failure::Error),
    #[fail(display = "invalid attestation report version: {}", _0)]
    WrongVersion(u64),
    #[fail(display = "wrong attestation report quote")]
    WrongQuote,
    #[fail(display = "stale attestation revocation list")]
    StaleRevocationList,
    #[fail(display = "attestation group out of date: {}", _0)]
    GroupOutOfDate(String, QuoteSignatureResponseBody),
    #[fail(display = "attestation error: {}", _0)]
    AttestationError(String),
}

impl fmt::Debug for QuoteVerificationError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

#[derive(Debug)]
pub struct SignedQuote {
    pub quote:        Vec<u8>,
    pub body:         Vec<u8>,
    pub signature:    Vec<u8>,
    pub certificates: Vec<Vec<u8>>,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
pub struct QuoteSignatureRequest<'a> {
    #[serde(with = "base64")]
    pub isvEnclaveQuote: &'a [u8],
}

#[allow(non_snake_case)]
#[derive(Deserialize, Debug)]
pub struct QuoteSignatureResponseBody {
    pub isvEnclaveQuoteStatus: String,

    #[serde(with = "base64")]
    pub isvEnclaveQuoteBody: Vec<u8>,

    pub version: u64,

    pub timestamp: String,

    pub platformInfoBlob: Option<String>,
}
