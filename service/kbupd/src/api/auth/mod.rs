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

pub mod anonymous_user;
pub mod signal_user;

use std::fmt;
use std::str;

use hyper::header::{HeaderValue};

pub trait Authenticator {
    type User:  Send + 'static;
    type Error: fmt::Display;
    fn authenticate(&self, maybe_credentials: Option<BasicCredentials>) -> Result<Self::User, Self::Error>;
}

pub struct BasicCredentials {
    username: String,
    password: String,
}

pub enum AuthorizationHeaderError {
    UnsupportedAuthorizationMethod,
    InvalidAuthorizationHeader,
    InvalidCredentials,
}

//
// BasicCredentials impls
//

impl BasicCredentials {
    pub fn try_from(header_value: &HeaderValue) -> Result<Self, AuthorizationHeaderError> {
        let header           = header_value.to_str().map_err(|_| AuthorizationHeaderError::InvalidAuthorizationHeader)?;
        let mut header_parts = header.split(" ");

        if "Basic" != header_parts.next().ok_or(AuthorizationHeaderError::InvalidAuthorizationHeader)? {
            return Err(AuthorizationHeaderError::UnsupportedAuthorizationMethod);
        }

        let base64_value              = header_parts.next().ok_or(AuthorizationHeaderError::InvalidAuthorizationHeader)?;
        let concatenated_values_bytes = base64::decode(base64_value).map_err(|_| AuthorizationHeaderError::InvalidAuthorizationHeader)?;
        let concatenated_values       = str::from_utf8(&concatenated_values_bytes).map_err(|_| AuthorizationHeaderError::InvalidCredentials)?;
        let mut credential_parts      = concatenated_values.splitn(2, ":");

        Ok(Self {
            username: credential_parts.next().ok_or(AuthorizationHeaderError::InvalidCredentials)?.to_string(),
            password: credential_parts.next().ok_or(AuthorizationHeaderError::InvalidCredentials)?.to_string(),
        })
    }
}
