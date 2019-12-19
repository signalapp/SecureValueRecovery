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
use std::str;
use std::time::{Duration, SystemTime};

use ring::constant_time;
use ring::digest;
use ring::hmac;

use super::*;
use crate::util;

#[derive(Clone, Debug)]
pub struct SignalUser {
    pub username: String,
    _private: (),
}

pub struct SignalUserAuthenticator {
    hmac_key: hmac::SigningKey,
}

#[derive(failure::Fail)]
pub enum SignalUserAuthenticationError {
    #[fail(display = "unauthenticated")]
    Unauthenticated,
    #[fail(display = "invalid user authorization token")]
    InvalidAuthorizationToken,
    #[fail(display = "expired user authorization token")]
    ExpiredAuthorizationToken,
}

impl SignalUser {
    #[cfg(test)]
    pub fn new(username: String) -> Self {
        Self { username, _private: () }
    }
}

//
// SignalUserAuthenticator impls
//

impl Authenticator for SignalUserAuthenticator {
    type User  = SignalUser;
    type Error = SignalUserAuthenticationError;
    fn authenticate(&self, maybe_credentials: Option<BasicCredentials>) -> Result<Self::User, Self::Error> {
        let credentials = maybe_credentials.ok_or(SignalUserAuthenticationError::Unauthenticated)?;
        let mut parts   = credentials.password.split(":");
        let username    = parts.next().ok_or(SignalUserAuthenticationError::InvalidAuthorizationToken)?;
        let timestamp   = parts.next().ok_or(SignalUserAuthenticationError::InvalidAuthorizationToken)?;
        let signature   = parts.next().ok_or(SignalUserAuthenticationError::InvalidAuthorizationToken)?;
        if parts.next().is_some() {
            return Err(SignalUserAuthenticationError::InvalidAuthorizationToken);
        }
        if username != credentials.username {
            return Err(SignalUserAuthenticationError::InvalidAuthorizationToken);
        }
        if !self.is_valid_time(timestamp, SystemTime::now())? {
            return Err(SignalUserAuthenticationError::ExpiredAuthorizationToken);
        }
        if !self.is_valid_signature(&format!("{}:{}", username, timestamp), signature)? {
            return Err(SignalUserAuthenticationError::InvalidAuthorizationToken);
        }
        Ok(SignalUser {
            username: credentials.username,
            _private: (),
        })
    }
}

impl SignalUserAuthenticator {
    pub fn new(shared_secret: &[u8]) -> Self {
        Self {
            hmac_key: hmac::SigningKey::new(&digest::SHA256, shared_secret),
        }
    }
    fn is_valid_time(&self, timestamp: &str, now: SystemTime) -> Result<bool, SignalUserAuthenticationError> {
        let token_time: Duration = Duration::from_secs(timestamp.parse().map_err(|_| SignalUserAuthenticationError::InvalidAuthorizationToken)?);
        let our_time:   Duration = now.duration_since(SystemTime::UNIX_EPOCH).map_err(|_| SignalUserAuthenticationError::ExpiredAuthorizationToken)?;
        let distance:   Duration = our_time.checked_sub(token_time).unwrap_or_else(|| token_time - our_time);
        Ok(distance.as_secs() < 86400)
    }
    fn is_valid_signature(&self, data: &str, signature: &str) -> Result<bool, SignalUserAuthenticationError> {
        let their_suffix:  Vec<u8>         = util::hex::parse(signature).map_err(|_| SignalUserAuthenticationError::InvalidAuthorizationToken)?;
        let our_signature: hmac::Signature = hmac::sign(&self.hmac_key, data.as_bytes());
        let our_suffix:    &[u8]           = &our_signature.as_ref()[..10];
        Ok(constant_time::verify_slices_are_equal(our_suffix, &their_suffix).is_ok())
    }
}

//
// SignalUserAuthenticationError impls
//

impl fmt::Debug for SignalUserAuthenticationError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

#[cfg(test)]
pub mod test {
    use std::fmt;
    use std::time::{SystemTime};

    use ring::digest;
    use ring::hmac;

    use crate::util;

    pub struct MockSignalUserToken {
        pub hmac_key: [u8; 32],
        pub username: String,
    }
    impl MockSignalUserToken {
        pub fn new(hmac_key: [u8; 32], username: String) -> Self {
            Self { hmac_key, username }
        }
    }
    impl fmt::Display for MockSignalUserToken {
        fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
            let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
            let signdata  = format!("{}:{}", &self.username, timestamp);
            let signature = hmac::sign(&hmac::SigningKey::new(&digest::SHA256, &self.hmac_key), signdata.as_bytes());
            write!(fmt, "{}:{}", signdata, util::ToHex(&signature.as_ref()[..10]))
        }
    }
}
