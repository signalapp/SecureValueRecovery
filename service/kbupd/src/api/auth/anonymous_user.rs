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

use super::*;

pub struct AnonymousUser {
    _private: (),
}

#[derive(Clone, Copy, Default)]
pub struct AnonymousUserAuthenticator;

pub enum AnonymousUserAuthenticationError {
}

impl Authenticator for AnonymousUserAuthenticator {
    type User  = AnonymousUser;
    type Error = AnonymousUserAuthenticationError;
    fn authenticate(&self, _maybe_credentials: Option<BasicCredentials>) -> Result<Self::User, Self::Error> {
        Ok(AnonymousUser {
            _private: (),
        })
    }
}

impl fmt::Display for AnonymousUserAuthenticationError {
    fn fmt(&self, _fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {}
    }
}
