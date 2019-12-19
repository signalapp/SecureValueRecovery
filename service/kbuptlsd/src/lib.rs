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

#![allow(unused_parens)]

pub use rustunnel as child;

mod base64;
pub mod client;
pub mod config;
pub mod counter;
pub mod proxy_child;
pub mod server;
pub mod util;

pub mod prelude {
    pub use crate::client::{TlsClientProxySpawner, TlsClientProxyArguments, TlsClientProxyCaArgument, TlsClientProxyHostnameArgument};
    #[cfg(feature = "hyper")]
    pub use crate::client::hyper::{TlsProxyConnector};
    pub use crate::server::{TlsProxyListener, TlsProxyListenerArguments};
    pub use crate::proxy_child::{TlsProxyChild, TlsProxyStream, TlsProxyStderrStream};
}
