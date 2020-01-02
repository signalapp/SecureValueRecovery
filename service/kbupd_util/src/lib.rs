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

pub mod base64;
pub mod duration;
pub mod hex;
pub mod pem;
pub mod percent;
pub mod thread;

use std::fmt;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};

pub struct ToHex<'a>(pub &'a [u8]);
pub struct OptionDisplay<T>(pub Option<T>);
pub struct ListDisplay<T>(pub T);
pub struct DisplayAsDebug<T>(pub T);

pub enum Never {}

pub fn to_socket_addr(address: impl ToSocketAddrs) -> io::Result<SocketAddr> {
    address
        .to_socket_addrs()?
        .next()
        .ok_or(io::Error::new(io::ErrorKind::Other, "empty listen address"))
}

//
// ToHex impls
//

impl<'a> ToHex<'a> {
    pub fn new<T: AsRef<[u8]>>(bytes: &'a T) -> Self {
        ToHex(bytes.as_ref())
    }
}

impl<'a> fmt::Display for ToHex<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ToHex(data) = self;
        for byte in *data {
            write!(fmt, "{:02x}", byte)?;
        }
        Ok(())
    }
}
impl<'a> fmt::Debug for ToHex<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

impl<T> fmt::Display for OptionDisplay<T>
where T: fmt::Display
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let OptionDisplay(inner) = self;
        match inner {
            Some(inner) => fmt::Display::fmt(inner, fmt),
            None        => write!(fmt, "<none>"),
        }
    }
}

//
// OptionDisplay impls
//

impl<T> fmt::Debug for OptionDisplay<T>
where T: fmt::Display
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

//
// ListDisplay impls
//

impl<T> fmt::Display for ListDisplay<T>
where
    T: IntoIterator + Clone,
    T::Item: fmt::Display,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ListDisplay(inner) = self;
        fmt.debug_list().entries(inner.clone().into_iter().map(DisplayAsDebug)).finish()
    }
}

impl<T> fmt::Debug for ListDisplay<T>
where
    T: IntoIterator + Clone,
    T::Item: fmt::Display,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

//
// DisplayAsDebug impls
//

impl<T> fmt::Debug for DisplayAsDebug<T>
where T: fmt::Display
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let DisplayAsDebug(inner) = self;
        fmt::Display::fmt(inner, fmt)
    }
}

//
// Never impls
//

macro_rules! from_never {
    ($type:ty) => {
        impl From<Never> for $type {
            fn from(never: Never) -> Self {
                match never {}
            }
        }
    };
}

from_never!(());
