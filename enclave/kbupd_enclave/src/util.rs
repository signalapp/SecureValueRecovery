//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use crate::prelude::*;

use std::fmt;

use base64;
use serde::de::Error;
use serde::{Deserialize, Deserializer};

pub use crate::protobufs::kbupd::*;
pub use sgx_ffi::util::*;

pub struct ToHex<'a>(pub &'a [u8]);

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

pub struct OptionDisplay<T>(pub Option<T>);

impl<T> fmt::Display for OptionDisplay<T>
where T: fmt::Display
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let Self(inner) = self;
        match inner {
            Some(inner) => fmt::Display::fmt(inner, fmt),
            None => write!(fmt, "<none>"),
        }
    }
}

impl<T> fmt::Debug for OptionDisplay<T>
where T: fmt::Display
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        fmt::Display::fmt(self, fmt)
    }
}

pub struct ListDisplay<T>(pub T);

impl<T> fmt::Display for ListDisplay<T>
where
    T: IntoIterator + Clone,
    T::Item: fmt::Display,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let Self(inner) = self;
        fmt.debug_list().entries(inner.clone().into_iter().map(DisplayAsDebug)).finish()
    }
}

impl<T> fmt::Debug for ListDisplay<T>
where
    T: IntoIterator + Clone,
    T::Item: fmt::Display,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        fmt::Display::fmt(self, fmt)
    }
}

pub struct DisplayAsDebug<T>(pub T);

impl<T> fmt::Debug for DisplayAsDebug<T>
where T: fmt::Display
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let Self(inner) = self;
        fmt::Display::fmt(inner, fmt)
    }
}

pub fn deserialize_base64<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    Deserialize::deserialize(deserializer)
        .and_then(|base64: &[u8]| base64::decode(base64).map_err(|error| D::Error::custom(error.to_string())))
}

pub fn copy_exact<T>(src: &[u8]) -> Result<T, ()>
where T: AsMut<[u8]> + Default {
    let mut dst = T::default();
    if src.len() == dst.as_mut().len() {
        dst.as_mut().copy_from_slice(src);
        Ok(dst)
    } else {
        Err(())
    }
}

pub fn memory_status() -> EnclaveMemoryStatus {
    let memory_status = MemoryStatus::collect();
    EnclaveMemoryStatus {
        footprint_bytes: memory_status.footprint_bytes,
        used_bytes:      memory_status.used_bytes,
        free_chunks:     memory_status.free_chunks,
    }
}

pub trait ToUsize {
    fn to_usize(self) -> usize;
}

#[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
impl ToUsize for u32 {
    fn to_usize(self) -> usize {
        self as usize
    }
}

#[allow(clippy::cast_possible_truncation)]
#[cfg(any(target_pointer_width = "64"))]
impl ToUsize for u64 {
    fn to_usize(self) -> usize {
        self as usize
    }
}

pub trait ToU64 {
    fn to_u64(self) -> u64;
}

#[cfg(any(target_pointer_width = "64"))]
impl ToU64 for usize {
    fn to_u64(self) -> u64 {
        self as u64
    }
}
