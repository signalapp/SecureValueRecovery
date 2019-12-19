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
use std::marker::{PhantomData};

use base64;
use serde::{Deserializer, Serializer};

pub fn decode(encoded: &[u8]) -> Result<Vec<u8>, base64::DecodeError> {
    let space_regex = regex::bytes::Regex::new(r"[ \t\r\n]").unwrap();
    let base64_data = space_regex.replace_all(encoded, &b""[..]);
    let config      = base64::Config::new(base64::CharacterSet::Standard, true);
    base64::decode_config(&base64_data, config)
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    deserializer.deserialize_bytes(Base64Visitor)
}

pub fn serialize<S: Serializer>(data: impl AsRef<[u8]>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&base64::encode(data.as_ref()))
}

//
// Base64Visitor impls
//

struct Base64Visitor;

impl<'de> serde::de::Visitor<'de> for Base64Visitor {
    type Value = Vec<u8>;
    fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str("a base64-encoded string")
    }

    fn visit_bytes<E>(self, base64: &[u8]) -> Result<Self::Value, E>
    where E: serde::de::Error
    {
        decode(base64).map_err(|error| E::custom(error.to_string()))
    }

    fn visit_str<E>(self, base64: &str) -> Result<Self::Value, E>
    where E: serde::de::Error
    {
        self.visit_bytes(base64.as_bytes())
    }
}

//
// FixedLengthBase64Visitor impls
//

struct FixedLengthBase64Visitor<T>(PhantomData<T>);

impl<'de, T> serde::de::Visitor<'de> for FixedLengthBase64Visitor<T>
where T: AsMut<[u8]> + AsRef<[u8]> + Default
{
    type Value = T;
    fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str("a base64-encoded string")
    }

    fn visit_bytes<E>(self, base64: &[u8]) -> Result<Self::Value, E>
    where E: serde::de::Error
    {
        let mut deserialized = T::default();
        let estimated_length = (base64.len() + 3) / 4 * 3;
        if estimated_length > deserialized.as_ref().len() + 2 {
            Err(E::custom(format!("base64 parameter length {} > {}", estimated_length, deserialized.as_ref().len())))
        } else {
            let data = decode(base64).map_err(|error| E::custom(error.to_string()))?;
            if data.len() != deserialized.as_ref().len() {
                Err(E::custom(format!("base64 parameter length {} != {}", data.len(), deserialized.as_ref().len())))
            } else {
                deserialized.as_mut().copy_from_slice(&data[..]);
                Ok(deserialized)
            }
        }
    }

    fn visit_str<E>(self, base64: &str) -> Result<Self::Value, E>
    where E: serde::de::Error
    {
        self.visit_bytes(base64.as_bytes())
    }
}

pub trait SerdeFixedLengthBase64: Sized + AsMut<[u8]> + AsRef<[u8]> + Default {
    fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_bytes(FixedLengthBase64Visitor(PhantomData))
    }

    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize(self, serializer)
    }
}

impl<T: AsMut<[u8]> + AsRef<[u8]> + Default> SerdeFixedLengthBase64 for T {
}
