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

use serde::{Deserializer, Serializer};

use super::{ToHex};

pub fn parse(hex: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(hex)
}

pub fn parse_fixed<T>(hex: &str) -> Result<T, hex::FromHexError>
where T: Sized + AsMut<[u8]> + AsRef<[u8]> + Default
{
    let mut bytes = T::default();
    let () = hex::decode_to_slice(hex, bytes.as_mut())?;
    Ok(bytes)
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    deserializer.deserialize_str(HexVisitor)
}

pub fn serialize<S: Serializer>(data: impl AsRef<[u8]>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&format!("{}", ToHex(data.as_ref())))
}

//
// HexVisitor impls
//

struct HexVisitor;

impl<'de> serde::de::Visitor<'de> for HexVisitor {
    type Value = Vec<u8>;
    fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str("a hexadecimal-encoded string")
    }
    fn visit_str<E>(self, hex: &str) -> Result<Vec<u8>, E>
    where E: serde::de::Error
    {
        parse(hex).map_err(|error| E::custom(format!("{}", error)))
    }
}

//
// FixedLengthHexVisitor impls
//

struct FixedLengthHexVisitor<T>(PhantomData<T>);

impl<'de, T> serde::de::Visitor<'de> for FixedLengthHexVisitor<T>
where T: AsMut<[u8]> + AsRef<[u8]> + Default
{
    type Value = T;
    fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str("a hexadecimal-encoded string")
    }
    fn visit_str<E>(self, hex: &str) -> Result<Self::Value, E>
    where E: serde::de::Error
    {
        parse_fixed(hex).map_err(|error| E::custom(format!("{}", error)))
    }
}

pub trait SerdeFixedLengthHex: Sized + AsMut<[u8]> + AsRef<[u8]> + Default {
    fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(FixedLengthHexVisitor(PhantomData))
    }

    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize(self, serializer)
    }
}

impl<T: AsMut<[u8]> + AsRef<[u8]> + Default> SerdeFixedLengthHex for T {
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(&parse("").unwrap(),       b"");
        assert_eq!(&parse("616263").unwrap(), b"abc");
        assert_eq!(&parse("00fF").unwrap(),   b"\x00\xFF");

        parse("\n").unwrap_err();
        parse(" ").unwrap_err();
        parse(" 00").unwrap_err();
        parse("00 ").unwrap_err();
        parse("00\n").unwrap_err();
        parse(" 00 ").unwrap_err();
        parse("0 0").unwrap_err();
        parse("0").unwrap_err();
        parse("0g").unwrap_err();
        parse("0\x00").unwrap_err();
        parse("\x00").unwrap_err();
        parse("\x00\x00").unwrap_err();
        parse("FF\x7F").unwrap_err();
        parse("000").unwrap_err();
    }

    #[test]
    fn test_parse_fixed() {
        assert_eq!(&parse_fixed::<[u8; 0]>("").unwrap(),       b"");
        assert_eq!(&parse_fixed::<[u8; 3]>("616263").unwrap(), b"abc");
        assert_eq!(&parse_fixed::<[u8; 2]>("00fF").unwrap(),   b"\x00\xFF");

        parse_fixed::<[u8; 1]>("").unwrap_err();
        parse_fixed::<[u8; 0]>("00").unwrap_err();
        parse_fixed::<[u8; 2]>("00").unwrap_err();

        macro_rules! test_parse_fixed {
            ($n:literal) => ({
                parse_fixed::<[u8; $n]>("\n").unwrap_err();
                parse_fixed::<[u8; $n]>(" ").unwrap_err();
                parse_fixed::<[u8; $n]>(" 00").unwrap_err();
                parse_fixed::<[u8; $n]>("00 ").unwrap_err();
                parse_fixed::<[u8; $n]>("00\n").unwrap_err();
                parse_fixed::<[u8; $n]>(" 00 ").unwrap_err();
                parse_fixed::<[u8; $n]>("0 0").unwrap_err();
                parse_fixed::<[u8; $n]>("0").unwrap_err();
                parse_fixed::<[u8; $n]>("0g").unwrap_err();
                parse_fixed::<[u8; $n]>("0\x00").unwrap_err();
                parse_fixed::<[u8; $n]>("\x00").unwrap_err();
                parse_fixed::<[u8; $n]>("\x00\x00").unwrap_err();
                parse_fixed::<[u8; $n]>("FF\x7F").unwrap_err();
                parse_fixed::<[u8; $n]>("000").unwrap_err();
            })
        }
        test_parse_fixed!(0);
        test_parse_fixed!(1);
        test_parse_fixed!(2);
    }
}
