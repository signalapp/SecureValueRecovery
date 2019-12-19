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

use std::str;

pub fn decode(encoded: &[u8]) -> Vec<u8> {
    let re = regex::bytes::Regex::new(r"(?-u)%(?:([\x30-\x39\x41-\x46\x61-\x66]{2})|(%))").unwrap();

    let mut decoded: Vec<u8> = Vec::with_capacity(encoded.len());
    let mut last_match_end = 0;
    for capture in re.captures_iter(encoded) {
        if let Some(capture_match) = capture.get(1) {
            decoded.extend(&encoded[last_match_end..(capture_match.start() - 1)]);
            decoded.push(u8::from_str_radix(str::from_utf8(capture_match.as_bytes()).unwrap(), 16).unwrap());
            last_match_end = capture_match.end();
        } else if let Some(capture_match) = capture.get(2) {
            decoded.extend(&encoded[last_match_end..capture_match.start()]);
            last_match_end = capture_match.end();
        }
    }
    decoded.extend(&encoded[last_match_end..]);
    decoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode() {
        // valid tests
        assert_eq!(decode(b""), b"");
        assert_eq!(decode(b"%20"), b" ");
        assert_eq!(decode(b"%%"), b"%");
        assert_eq!(decode(b"ABCD"), b"ABCD");
        assert_eq!(decode(b"%41BC"), b"ABC");
        assert_eq!(decode(b"AB%%%43"), b"AB%C");
        assert_eq!(decode(b"test1%20test2"), b"test1 test2");
        assert_eq!(decode(b"test1%20%20test2"), b"test1  test2");
        assert_eq!(decode(b"%00%FF"), b"\x00\xFF");
        // invalid hex
        assert_eq!(decode(b"%"), b"%");
        assert_eq!(decode(b"%A"), b"%A");
        assert_eq!(decode(b"%%A"), b"%A");
        assert_eq!(decode(b"%%%"), b"%%");
        assert_eq!(decode(b"%AZ"), b"%AZ");
        assert_eq!(decode(b"AB%C"), b"AB%C");
        assert_eq!(decode(b"AB%C%D"), b"AB%C%D");
        assert_eq!(decode(b"AB%C%44"), b"AB%CD");
    }
}
