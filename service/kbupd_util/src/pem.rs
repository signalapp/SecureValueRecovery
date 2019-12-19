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

pub fn decode(pem: &[u8]) -> Vec<Vec<u8>> {
    // based on RFC7468
    let re = regex::bytes::Regex::new(r"(?-u)-----BEGIN (?:[\x21-\x2C\x2E-\x7E](?:[- ]?[\x21-\x2C\x2E-\x7E])*)?-----[ \t]*(?:\r|\n|\r\n)[ \t\r\n]*([ \t\r\n\x2B\x2F\x30-\x39\x3D\x41-\x5A\x61-\x7A]*)(?:\r|\n|\r\n)-----END (?:[\x21-\x2C\x2E-\x7E](?:[- ]?[\x21-\x2C\x2E-\x7E])*)?-----").unwrap();

    let mut certificates: Vec<Vec<u8>> = Vec::new();
    for captures in re.captures_iter(pem) {
        if let Ok(der) = crate::base64::decode(&captures[1]) {
            if !der.is_empty() {
                certificates.push(der);
            }
        }
    }
    certificates
}

pub fn encode<T>(tag: &str, certificates_der: impl IntoIterator<Item = T> + Clone) -> String
where T: AsRef<[u8]>
{
    const PEM_BEGIN:      &'static str = "-----BEGIN ";
    const PEM_END:        &'static str = "-----END ";
    const PEM_TAG_SUFFIX: &'static str = "-----\n";

    let config = base64::Config::new(base64::CharacterSet::Standard, true);

    let mut approx_len = 0;
    for certificate_der in certificates_der.clone() {
        let unwrapped_len = certificate_der.as_ref().len() * 4 / 3 + 4;
        approx_len += PEM_BEGIN.len() + tag.len() + PEM_TAG_SUFFIX.len();
        approx_len += unwrapped_len + (unwrapped_len / 64);
        approx_len += PEM_END.len() + tag.len() + PEM_TAG_SUFFIX.len();
    }

    let mut encoded = String::with_capacity(approx_len);
    for certificate_der in certificates_der {
        encoded.push_str(PEM_BEGIN);
        encoded.push_str(tag);
        encoded.push_str(PEM_TAG_SUFFIX);

        let base64:       String = base64::encode_config(certificate_der.as_ref(), config);
        let base64_bytes: &[u8]  = base64.as_ref();
        for base64_line_bytes in base64_bytes.chunks(64) {
            let base64_line_str = str::from_utf8(base64_line_bytes)
                .unwrap_or_else(|_| unreachable!("base64 is ascii"));
            encoded.push_str(base64_line_str);
            encoded.push_str("\n");
        }

        encoded.push_str(PEM_END);
        encoded.push_str(tag);
        encoded.push_str(PEM_TAG_SUFFIX);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode() {
        assert!(decode(b"").is_empty());
        assert!(decode(b"test").is_empty());
        // malformed data
        assert!(decode(b"-----BEGIN TEST-----\n.GVzdA==\n-----END TEST-----").is_empty());
        // malformed tag
        assert!(decode(b"-----BEGIN TEST------\ndGVzdA==\n-----END TEST-----").is_empty());
        assert!(decode(b"-----BEGIN TEST -----\ndGVzdA==\n-----END TEST-----").is_empty());
        assert!(decode(b"-----BEGIN TEST-----\ndGVzdA==\n-----END TEST -----").is_empty());
        // missing line break
        assert!(decode(b"-----BEGIN TEST -----dGVzdA==\n-----END TEST-----").is_empty());
        assert!(decode(b"-----BEGIN TEST -----\ndGVzdA==-----END TEST-----").is_empty());
        // missing data
        assert!(decode(b"-----BEGIN TEST-----\n\n-----END TEST-----").is_empty());
        assert!(decode(b"-----BEGIN TEST-----\n \n-----END TEST-----").is_empty());
        // valid tests
        assert_eq!(decode(b"-----BEGIN -----\ndGVzdA==\n-----END -----"), [b"test"]);
        assert_eq!(decode(b"-----BEGIN -----\t \r\n dGVzdA== \n\n-----END TEST-----"), [b"test"]);
        assert_eq!(decode(b"-----BEGIN TEST-----\t \r\n dGVzdA== \n\n-----END TEST-----"), [b"test"]);
        assert_eq!(decode(b"-----BEGIN TEST1 TEST2-----\t \r\n d\tG VzdA== \n\n-----END TEST1-TEST2-----"), [b"test"]);
        let test_certs = [b"test"];
        assert_eq!(decode(encode("", &test_certs).as_bytes()), test_certs);
        let test_certs = [b"test1", b"test2"];
        assert_eq!(decode(encode("SOME TAG", &test_certs).as_bytes()), test_certs);
    }

    #[test]
    fn test_encode() {
        let no_certs: [&'static [u8]; 0] = [];
        assert_eq!(encode("TEST", &no_certs), "");
        assert_eq!(encode("", &[b"test"]), "-----BEGIN -----\ndGVzdA==\n-----END -----\n");
        assert_eq!(encode("TEST", &[b""]), "-----BEGIN TEST-----\n-----END TEST-----\n");
        assert_eq!(encode("TEST", &[b"test1", b"test2"]),
                   "-----BEGIN TEST-----\ndGVzdDE=\n-----END TEST-----\n-----BEGIN TEST-----\ndGVzdDI=\n-----END TEST-----\n");
    }
}
