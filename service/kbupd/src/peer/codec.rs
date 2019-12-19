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

use std::sync::{Arc};

use bytes::{Buf, BufMut, BytesMut, IntoBuf};
use prost::{Message};

use crate::protobufs::kbupd::*;

pub struct PeerCodec;

impl tokio_codec::Decoder for PeerCodec {
    type Item  = PeerConnectionMessage;
    type Error = tokio::io::Error;
    fn decode(&mut self, buffer: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buffer.len() < 4 {
            return Ok(None);
        }

        let frame_length    = buffer[..].into_buf().get_u32_be() as usize;
        let frame_remaining = frame_length.saturating_sub(buffer.len() - 4);
        if frame_remaining != 0 {
            buffer.reserve(frame_remaining + 4);
            return Ok(None);
        }

        buffer.advance(4);
        let data    = buffer.split_to(frame_length);
        let message = PeerConnectionMessage::decode(&data)?;

        Ok(Some(message))
    }
}

impl tokio_codec::Encoder for PeerCodec {
    type Item  = Arc<PeerConnectionMessage>;
    type Error = tokio::io::Error;
    fn encode(&mut self, message: Arc<PeerConnectionMessage>, output: &mut BytesMut) -> Result<(), Self::Error> {
        let frame_len = match message.encoded_len() {
            frame_len if frame_len > u32::max_value() as usize - 4 => {
                return Err(tokio::io::Error::new(tokio::io::ErrorKind::InvalidInput, "peer message size limit"));
            }
            frame_len => frame_len as u32,
        };
        output.reserve(4 + frame_len as usize);
        output.put_u32_be(frame_len);
        message.encode(output)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::sync::{Arc};

    use bytes::{BytesMut};
    use tokio_codec::{Decoder, Encoder};

    use super::*;

    #[test]
    fn test_decode() {
        let mut buf = BytesMut::new();

        assert!(PeerCodec.decode(&mut buf).unwrap().is_none());

        buf.put_u32_be(0);
        buf.put_u32_be(0);
        assert_eq!(PeerCodec.decode(&mut buf).unwrap(), Some(Default::default()));
        assert_eq!(PeerCodec.decode(&mut buf).unwrap(), Some(Default::default()));

        let message = PeerConnectionMessage {
            inner: Some(peer_connection_message::Inner::Hello(Default::default())),
        };

        let encoded_len = (message.encoded_len() as u32).to_be_bytes();
        for byte in &encoded_len {
            buf.put_u8(*byte);
            assert!(PeerCodec.decode(&mut buf).unwrap().is_none());
        }

        let () = message.encode(&mut buf).unwrap();
        let last_byte_1 = buf[buf.len() - 2];
        let last_byte_2 = buf[buf.len() - 1];
        buf.truncate(buf.len() - 2);
        assert!(PeerCodec.decode(&mut buf).unwrap().is_none());

        buf.put_u8(last_byte_1);
        assert!(PeerCodec.decode(&mut buf).unwrap().is_none());

        buf.put_u8(last_byte_2);
        buf.put_u32_be(0);
        assert_eq!(PeerCodec.decode(&mut buf).unwrap(), Some(message));
        assert_eq!(PeerCodec.decode(&mut buf).unwrap(), Some(Default::default()));
    }

    #[test]
    fn test_encode() {
        let mut output = BytesMut::new();

        let () = PeerCodec.encode(Default::default(), &mut output).unwrap();
        assert_eq!(output[..], [0, 0, 0, 0]);

        let () = PeerCodec.encode(Default::default(), &mut output).unwrap();
        assert_eq!(&output[..], [0, 0, 0, 0, 0, 0, 0, 0]);

        output.clear();

        let message = PeerConnectionMessage {
            inner: Some(peer_connection_message::Inner::Hello(Default::default())),
        };

        let () = PeerCodec.encode(Arc::new(message), &mut output).unwrap();
        assert_eq!(output[..4], 4u32.to_be_bytes());
        assert_eq!(output.len(), 8);
    }
}
