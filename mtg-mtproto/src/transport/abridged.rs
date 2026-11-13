// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::{Error, Tagged, Transport, UnpackedOffset};
use crate::DequeBuffer;

/// The lightest MTProto transport protocol available.
///
/// This is an implementation of the [abridged transport].
///
/// * Overhead: very small.
/// * Minimum envelope length: 1 byte.
/// * Maximum envelope length: 4 bytes.
///
/// It serializes the input payload as follows, if the length is small enough:
///
/// ```text
/// +-+----...----+
/// |L|  payload  |
/// +-+----...----+
///  ^ 1 byte
/// ```
///
/// Otherwise:
///
/// ```text
/// +----+----...----+
/// | len|  payload  |
/// +----+----...----+
///  ^^^^ 4 bytes
/// ```
///
/// [abridged transport]: https://core.telegram.org/mtproto/mtproto-transports#abridged
pub struct Abridged {
    init: bool,
}

#[allow(clippy::new_without_default)]
impl Abridged {
    pub fn new() -> Self {
        Self { init: false }
    }
}

impl Transport for Abridged {
    fn pack(&mut self, buffer: &mut DequeBuffer<u8>) {
        let len = buffer.len();
        assert_eq!(len % 4, 0);

        let len = len / 4;
        if len < 127 {
            buffer.extend_front(&[len as u8]);
        } else {
            buffer.extend_front(&(0x7f | ((len as u32) << 8)).to_le_bytes());
        }

        if !self.init {
            buffer.extend_front(&[0xef]);
            self.init = true;
        }
    }

    fn unpack(&mut self, buffer: &mut [u8]) -> Result<UnpackedOffset, Error> {
        if buffer.is_empty() {
            return Err(Error::MissingBytes);
        }

        let header_len: usize;
        let len = buffer[0];
        let len = if len < 127 {
            header_len = 1;
            len as usize
        } else {
            if buffer.len() < 4 {
                return Err(Error::MissingBytes);
            }

            header_len = 4;
            // 24 bits, unsigned: a signed shift made lengths with the top bit set negative
            (u32::from_le_bytes(buffer[0..4].try_into().unwrap()) >> 8) as usize
        };

        let len = len * 4;
        if buffer.len() < header_len + len {
            return Err(Error::MissingBytes);
        }

        // A 4-byte payload is a transport error code, never a message (the shortest is 20 bytes).
        // Longer payloads start with an auth_key_id, whose first int may well be negative.
        if len == 4 {
            let data = i32::from_le_bytes(buffer[header_len..header_len + 4].try_into().unwrap());
            return Err(Error::BadStatus {
                status: data.unsigned_abs(),
            });
        }

        Ok(UnpackedOffset {
            data_range: header_len..header_len + len,
            next_offset: header_len + len,
        })
    }
}

impl Tagged for Abridged {
    fn init_tag(&mut self) -> [u8; 4] {
        self.init = true;
        [0xef, 0xef, 0xef, 0xef]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns a new abridged transport, and `n` bytes of input data for it.
    fn setup_pack(n: usize) -> (Abridged, DequeBuffer<u8>) {
        let mut buffer = DequeBuffer::with_capacity(n, 0);
        for i in 0..n {
            buffer.push((i & 0xff) as u8);
        }
        (Abridged::new(), buffer)
    }

    #[test]
    fn pack_empty() {
        let (mut transport, mut buffer) = setup_pack(0);
        transport.pack(&mut buffer);
        assert_eq!(&buffer[..], &[0xef, 0]);
    }

    #[test]
    #[should_panic]
    fn pack_non_padded() {
        let (mut transport, mut buffer) = setup_pack(7);
        transport.pack(&mut buffer);
    }

    #[test]
    fn pack_normal() {
        let (mut transport, mut buffer) = setup_pack(128);
        let orig = buffer.clone();
        transport.pack(&mut buffer);
        assert_eq!(&buffer[..2], &[0xef, 32]);
        assert_eq!(&buffer[2..], &orig[..]);
    }

    #[test]
    fn pack_large() {
        let (mut transport, mut buffer) = setup_pack(1024);
        let orig = buffer.clone();
        transport.pack(&mut buffer);
        assert_eq!(&buffer[..5], &[0xef, 127, 0, 1, 0]);
        assert_eq!(&buffer[5..], &orig[..]);
    }

    #[test]
    fn unpack_small() {
        let mut transport = Abridged::new();
        let mut buffer = DequeBuffer::with_capacity(1, 0);
        buffer.extend_back(&[1]);
        assert_eq!(transport.unpack(&mut buffer[..]), Err(Error::MissingBytes));
    }

    #[test]
    fn unpack_normal() {
        let (mut transport, mut buffer) = setup_pack(128);
        let orig = buffer.clone();
        transport.pack(&mut buffer);
        let n = 1; // init byte
        let offset = transport.unpack(&mut buffer[n..][..]).unwrap();
        assert_eq!(&buffer[n..][offset.data_range], &orig[..]);
    }

    #[test]
    fn unpack_two_at_once() {
        let (mut transport, mut buffer) = setup_pack(128);
        let orig = buffer.clone();

        let mut two_buffer = DequeBuffer::with_capacity(0, 0);
        transport.pack(&mut buffer);
        two_buffer.extend_back(&buffer[1..]); // init byte
        let single_size = two_buffer.len();

        buffer = orig.clone();
        transport.pack(&mut buffer);
        two_buffer.extend_back(&buffer[..]);

        let offset = transport.unpack(&mut two_buffer[..]).unwrap();
        assert_eq!(&buffer[offset.data_range], &orig[..]);
        assert_eq!(offset.next_offset, single_size);

        let n = offset.next_offset;
        let offset = transport.unpack(&mut two_buffer[n..]).unwrap();
        assert_eq!(&buffer[offset.data_range], &orig[..]);
    }

    #[test]
    fn unpack_large() {
        let (mut transport, mut buffer) = setup_pack(1024);
        let orig = buffer.clone();
        transport.pack(&mut buffer);
        let n = 1; // init byte
        let offset = transport.unpack(&mut buffer[n..]).unwrap();
        assert_eq!(&buffer[n..][offset.data_range], &orig[..]);
    }

    #[test]
    fn unpack_bad_status() {
        let mut transport = Abridged::new();
        let mut buffer = DequeBuffer::with_capacity(5, 0);
        buffer.push(1u8);
        buffer.extend_back(&(-404_i32).to_le_bytes());

        assert_eq!(
            transport.unpack(&mut buffer[..]),
            Err(Error::BadStatus { status: 404 })
        );
    }

    #[test]
    fn a_payload_starting_with_a_negative_int_is_not_a_status() {
        // 8 bytes: the first 4 are an auth_key_id fragment with the top bit set
        let mut buffer = vec![2, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0];
        let offset = Abridged::new().unpack(&mut buffer).unwrap();
        assert_eq!(offset.data_range, 1..9);
    }

    #[test]
    fn a_four_byte_payload_is_a_transport_error() {
        // https://core.telegram.org/mtproto/mtproto-transports#transport-errors
        let mut buffer = vec![1];
        buffer.extend((-404i32).to_le_bytes());
        assert_eq!(
            Abridged::new().unpack(&mut buffer),
            Err(Error::BadStatus { status: 404 })
        );
    }

    #[test]
    fn a_long_header_and_missing_bytes() {
        assert_eq!(Abridged::new().unpack(&mut []), Err(Error::MissingBytes));
        assert_eq!(
            Abridged::new().unpack(&mut [0x7f, 1]),
            Err(Error::MissingBytes)
        );
        assert_eq!(
            Abridged::new().unpack(&mut [3, 0, 0]),
            Err(Error::MissingBytes)
        );
    }
}
