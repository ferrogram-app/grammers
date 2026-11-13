// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use mtg_crypto::ObfuscatedCipher;

use super::{Error, Tagged, Transport, UnpackedOffset};
use crate::DequeBuffer;

/// Obfuscation layer for other MTProto transport protocols.
///
/// This was made by Telegram to avoid ISP blocks.
/// This is needed to connect to the Telegram servers
/// using websockets or when conecting to MTProto proxies.
///
/// This wrapper encrypts the data using AES-256-CTR with a randomly
/// generated key that is then sent at the beginning of the connection.
///
/// Obfuscated transport can only be used with "tagged" transports, which
/// provide a way to get the obfuscated tag that is used in the encryption.
///
/// See [Transport Obfuscation](https://core.telegram.org/mtproto/mtproto-transports#transport-obfuscation)
/// for more information.
pub struct Obfuscated<T: Transport + Tagged> {
    inner: T,
    head: Option<[u8; 64]>,
    decrypt_tail: usize,
    cipher: ObfuscatedCipher,
}

const FORBIDDEN_FIRST_INTS: [[u8; 4]; 7] = [
    *b"HEAD",                 // HTTP HEAD
    *b"POST",                 // HTTP POST
    *b"GET ",                 // HTTP GET
    *b"OPTI",                 // HTTP OPTIONS
    [0x16, 0x03, 0x01, 0x02], // TLS handshake
    [0xdd, 0xdd, 0xdd, 0xdd], // Padded Intermediate
    [0xee, 0xee, 0xee, 0xee], // Intermediate
];

impl<T: Transport + Tagged> Obfuscated<T> {
    fn generate_keys(inner: &mut T) -> ([u8; 64], ObfuscatedCipher) {
        let mut init = [0; 64];

        while init[4..8] == [0; 4] // Full
            || init[0] == 0xef // Abridged
            || FORBIDDEN_FIRST_INTS.iter().any(|start| start == &init[..4])
        {
            getrandom::fill(&mut init).unwrap();
        }

        init[56..60].copy_from_slice(&inner.init_tag());

        let mut cipher = ObfuscatedCipher::new(&init);

        let mut encrypted_init = init.to_vec();
        cipher.encrypt(&mut encrypted_init);
        init[56..64].copy_from_slice(&encrypted_init[56..64]);

        (init, cipher)
    }

    pub fn new(mut inner: T) -> Self {
        let (init, cipher) = Self::generate_keys(&mut inner);

        Self {
            inner,
            head: Some(init),
            decrypt_tail: 0,
            cipher,
        }
    }
}

impl<T: Transport + Tagged> Transport for Obfuscated<T> {
    fn pack(&mut self, buffer: &mut DequeBuffer<u8>) {
        self.inner.pack(buffer);
        self.cipher.encrypt(buffer.as_mut());
        if let Some(head) = self.head.take() {
            buffer.extend_front(&head);
        }
    }

    fn unpack(&mut self, buffer: &mut [u8]) -> Result<UnpackedOffset, Error> {
        if buffer.len() < self.decrypt_tail {
            panic!("buffer is smaller than what was decrypted");
        }

        self.cipher.decrypt(&mut buffer[self.decrypt_tail..]);
        self.decrypt_tail = buffer.len();

        match self.inner.unpack(buffer) {
            Ok(offset) => {
                self.decrypt_tail -= offset.next_offset;
                Ok(offset)
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Intermediate;

    /// Client plus the server-side cipher derived from the head the client sent.
    fn pair() -> (Obfuscated<Intermediate>, ObfuscatedCipher, [u8; 64]) {
        let mut client = Obfuscated::new(Intermediate::new());
        let mut buffer = DequeBuffer::with_capacity(4, 0);
        buffer.extend_back(&[1, 2, 3, 4]);
        client.pack(&mut buffer);
        let head: [u8; 64] = buffer[..64].try_into().unwrap();
        let rev: [u8; 64] = std::array::from_fn(|i| head[63 - i]);
        let mut server = ObfuscatedCipher::new(&rev);
        // the client's stream also covered the 64 head bytes
        let mut all = buffer[..].to_vec();
        server.decrypt(&mut all);
        let body = all[64..].to_vec();
        // first frame: intermediate length prefix + our 4 bytes (the tag went into the head)
        assert_eq!(body, [4, 0, 0, 0, 1, 2, 3, 4]);
        (client, server, head)
    }

    #[test]
    fn the_head_is_sent_once_and_never_starts_with_a_forbidden_value() {
        let (mut client, _, head) = pair();
        assert!(!FORBIDDEN_FIRST_INTS.iter().any(|f| f == &head[..4]));
        assert_ne!(head[4..8], [0; 4]);
        assert_ne!(head[0], 0xef);
        let mut buffer = DequeBuffer::with_capacity(4, 0);
        buffer.extend_back(&[5, 6, 7, 8]);
        client.pack(&mut buffer);
        assert_eq!(buffer.len(), 8, "no second head");
    }

    #[test]
    fn unpack_decrypts_incrementally_and_keeps_the_tail() {
        let (mut client, mut server, _) = pair();
        let mut wire = vec![8, 0, 0, 0, 9, 9, 9, 9, 9, 9, 9, 9, 8, 0];
        server.encrypt(&mut wire);

        let mut buf = wire.clone();
        let off = client.unpack(&mut buf).unwrap();
        assert_eq!(&buf[off.data_range.clone()], &[9; 8]);
        assert_eq!(off.next_offset, 12);
        // the caller drops the consumed frame; two decrypted bytes of the next one remain
        let mut rest = wire[12..].to_vec();
        assert_eq!(client.decrypt_tail, 2);
        let err = client.unpack(&mut rest).unwrap_err();
        assert_eq!(err, Error::MissingBytes);
    }

    #[test]
    #[should_panic(expected = "smaller than what was decrypted")]
    fn unpack_panics_if_the_caller_shrinks_the_buffer() {
        let (mut client, _, _) = pair();
        client.decrypt_tail = 10;
        let _ = client.unpack(&mut [0u8; 4]);
    }
}
