// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[allow(deprecated)] // see https://github.com/RustCrypto/block-ciphers/issues/509
use aes::cipher::{KeyIvInit, StreamCipher};

/// This implements the AES-256-CTR cipher used by Telegram to encrypt data
/// when using the obfuscated transport.
///
/// It is not intended to be used directly.
pub struct ObfuscatedCipher {
    rx: ctr::Ctr128BE<aes::Aes256>,
    tx: ctr::Ctr128BE<aes::Aes256>,
}

/// Key (bytes 8..40) and IV (bytes 40..56) of the 64-byte init payload.
fn key_iv(init: &[u8; 64]) -> ([u8; 32], [u8; 16]) {
    (
        std::array::from_fn(|i| init[8 + i]),
        std::array::from_fn(|i| init[40 + i]),
    )
}

impl ObfuscatedCipher {
    /// Creates the cipher pair from the 64-byte init payload: the sending side uses the payload,
    /// the receiving side its byte-reversed copy.
    #[must_use]
    pub fn new(init: &[u8; 64]) -> Self {
        let init_rev: [u8; 64] = std::array::from_fn(|i| init[63 - i]);
        let (rx_key, rx_iv) = key_iv(&init_rev);
        let (tx_key, tx_iv) = key_iv(init);
        #[allow(deprecated)] // see https://github.com/RustCrypto/block-ciphers/issues/509
        Self {
            rx: ctr::Ctr128BE::<aes::Aes256>::new(&rx_key.into(), &rx_iv.into()),
            tx: ctr::Ctr128BE::<aes::Aes256>::new(&tx_key.into(), &tx_iv.into()),
        }
    }

    /// Encrypts `buffer` in place with the sending stream.
    pub fn encrypt(&mut self, buffer: &mut [u8]) {
        self.tx.apply_keystream(buffer);
    }

    /// Decrypts `buffer` in place with the receiving stream.
    pub fn decrypt(&mut self, buffer: &mut [u8]) {
        self.rx.apply_keystream(buffer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() -> [u8; 64] {
        std::array::from_fn(|i| i as u8 ^ 0x5a)
    }

    #[test]
    fn peer_with_reversed_init_decrypts_what_we_encrypt() {
        let init = init();
        let reversed: [u8; 64] = std::array::from_fn(|i| init[63 - i]);
        let mut ours = ObfuscatedCipher::new(&init);
        let mut theirs = ObfuscatedCipher::new(&reversed);

        // the counter continues across calls
        for msg in [&b"hello"[..], &[0u8; 40][..], b"x"] {
            let mut buf = msg.to_vec();
            ours.encrypt(&mut buf);
            assert_ne!(buf, msg);
            theirs.decrypt(&mut buf);
            assert_eq!(buf, msg);

            let mut buf = msg.to_vec();
            theirs.encrypt(&mut buf);
            ours.decrypt(&mut buf);
            assert_eq!(buf, msg);
        }
    }

    #[test]
    fn keystream_is_aes_ctr_of_key_and_iv_from_the_payload() {
        // independent construction: key = init[8..40], iv = init[40..56]
        let init = init();
        let mut expected = vec![0u8; 33];
        #[allow(deprecated)]
        let mut ctr = ctr::Ctr128BE::<aes::Aes256>::new(
            init[8..40].try_into().unwrap(),
            init[40..56].try_into().unwrap(),
        );
        ctr.apply_keystream(&mut expected);

        let mut got = vec![0u8; 33];
        ObfuscatedCipher::new(&init).encrypt(&mut got);
        assert_eq!(got, expected);
    }
}
