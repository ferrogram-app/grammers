// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::fmt;

use mtg_tl_types as tl;
use num_bigint::BigUint;

/// The error type for Authorization Key generation process.
#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// The server's nonce did not match ours.
    InvalidNonce {
        /// The unexpected nonce that we got.
        got: [u8; 16],

        /// The expected nonce.
        expected: [u8; 16],
    },

    /// The server's PQ number was not of the right size.
    InvalidPqSize {
        /// The unexpected size that we got.
        size: usize,
    },

    /// None of the server fingerprints are known to us.
    UnknownFingerprints {
        /// The list of fingerprint that we got.
        fingerprints: Vec<i64>,
    },

    /// The server failed to send the Diffie-Hellman parameters.
    DhParamsFail,

    /// The server's nonce has changed during the key exchange.
    InvalidServerNonce {
        /// The unexpected nonce that we got.
        got: [u8; 16],

        /// The expected nonce.
        expected: [u8; 16],
    },

    /// The server's `encrypted_data` is not correctly padded.
    EncryptedResponseNotPadded {
        /// The non-padded length of the response.
        len: usize,
    },

    /// An error occured while trying to read the DH inner data.
    InvalidDhInnerData {
        /// The inner error that occured when reading the data.
        error: tl::deserialize::Error,
    },

    /// The server's parameter `g` is invalid.
    InvalidG(i32),

    /// The server's `dh_prime` is invalid.
    InvalidDhPrime,

    /// The server's `pq` could not be split into two primes.
    FactorizationFailed,

    /// The operating system could not provide random bytes.
    RandomUnavailable,

    /// The system clock is set before the Unix epoch.
    ClockBeforeEpoch,

    /// Some parameter (`g`, `g_a` or `g_b`) was out of range.
    GParameterOutOfRange {
        value: BigUint,
        low: BigUint,
        high: BigUint,
    },

    /// The server asked to retry the Diffie-Hellman exchange (`dh_gen_retry`).
    DhGenRetry,

    /// The server reported failure of the Diffie-Hellman exchange (`dh_gen_fail`).
    DhGenFail,

    /// The plaintext answer hash did not match.
    InvalidAnswerHash {
        /// The unexpected hash that we got.
        got: [u8; 20],

        /// The expected hash.
        expected: [u8; 20],
    },

    // The new nonce hash did not match.
    InvalidNewNonceHash {
        /// The unexpected nonce that we got.
        got: [u8; 16],

        /// The expected nonce.
        expected: [u8; 16],
    },
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNonce { got, expected } => {
                write!(f, "invalid nonce: got {got:?}, expected {expected:?}")
            }
            Self::InvalidPqSize { size } => write!(f, "invalid pq size {size}"),
            Self::UnknownFingerprints { fingerprints } => {
                write!(f, "all server fingerprints are unknown: {fingerprints:?}")
            }
            Self::DhParamsFail => write!(f, "the generation of DH parameters by the server failed"),
            Self::InvalidServerNonce { got, expected } => write!(
                f,
                "invalid server nonce: got {got:?}, expected {expected:?}"
            ),
            Self::EncryptedResponseNotPadded { len } => write!(
                f,
                "the encrypted server response was {len} bytes long, which is not correctly padded"
            ),
            Self::InvalidDhInnerData { error } => {
                write!(f, "could not deserialize DH inner data: {error}")
            }
            Self::InvalidG(g) => write!(f, "the parameter g was invalid: {g}"),
            Self::InvalidDhPrime => write!(f, "the parameter dh_prime was invalid"),
            Self::FactorizationFailed => write!(f, "could not factorize the server's pq"),
            Self::RandomUnavailable => write!(f, "secure random bytes are unavailable"),
            Self::ClockBeforeEpoch => write!(f, "the system clock is before the Unix epoch"),
            Self::GParameterOutOfRange { low, high, value } => write!(
                f,
                "the parameter g = {value} was not in the range {low}..{high}"
            ),
            Self::DhGenRetry => write!(f, "the generation of DH parameters should be retried"),
            Self::DhGenFail => write!(f, "the generation of DH parameters failed"),
            Self::InvalidAnswerHash { got, expected } => {
                write!(f, "invalid answer hash: got {got:?}, expected {expected:?}")
            }
            Self::InvalidNewNonceHash { got, expected } => write!(
                f,
                "invalid new nonce hash: got {got:?}, expected {expected:?}"
            ),
        }
    }
}
