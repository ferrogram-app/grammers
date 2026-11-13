// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::mem;

/// How many server message ids are remembered for duplicate detection.
const SEEN_MSG_IDS: usize = 512;

/// How many `new_session_created` ids are remembered.
const SEEN_SESSIONS: usize = 16;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use mtg_crypto::{AuthKey, decrypt_data_v2, encrypt_data_v2, get_padding_data_v2};
use mtg_tl_types::{self as tl, Cursor, Deserializable, Identifiable, Serializable};
use tracing::info;

use super::{
    Deserialization, DeserializationFailure, DeserializeError, Mtp, RpcResult, RpcResultError,
};
use crate::utils::StackBuffer;
use crate::{DequeBuffer, MsgId, manual_tl};

/// How many future salts to fetch or have stored at a given time.
///
/// Not an `usize` because the API expects a signed `i32`. Should be more than two because the
/// code expects to fetch more salts when going from two to one.
const NUM_FUTURE_SALTS: i32 = 64;

/// Containers and gzip wrappers may nest this deep (a container holding a gzip_packed message).
/// Telegram never sends more; a deeper chain is hostile and would only eat the stack.
const MAX_NESTING: u8 = 2;

/// `msgs_ack`, `msgs_state_req` and `msg_resend_req` carry at most this many ids.
/// https://core.telegram.org/mtproto/service_messages#acknowledgment-of-receipt
const MAX_IDS_PER_ACK: usize = 8192;

/// How long to wait before asking again for an answer that did not arrive.
const RESEND_ASK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// When switching to a different salt, how many seconds must have passed since its `valid_since`.
///
/// Used to prevent small fluctuations in the system clock.
const SALT_USE_DELAY: i32 = 60;

static UPDATE_IDS: [u32; 9] = [
    tl::types::UpdateShortMessage::CONSTRUCTOR_ID,
    tl::types::UpdateShortChatMessage::CONSTRUCTOR_ID,
    tl::types::UpdateShort::CONSTRUCTOR_ID,
    tl::types::UpdatesCombined::CONSTRUCTOR_ID,
    tl::types::Updates::CONSTRUCTOR_ID,
    tl::types::UpdateShortSentMessage::CONSTRUCTOR_ID,
    tl::types::messages::AffectedMessages::CONSTRUCTOR_ID,
    tl::types::messages::InvitedUsers::CONSTRUCTOR_ID,
    tl::types::messages::ChatInviteJoinResultOk::CONSTRUCTOR_ID,
];

/// A builder to configure [`Mtp`] instances.
///
/// Use the [`Encrypted::build`] method to create builder instances.
pub struct Builder {
    time_offset: i32,
    first_salt: i64,
    compression_threshold: Option<usize>,
}

/// An implementation of the [Mobile Transport Protocol] for ciphertext
/// (encrypted) messages.
///
/// [Mobile Transport Protocol]: https://core.telegram.org/mtproto
pub struct Encrypted {
    /// The Authorization Key to use to encrypt payload.
    auth_key: AuthKey,

    /// The time offset from the server's time, in seconds.
    time_offset: i32,

    /// Salts that may be used when encrypting payload, sorted by valid date descending (so the last one is the one
    /// that can be used now).
    salts: Vec<tl::types::FutureSalt>,

    /// The `now` received from future salts along with the instant when it occured.
    ///
    /// Used to accurately determine when salts become valid.
    start_salt_time: Option<(i32, Instant)>,

    /// Internal request for salts which should not be propagated.
    salt_request_msg_id: Option<MsgId>,

    /// The secure, random identifier for this instance.
    session_id: i64,

    /// The current message sequence number.
    sequence: i32,

    /// The ID of the last message.
    last_msg_id: i64,

    /// Identifiers that need to be acknowledged to the server.
    ///
    /// A [Content-related Message] is "a message requiring an explicit
    /// acknowledgment. These include all the user and many service messages,
    /// virtually all with the exception of containers and acknowledgments."
    ///
    /// [Content-related Message]: https://core.telegram.org/mtproto/description#content-related-message
    pending_ack: Vec<i64>,

    /// `unique_id`s of the latest `new_session_created` messages, so a resent one is ignored.
    seen_sessions: std::collections::VecDeque<i64>,

    /// The ids of the latest server messages, to drop a message the server sent twice.
    seen_msg_ids: std::collections::VecDeque<i64>,

    /// The last ping we sent and when, to measure its round trip on the pong.
    ping_sent: Option<(i64, Instant)>,

    /// Smoothed round trip to the server in milliseconds, once a pong has been measured.
    ping_ms: Option<i64>,

    /// The session id before the last `recreate_session`: answers still in flight use it.
    previous_session_id: Option<i64>,

    /// Answers the server announced (`msg_detailed_info`) but we have not received yet; a
    /// `msg_resend_req` for them goes out with the next packet.
    pending_resend: Vec<i64>,

    /// When each answer was last asked for, to ask at most once a minute.
    resend_asked: Vec<(i64, Instant)>,

    /// If present, the threshold in bytes at which a message will be
    /// considered large enough to attempt compressing it. Otherwise,
    /// outgoing messages will never be compressed.
    compression_threshold: Option<usize>,

    /// Temporary deserialization results.
    deserialization: Vec<Deserialization>,

    /// How many messages are there in the buffer.
    msg_count: usize,

    /// How many containers / gzip wrappers are being unpacked right now.
    nesting: u8,
}

/// Time since the Unix epoch; a clock set before it reads as zero (`bad_msg_notification` then
/// corrects the offset) instead of panicking.
fn since_epoch() -> std::time::Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

/// A random session id. It is not secret; a clock-based value beats aborting.
fn new_session_id() -> i64 {
    let mut buffer = [0u8; 8];
    if getrandom::fill(&mut buffer).is_err() {
        buffer = (since_epoch().as_nanos() as u64).to_le_bytes();
    }
    i64::from_le_bytes(buffer)
}

/// How much of a large request is compressed on a trial basis before the whole is.
const COMPRESSION_PROBE_LEN: usize = 8 * 1024;

/// Whether compressing `request` is worth the CPU time.
///
/// Uploads send hundreds of kilobytes of already compressed media, and compressing those at the
/// best level costs milliseconds per part only for the result to be thrown away. A request longer
/// than the probe is therefore judged by its first [`COMPRESSION_PROBE_LEN`] bytes.
///
/// shortcut: a request that starts incompressible and ends compressible is sent as is,
/// upgrade when such requests turn up.
fn looks_compressible(request: &[u8]) -> bool {
    request.len() <= COMPRESSION_PROBE_LEN
        || manual_tl::GzipPacked::shrinks_on_fast_level(&request[..COMPRESSION_PROBE_LEN])
}

impl Builder {
    /// Configures the time offset to Telegram servers.
    pub fn time_offset(mut self, offset: i32) -> Self {
        self.time_offset = offset;
        self
    }

    pub fn first_salt(mut self, first_salt: i64) -> Self {
        self.first_salt = first_salt;
        self
    }

    /// Configures the compression threshold for outgoing messages.
    pub fn compression_threshold(mut self, threshold: Option<usize>) -> Self {
        self.compression_threshold = threshold;
        self
    }

    /// Finishes the builder and returns the `MTProto` instance with all
    /// the configuration changes applied.
    pub fn finish(self, auth_key: [u8; 256]) -> Encrypted {
        Encrypted {
            auth_key: AuthKey::from_bytes(auth_key),
            time_offset: self.time_offset,
            salts: vec![tl::types::FutureSalt {
                valid_since: 0,
                valid_until: i32::MAX,
                salt: self.first_salt,
            }],
            start_salt_time: None,
            salt_request_msg_id: None,
            session_id: new_session_id(),
            sequence: 0,
            last_msg_id: 0,
            pending_ack: vec![],
            seen_sessions: std::collections::VecDeque::new(),
            seen_msg_ids: Default::default(),
            ping_sent: None,
            ping_ms: None,
            previous_session_id: None,
            pending_resend: Vec::new(),
            resend_asked: Vec::new(),
            compression_threshold: self.compression_threshold,
            deserialization: Vec::new(),
            msg_count: 0,
            nesting: 0,
        }
    }
}

impl Encrypted {
    /// Start building a new encrypted MTP.
    pub fn build() -> Builder {
        Builder {
            time_offset: 0,
            compression_threshold: crate::DEFAULT_COMPRESSION_THRESHOLD,
            first_salt: 0,
        }
    }

    /// The Authorization Key used for encryption and decryption.
    pub fn auth_key(&self) -> [u8; 256] {
        self.auth_key.to_bytes()
    }

    /// Correct our time offset based on a known valid message ID, as the official client does:
    /// the server stamped the message about half a round trip ago.
    fn correct_time_offset(&mut self, msg_id: i64) {
        let server_ms = ((msg_id as u64 as u128 * 1000) >> 32) as i64;
        let now_ms = since_epoch().as_millis() as i64;
        let half_ping = self.ping_ms.map_or(0, |ping| ping / 2);
        self.time_offset = ((server_ms - now_ms - half_ping) / 1000) as i32;
    }

    /// Folds a measured round trip into the smoothed ping, like the official client.
    fn add_ping_sample(&mut self, sample_ms: i64) {
        // The official client ignores samples of 10 s and more: they say nothing about the link.
        if sample_ms >= 10_000 {
            return;
        }
        self.ping_ms = Some(
            self.ping_ms
                .map_or(sample_ms, |ping| (ping + sample_ms) / 2),
        );
    }

    /// Starts a new session (new id, sequence from zero), as the official client does when the
    /// server rejects our sequence numbers. The server answers with `new_session_created`,
    /// which makes the sender resend what the new session has not seen.
    fn recreate_session(&mut self) {
        self.previous_session_id = Some(self.session_id);
        self.session_id = new_session_id();
        self.sequence = 0;
    }

    /// Whether a server message id is not older than 300 s nor more than 30 s ahead of our clock.
    fn msg_id_in_window(&self, msg_id: i64) -> bool {
        let now = since_epoch().as_secs() as i64 + self.time_offset as i64;
        let age = now - (msg_id >> 32);
        (-30..=300).contains(&age)
    }

    /// Generates a new unique message ID based on the current
    /// time (in ms) since epoch, applying a known time offset.
    fn get_new_msg_id(&mut self) -> i64 {
        let now = since_epoch();

        let seconds = (now.as_secs() as i32 + self.time_offset) as u64;
        let nanoseconds = now.subsec_nanos() as u64;
        let mut new_msg_id = ((seconds << 32) | (nanoseconds << 2)) as i64;

        if self.last_msg_id >= new_msg_id {
            new_msg_id = self.last_msg_id + 4;
        }

        self.last_msg_id = new_msg_id;
        new_msg_id
    }

    /// Generates the next sequence number depending on whether
    /// it should be for a content-related query or not.
    fn get_seq_no(&mut self, content_related: bool) -> i32 {
        if content_related {
            self.sequence += 2;
            self.sequence - 1
        } else {
            self.sequence
        }
    }

    fn try_serialize_msg(
        &mut self,
        buffer: &mut DequeBuffer<u8>,
        body: &[u8],
        content_related: bool,
    ) -> Option<MsgId> {
        // Make sure it's within bounds both in message count and buffer size.
        if self.msg_count == manual_tl::MessageContainer::MAXIMUM_LENGTH {
            return None;
        }
        let container_overhead = if self.msg_count == 0 {
            0
        } else {
            manual_tl::MessageContainer::SIZE_OVERHEAD
        };
        if buffer.len() + body.len() + manual_tl::Message::SIZE_OVERHEAD + container_overhead
            > manual_tl::MAX_ENCRYPTED_DATA_SIZE
        {
            return None;
        }

        // Within bounds; add it.
        let msg_id = self.get_new_msg_id();

        let sink = &mut |bytes: &[u8]| buffer.extend_back(bytes);
        msg_id.serialize(sink);
        self.get_seq_no(content_related).serialize(sink);
        (body.len() as i32).serialize(sink);
        buffer.extend_back(body);

        self.msg_count += 1;
        Some(MsgId(msg_id))
    }

    fn get_current_salt(&self) -> i64 {
        self.salts.last().map(|s| s.salt).unwrap_or(0)
    }

    fn try_request_salts(&mut self, buffer: &mut DequeBuffer<u8>) {
        if self.salts.len() == 1
            && self.salt_request_msg_id.is_none()
            && self.get_current_salt() != 0
        {
            // If salts are requested in a container leading to bad_msg,
            // the bad_msg_id will refer to the container, not the salts request.
            //
            // We don't keep track of containers and content-related messages they contain for simplicity.
            // This would break, because we couldn't identify the response.
            //
            // So salts are only requested once we have a valid salt to reduce the chances of this happening.
            info!("only one future salt remaining; asking for more salts");
            let body = tl::functions::GetFutureSalts {
                num: NUM_FUTURE_SALTS,
            }
            .to_bytes();
            self.salt_request_msg_id = self.try_serialize_msg(buffer, &body, true);
        }
    }

    /// `finalize`, but without encryption.
    ///
    /// The buffer is *not* cleared, but is instead returned.
    fn finalize_plain(&mut self, buffer: &mut DequeBuffer<u8>) {
        if self.msg_count == 0 {
            return;
        }

        if self.msg_count != 1 {
            // Prepend a container, setting its message ID and sequence number.
            // + 8 because it has to include the constructor ID and length (4 bytes each).
            let len = (buffer.len() + 8) as i32;
            let mut header = StackBuffer::<MESSAGE_CONTAINER_HEADER_LEN>::new();

            // Manually `serialize_msg` because the container body was already written.
            let sink = &mut |bytes: &[u8]| header.extend_from_slice(bytes);
            self.get_new_msg_id().serialize(sink);
            self.get_seq_no(false).serialize(sink);

            len.serialize(sink);

            manual_tl::MessageContainer::CONSTRUCTOR_ID.serialize(sink);
            (self.msg_count as i32).serialize(sink);
            buffer.extend_front(&header.into_inner());
        }

        {
            // Prepend the message header
            let mut header = StackBuffer::<PLAIN_PACKET_HEADER_LEN>::new();
            let sink = &mut |bytes: &[u8]| header.extend_from_slice(bytes);
            self.get_current_salt().serialize(sink); // 8 bytes

            self.session_id.serialize(sink); // 8 bytes
            buffer.extend_front(&header.into_inner());
        }

        self.msg_count = 0;
    }
}

mod handlers;
#[cfg(test)]
mod tests;

/// The maximum header length used by any available transport.
///
/// The largest transport is `Full`, needing 4 bytes for each of `len` and `seq`.
///
/// The `crc32` is appended at the end, so it is not part of the leading header.
pub const MAX_TRANSPORT_HEADER_LEN: usize = 4 + 4;

/// Amount of bytes used by the [Encrypted Message](https://core.telegram.org/mtproto/description#encrypted-message).
///
/// This accounts for both the `auth_key_id` (8 bytes) and `msg_key` (16 bytes).
pub const ENCRYPTED_PACKET_HEADER_LEN: usize = 8 + 16;

/// Amount of bytes used by the [`encrypted_data`](https://core.telegram.org/mtproto/description#encrypted-message-encrypted-data).
///
/// This accounts for both `salt` (8 bytes) and `session_id` (8 bytes).
///
/// The `message_id`, `seq_no` and `message_data_length` are not included
/// because those will have been appended at the current buffer position.
pub const PLAIN_PACKET_HEADER_LEN: usize = 8 + 8;

/// Amount of bytes used by a `msg_container`.
///
/// The message header for the container occupies the size of the message header
/// (`msg_id`, `seq_no` and `size`) followed by the container header (`constructor`, `len`).
pub const MESSAGE_CONTAINER_HEADER_LEN: usize = (8 + 4 + 4) + (4 + 4);

impl Mtp for Encrypted {
    /// Pushes a request into the internal buffer.
    ///
    /// Multiple requests will be buffered and sent as a single container to reduce roundtrips.
    /// If the buffer is full (request does not fit in the container), returns `None`.
    ///
    /// [MTProto 2.0 guidelines]: https://core.telegram.org/mtproto/description.
    fn push(&mut self, buffer: &mut DequeBuffer<u8>, request: &[u8]) -> Option<MsgId> {
        // TODO rather than taking in bytes, take requests, serialize them in place, and if too large drop the last part of the buffer

        // Check to see if the next salt can be used already. If it can, drop the current one and,
        // if the next salt is the last one, fetch more.
        if let Some((start_secs, start_instant)) = self.start_salt_time
            && self.salts.len() > 1
        {
            let salt = &self.salts[self.salts.len() - 2];
            let now = start_secs + start_instant.elapsed().as_secs() as i32;
            if now >= salt.valid_since + SALT_USE_DELAY {
                self.salts.pop();
            }
        }

        self.try_request_salts(buffer);
        if self.salt_request_msg_id.is_some() {
            // Don't add anything else to the container while we still need new salts.
            return None;
        }

        // If we need to acknowledge messages, this notification goes in with the rest of requests
        // so that we can also include it. It has priority over user requests because these should
        // be sent out as soon as possible.
        if !self.pending_ack.is_empty() {
            // TODO avoid to_bytes here, serialize it in-place
            let n = self.pending_ack.len().min(MAX_IDS_PER_ACK);
            let body = tl::enums::MsgsAck::Ack(tl::types::MsgsAck {
                msg_ids: self.pending_ack[..n].to_vec(),
            })
            .to_bytes();

            // This should take priority during the next packet. If it does not fit, the ids
            // stay pending instead of being forgotten.
            self.try_serialize_msg(buffer, &body, false)?;
            self.pending_ack.drain(..n);
            // Don't allow other requests through until ^ can be sent.
        }

        // Ask for the answers the server announced but we never got.
        if !self.pending_resend.is_empty() {
            let body = tl::enums::MsgResendReq::Req(tl::types::MsgResendReq {
                msg_ids: self.pending_resend.clone(),
            })
            .to_bytes();
            self.try_serialize_msg(buffer, &body, true)?;
            self.pending_resend.clear();
        }

        // Requests that are too large would cause Telegram to close the
        // connection but are so uncommon it's not worth returning `Err`.
        // Without this, failing to serialize would repeatedly return `None`,
        // leading to an infinite loop as well.
        assert!(request.len() <= manual_tl::Message::MAX_BODY_SIZE);

        // Serialized requests will always be correctly padded.
        assert!(request.len().is_multiple_of(4));

        // Payload provided by the user is always considered to be
        // content-related, which means we can apply compression.
        let mut body = request;
        let compressed;
        if let Some(threshold) = self.compression_threshold
            && request.len() >= threshold
            && looks_compressible(request)
        {
            compressed = manual_tl::GzipPacked::new(request).to_bytes();
            if compressed.len() < request.len() {
                body = &compressed;
            }
        }

        let msg_id = self.try_serialize_msg(buffer, body, true)?;
        if request.starts_with(&tl::functions::Ping::CONSTRUCTOR_ID.to_le_bytes())
            || request
                .starts_with(&tl::functions::PingDelayDisconnect::CONSTRUCTOR_ID.to_le_bytes())
        {
            self.ping_sent = Some((msg_id.0, Instant::now()));
        }
        Some(msg_id)
    }

    fn finalize(&mut self, buffer: &mut DequeBuffer<u8>) -> Option<MsgId> {
        self.finalize_plain(buffer);
        if buffer.is_empty() {
            None
        } else {
            let (padding, padding_len) = get_padding_data_v2(buffer.len());
            buffer.extend_back(&padding[..padding_len]);

            let msg_key = encrypt_data_v2(&mut buffer[..], &self.auth_key);

            buffer.extend_front(&msg_key);
            buffer.extend_front(&self.auth_key.key_id());

            Some(MsgId(self.last_msg_id))
        }
    }

    /// Processes an encrypted response from the server.
    fn deserialize(
        &mut self,
        payload: &mut [u8],
    ) -> Result<Vec<Deserialization>, DeserializeError> {
        crate::utils::check_message_buffer(payload)?;

        let plaintext = decrypt_data_v2(payload, &self.auth_key)?;

        let plaintext_len = plaintext.len();
        let mut buffer = Cursor::from_slice(plaintext);

        let _salt = i64::deserialize(&mut buffer)?;
        let session_id = i64::deserialize(&mut buffer)?;
        if session_id != self.session_id && Some(session_id) != self.previous_session_id {
            return Err(DeserializeError::BadSessionId {
                got: session_id,
                expected: self.session_id,
            });
        }

        let message = manual_tl::Message::deserialize(&mut buffer)?;
        let padding = plaintext_len - buffer.pos();
        if !(12..=1024).contains(&padding) {
            return Err(DeserializeError::BadPadding { got: padding });
        }
        self.process_message(message)?;

        // For simplicity, and to avoid passing too much stuff around (RPC results, updates),
        // the processing result is stored in self. After processing is done, that temporary
        // state is cleaned and returned with `mem::take`.
        Ok(mem::take(&mut self.deserialization))
    }
}
