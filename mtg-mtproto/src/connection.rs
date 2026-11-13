// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Sans-IO state that a connection needs to hold.

use std::io;

use mtg_tl_types as tl;
use tracing::{debug, trace};

use crate::DequeBuffer;
use crate::authentication::Finished;
use crate::mtp::{self, Deserialization, DeserializeError, Encrypted, Mtp, Plain};
use crate::transport::Transport;
use crate::{MsgId, transport};

/// The maximum data that we're willing to send or receive at once.
///
/// By having a fixed-size buffer, we can avoid unnecessary allocations
/// and trivially prevent allocating more than this limit if we ever
/// received invalid data.
///
/// Telegram will close the connection with roughly a megabyte of data,
/// so to account for the transports' own overhead, we add a few extra
/// kilobytes to the maximum data size.
const MAXIMUM_DATA: usize = (1024 * 1024) + (8 * 1024);

/// How much leading space should be reserved in a buffer to avoid moving memory.
const LEADING_BUFFER_SPACE: usize = mtp::MAX_TRANSPORT_HEADER_LEN
    + mtp::ENCRYPTED_PACKET_HEADER_LEN
    + mtp::PLAIN_PACKET_HEADER_LEN
    + mtp::MESSAGE_CONTAINER_HEADER_LEN;

/// Glues together the transport and MTP state, and coordinates them to manage
/// the I/O buffers to send packed requests and iterate unpacked responses.
pub struct State<T: Transport, M: Mtp> {
    /// The transport framing the packets.
    pub transport: T,
    /// The MTProto state turning requests into packets and back.
    pub mtp: M,
    read_buffer: Vec<u8>,
    read_head: usize,
    read_tail: usize,
    write_buffer: DequeBuffer<u8>,
    write_head: usize,
    write_ready: bool,
}

impl<T: Transport, M: Mtp> State<T, M> {
    /// Creates a state with empty buffers.
    pub fn new(transport: T, mtp: M) -> Self {
        Self {
            transport,
            mtp,
            read_buffer: vec![0; MAXIMUM_DATA],
            read_head: 0,
            read_tail: 0,
            write_buffer: DequeBuffer::with_capacity(MAXIMUM_DATA, LEADING_BUFFER_SPACE),
            write_head: 0,
            write_ready: false,
        }
    }

    /// Returns `true` if requests can be buffered for sending.
    pub fn can_buffer_requests(&self) -> bool {
        !self.write_ready
    }

    /// Buffer a request's body to be sent.
    ///
    /// If the request can fit, its assigned message identifier is returned.
    ///
    /// Buffering will fail if not [`Self::can_buffer_requests`].
    pub fn buffer_request(&mut self, body: &[u8]) -> Option<MsgId> {
        if self.write_ready {
            return None;
        }

        // TODO make mtp itself use BytesMut to avoid copies
        if let Some(msg_id) = self.mtp.push(&mut self.write_buffer, body) {
            assert!(body.len() >= 4);
            let req_id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
            debug!(
                req_id = format_args!("{:x}", req_id),
                req_name = tl::name_for_id(req_id),
                ?msg_id,
                "serialized request",
            );
            Some(msg_id)
        } else {
            None
        }
    }

    /// Pack the outgoing buffer to make it ready for sending over the network.
    ///
    /// This should be done after having [`Self::buffer_request`] with as many
    /// requests as could fit, although a sendable buffer may be produced even
    /// if no user requests were buffered.
    ///
    /// Packing can only be done if [`Self::can_buffer_requests`].
    pub fn pack_outgoing_buffer(&mut self) -> Option<MsgId> {
        if self.write_ready {
            return None;
        }
        if let Some(container_msg_id) = self.mtp.finalize(&mut self.write_buffer) {
            self.transport.pack(&mut self.write_buffer);
            self.write_ready = true;
            Some(container_msg_id)
        } else {
            None
        }
    }

    /// Return a reference to the writable part of the read buffer for
    /// receiving, and the readable part of the write buffer for sending.
    ///
    /// If there is nothing to send, the write buffer will be zero sized.
    pub fn io_buffers(&mut self) -> (&mut [u8], &[u8]) {
        (
            &mut self.read_buffer[self.read_tail..],
            if self.write_ready {
                &self.write_buffer[self.write_head..]
            } else {
                &self.write_buffer[..0]
            },
        )
    }

    /// Mark `n` received bytes as being ready to be processed by
    /// [`Self::unpack_next`].
    ///
    /// Reading zero bytes from the network signals that the
    /// connection was reset. Error state is returned in that case.
    pub fn handle_net_read(&mut self, n: usize) -> Result<(), io::Error> {
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "read 0 bytes",
            ));
        }

        self.read_tail += n;
        trace!("read {} bytes from the network", n);
        trace!("trying to unpack buffer of {} bytes...", self.read_tail);
        Ok(())
    }

    /// Mark `n` sent bytes as having been flushed from the write buffer.
    ///
    /// Returns `true` if all data has been sent and
    /// the buffer is ready to be written into again.
    pub fn handle_net_write(&mut self, n: usize) -> bool {
        self.write_head += n;
        trace!(
            "written {} bytes to the network ({}/{})",
            n,
            self.write_head,
            self.write_buffer.len()
        );
        assert!(self.write_head <= self.write_buffer.len());
        if self.write_head != self.write_buffer.len() {
            return false;
        }

        self.write_buffer.clear();
        self.write_head = 0;
        self.write_ready = false;
        true
    }

    /// Unpack the next packet from the read buffer.
    ///
    /// If there is not enough data to unpack anything, `None` is returned.
    ///
    /// This should be called in a loop until `None` is returned.
    pub fn unpack_next(&mut self) -> Option<Result<Vec<Deserialization>, DeserializeError>> {
        if self.read_head != self.read_tail {
            match self
                .transport
                .unpack(&mut self.read_buffer[self.read_head..self.read_tail])
            {
                Ok(offset) => {
                    debug!("deserializing valid transport packet...");
                    let result = self
                        .mtp
                        .deserialize(&mut self.read_buffer[self.read_head..][offset.data_range]);

                    self.read_head += offset.next_offset;
                    return Some(result);
                }
                Err(transport::Error::MissingBytes) => {}
                Err(err) => return Some(Err(DeserializeError::Transport(err))),
            }
        }

        self.read_buffer
            .copy_within(self.read_head..self.read_tail, 0);

        self.read_tail -= self.read_head;
        self.read_head = 0;
        None
    }
}

impl<T: Transport> State<T, Plain> {
    /// Convert Plain state into Encrypted with the final authentication step.
    pub fn into_encrypted(self, auth: Finished) -> State<T, Encrypted> {
        State {
            transport: self.transport,
            mtp: mtp::Encrypted::build()
                .time_offset(auth.time_offset)
                .first_salt(auth.first_salt)
                .finish(auth.auth_key),
            read_buffer: self.read_buffer,
            read_head: self.read_head,
            read_tail: self.read_tail,
            write_buffer: self.write_buffer,
            write_head: self.write_head,
            write_ready: self.write_ready,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Intermediate;

    /// Writes requests verbatim; `accept` decides whether `push` has room.
    struct Fake {
        accept: bool,
        seen: Vec<Vec<u8>>,
    }

    impl Mtp for Fake {
        fn push(&mut self, buffer: &mut DequeBuffer<u8>, request: &[u8]) -> Option<MsgId> {
            if !self.accept {
                return None;
            }
            buffer.extend_back(request);
            Some(MsgId(7))
        }

        fn finalize(&mut self, buffer: &mut DequeBuffer<u8>) -> Option<MsgId> {
            (!buffer.is_empty()).then_some(MsgId(8))
        }

        fn deserialize(
            &mut self,
            payload: &mut [u8],
        ) -> Result<Vec<Deserialization>, DeserializeError> {
            self.seen.push(payload.to_vec());
            Ok(vec![Deserialization::Update(payload.to_vec())])
        }
    }

    fn state(accept: bool) -> State<Intermediate, Fake> {
        State::new(
            Intermediate::new(),
            Fake {
                accept,
                seen: vec![],
            },
        )
    }

    const REQ: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    #[test]
    fn a_request_is_buffered_packed_and_written_out() {
        let mut s = state(true);
        assert!(s.can_buffer_requests());
        assert_eq!(s.buffer_request(&REQ), Some(MsgId(7)));
        assert_eq!(s.pack_outgoing_buffer(), Some(MsgId(8)));
        assert!(!s.can_buffer_requests());
        // nothing more can be buffered or packed until the write completes
        assert_eq!(s.buffer_request(&REQ), None);
        assert_eq!(s.pack_outgoing_buffer(), None);

        let (_, out) = s.io_buffers();
        let total = out.len();
        assert_eq!(&out[..4], &[0xee; 4]); // intermediate tag
        assert!(total > REQ.len());
        assert!(!s.handle_net_write(3), "partial write");
        assert_eq!(s.io_buffers().1.len(), total - 3);
        assert!(s.handle_net_write(total - 3));
        assert!(s.can_buffer_requests());
        assert!(s.io_buffers().1.is_empty());
    }

    #[test]
    fn a_full_buffer_rejects_the_request_and_nothing_is_packed_when_empty() {
        let mut s = state(false);
        assert_eq!(s.buffer_request(&REQ), None);
        assert_eq!(s.pack_outgoing_buffer(), None);
        assert!(s.can_buffer_requests());
        assert!(s.io_buffers().1.is_empty());
    }

    #[test]
    fn zero_bytes_read_means_the_connection_was_reset() {
        let mut s = state(true);
        let e = s.handle_net_read(0).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::ConnectionReset);
    }

    fn feed(s: &mut State<Intermediate, Fake>, bytes: &[u8]) {
        let (read, _) = s.io_buffers();
        read[..bytes.len()].copy_from_slice(bytes);
        s.handle_net_read(bytes.len()).unwrap();
    }

    #[test]
    fn unpack_next_yields_whole_packets_and_keeps_partial_ones() {
        let mut s = state(true);
        // intermediate framing: tag only on the first packet we send, so frame by hand
        let mut wire = vec![8, 0, 0, 0];
        wire.extend(REQ);
        wire.extend([8, 0, 0, 0, 9, 9]); // second packet is cut short
        feed(&mut s, &wire);

        let first = s.unpack_next().unwrap().unwrap();
        assert!(matches!(&first[..], [Deserialization::Update(b)] if b == &REQ));
        assert!(s.unpack_next().is_none(), "second packet is incomplete");

        feed(&mut s, &[9; 6]);
        assert!(s.unpack_next().unwrap().is_ok());
        assert_eq!(s.mtp.seen.len(), 2);
        assert!(s.unpack_next().is_none());
    }

    #[test]
    fn a_transport_error_is_reported_not_swallowed() {
        let mut s = state(true);
        feed(&mut s, &[0xfc, 0xff, 0xff, 0xff, 0, 0, 0, 0]); // length -4: a transport status
        let r = s.unpack_next().unwrap();
        assert!(matches!(r, Err(DeserializeError::Transport(_))));
    }

    #[test]
    fn plain_state_converts_to_encrypted_keeping_its_buffers() {
        let s = State::new(Intermediate::new(), Plain::new());
        let enc = s.into_encrypted(Finished {
            auth_key: [5; 256],
            time_offset: 3,
            first_salt: 9,
        });
        assert_eq!(enc.mtp.auth_key(), [5; 256]);
        assert!(enc.can_buffer_requests());
    }
}
