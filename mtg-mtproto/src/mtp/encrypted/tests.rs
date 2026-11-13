// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::*;

// salt + session_id
const MESSAGE_PREFIX_LEN: usize = 8 + 8;

// gzip_packed#3072cfa1 packed_data:string = Object;
const GZIP_PACKED_HEADER: [u8; 4] = [0xa1, 0xcf, 0x72, 0x30];

// msg_container#73f1f8dc messages:vector<message> = MessageContainer;
const MSG_CONTAINER_HEADER: [u8; 4] = [0xdc, 0xf8, 0xf1, 0x73];

const REQUEST: &[u8] = b"Hey!";
const REQUEST_B: &[u8] = b"Bye!";

fn auth_key() -> [u8; 256] {
    [0; 256]
}

fn ensure_buffer_is_message(buffer: &[u8], body: &[u8], seq_no: u8) {
    // buffer[0..8] is the msg_id, based on `SystemTime::now()`
    assert_ne!(&buffer[0..8], [0, 0, 0, 0, 0, 0, 0, 0]);
    // buffer[8..12] is the seq_no, ever-increasing odd number (little endian)
    assert_eq!(&buffer[8..12], [seq_no, 0, 0, 0]);
    // buffer[12..16] is the bytes, the len of the body (little endian)
    assert_eq!(&buffer[12..16], [body.len() as u8, 0, 0, 0]);
    // buffer[16..] is the body, which is padded to 4 bytes
    assert_eq!(&buffer[16..], body);
}

#[test]
fn ensure_serialization_has_salt_session_id() {
    let mut buffer = DequeBuffer::with_capacity(0, 0);
    let mut mtproto = Encrypted::build().finish(auth_key());

    mtproto.push(&mut buffer, REQUEST);
    mtproto.finalize_plain(&mut buffer);

    // salt comes first, it's zero by default.
    assert_eq!(&buffer[0..8], [0, 0, 0, 0, 0, 0, 0, 0]);

    // session_id should be random.
    assert_ne!(&buffer[8..16], [0, 0, 0, 0, 0, 0, 0, 0]);

    // Only one message should remain.
    ensure_buffer_is_message(&buffer[MESSAGE_PREFIX_LEN..], REQUEST, 1);
}

#[test]
fn ensure_correct_single_serialization() {
    let mut buffer = DequeBuffer::with_capacity(0, 0);
    let mut mtproto = Encrypted::build().finish(auth_key());

    assert!(mtproto.push(&mut buffer, REQUEST).is_some());
    mtproto.finalize_plain(&mut buffer);

    let buffer = &buffer[MESSAGE_PREFIX_LEN..];
    ensure_buffer_is_message(buffer, REQUEST, 1);
}

#[test]
fn ensure_correct_multi_serialization() {
    let mut buffer = DequeBuffer::with_capacity(0, 0);
    let mut mtproto = Encrypted::build()
        .compression_threshold(None)
        .finish(auth_key());

    assert!(mtproto.push(&mut buffer, REQUEST).is_some());
    assert!(mtproto.push(&mut buffer, REQUEST_B).is_some());
    mtproto.finalize_plain(&mut buffer);
    let buffer = &buffer[MESSAGE_PREFIX_LEN..];

    // buffer[0..8] is the msg_id for the container
    assert_ne!(&buffer[0..8], [0, 0, 0, 0, 0, 0, 0, 0]);
    // buffer[8..12] is the seq_no, maybe-increasing even number.
    // after two messages (1, 3) the next non-content related is 4.
    assert_eq!(&buffer[8..12], [4, 0, 0, 0]);
    // buffer[12..16] is the bytes, the len of the body
    assert_eq!(&buffer[12..16], [48, 0, 0, 0]);

    // buffer[16..20] is the constructor id of the container
    assert_eq!(&buffer[16..20], MSG_CONTAINER_HEADER);
    // buffer[20..24] is how many messages are included
    assert_eq!(&buffer[20..24], [2, 0, 0, 0]);

    // buffer[24..44] is an inner message
    ensure_buffer_is_message(&buffer[24..44], REQUEST, 1);

    // buffer[44..] is the other inner message
    ensure_buffer_is_message(&buffer[44..], REQUEST_B, 3);
}

#[test]
fn ensure_correct_single_large_serialization() {
    let mut buffer = DequeBuffer::with_capacity(0, 0);
    let mut mtproto = Encrypted::build()
        .compression_threshold(None)
        .finish(auth_key());
    let data = vec![0x7f; 768 * 1024];

    assert!(mtproto.push(&mut buffer, &data).is_some());
    mtproto.finalize_plain(&mut buffer);

    let buffer = &buffer[MESSAGE_PREFIX_LEN..];
    assert_eq!(buffer.len(), 16 + data.len());
}

#[test]
fn ensure_correct_multi_large_serialization() {
    let mut buffer = DequeBuffer::with_capacity(0, 0);
    let mut mtproto = Encrypted::build()
        .compression_threshold(None)
        .finish(auth_key());
    let data = vec![0x7f; 768 * 1024];

    assert!(mtproto.push(&mut buffer, &data).is_some());
    assert!(mtproto.push(&mut buffer, &data).is_none());

    // No container should be used, only the `salt` + `session_id` (16 bytes) should count.
    mtproto.finalize_plain(&mut buffer);
    let buffer = &buffer[MESSAGE_PREFIX_LEN..];
    assert_eq!(buffer.len(), 16 + data.len());
}

#[test]
#[should_panic]
fn ensure_large_payload_panics() {
    let mut buffer = DequeBuffer::with_capacity(0, 0);
    let mut mtproto = Encrypted::build().finish(auth_key());

    mtproto.push(&mut buffer, &vec![0; 2 * 1024 * 1024]);
}

#[test]
#[should_panic]
fn ensure_non_padded_payload_panics() {
    let mut buffer = DequeBuffer::with_capacity(0, 0);
    let mut mtproto = Encrypted::build().finish(auth_key());

    mtproto.push(&mut buffer, &[1, 2, 3]);
}

#[test]
fn ensure_no_compression_is_honored() {
    // A large vector of null bytes should compress
    let mut buffer = DequeBuffer::with_capacity(0, 0);
    let mut mtproto = Encrypted::build()
        .compression_threshold(None)
        .finish(auth_key());

    mtproto.push(&mut buffer, &vec![0; 512 * 1024]);
    mtproto.finalize_plain(&mut buffer);
    assert!(!buffer.as_ref().windows(4).any(|w| w == GZIP_PACKED_HEADER));
}

#[test]
fn ensure_some_compression() {
    // A large vector of null bytes should compress
    {
        // High threshold not reached, should not compress
        let mut buffer = DequeBuffer::with_capacity(0, 0);
        let mut mtproto = Encrypted::build()
            .compression_threshold(Some(768 * 1024))
            .finish(auth_key());
        mtproto.push(&mut buffer, &vec![0; 512 * 1024]);
        mtproto.finalize_plain(&mut buffer);
        assert!(!buffer.as_ref().windows(4).any(|w| w == GZIP_PACKED_HEADER));
    }
    {
        // Low threshold is exceeded, should compress
        let mut buffer = DequeBuffer::with_capacity(0, 0);
        let mut mtproto = Encrypted::build()
            .compression_threshold(Some(256 * 1024))
            .finish(auth_key());
        mtproto.push(&mut buffer, &vec![0; 512 * 1024]);
        mtproto.finalize_plain(&mut buffer);
        assert!(buffer.as_ref().windows(4).any(|w| w == GZIP_PACKED_HEADER));
    }
    {
        // The default should compress
        let mut buffer = DequeBuffer::with_capacity(0, 0);
        let mut mtproto = Encrypted::build().finish(auth_key());
        mtproto.push(&mut buffer, &vec![0; 512 * 1024]);
        mtproto.finalize_plain(&mut buffer);
        assert!(buffer.as_ref().windows(4).any(|w| w == GZIP_PACKED_HEADER));
    }
}

/// A packet the way the server builds it: the key shifted by 8 bytes gives the server-to-client direction.
fn server_packet(session_id: i64, msg_id: i64, body: &[u8], padding: Option<usize>) -> Vec<u8> {
    let key = AuthKey::from_bytes(auth_key());
    let mut shifted = [0u8; 256];
    shifted[..248].copy_from_slice(&key.to_bytes()[8..]);
    let mut plain = 0i64.to_le_bytes().to_vec(); // salt
    plain.extend(session_id.to_le_bytes());
    plain.extend(msg_id.to_le_bytes());
    plain.extend(1u32.to_le_bytes());
    plain.extend((body.len() as u32).to_le_bytes());
    plain.extend(body);
    let n = padding.unwrap_or(12 + (16 - (plain.len() + 12) % 16) % 16);
    plain.extend(vec![0u8; n]);
    let msg_key = encrypt_data_v2(&mut plain, &AuthKey::from_bytes(shifted));
    let mut out = key.key_id().to_vec();
    out.extend(msg_key);
    out.extend(plain);
    out
}

fn pong() -> Vec<u8> {
    use tl::Serializable;
    tl::enums::Pong::Pong(tl::types::Pong {
        msg_id: 0,
        ping_id: 1,
    })
    .to_bytes()
}

fn session(m: &Encrypted) -> i64 {
    m.session_id
}

/// A valid server msg_id for "now" (odd), `n` steps further.
fn fresh(n: i64) -> i64 {
    at(0, n)
}

/// A server msg_id `secs_ago` seconds in the past.
fn at(secs_ago: i64, n: i64) -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    ((now - secs_ago) << 32) | (4 * n + 1)
}

#[test]
fn server_message_ids_must_be_recent() {
    let mut m = Encrypted::build().finish(auth_key());
    let s = session(&m);
    let mut try_id = |id| {
        m.deserialize(&mut server_packet(s, id, &pong(), None))
            .is_ok()
    };
    assert!(try_id(at(299, 0)));
    assert!(!try_id(at(301, 1)));
    assert!(!try_id(at(-60, 2)));
    assert!(try_id(at(-20, 3)));
}

#[test]
fn a_bad_msg_notification_is_accepted_whatever_our_clock_says() {
    use tl::Serializable;
    let mut m = Encrypted::build().finish(auth_key());
    let s = session(&m);
    let body = tl::enums::BadMsgNotification::Notification(tl::types::BadMsgNotification {
        bad_msg_id: 1,
        bad_msg_seqno: 1,
        error_code: 17,
    })
    .to_bytes();
    let r = m.deserialize(&mut server_packet(s, at(-3600, 0), &body, None));
    assert!(r.is_ok());
}

#[test]
fn lone_future_salt_and_msg_copy_are_errors_not_panics() {
    for id in [
        tl::types::FutureSalt::CONSTRUCTOR_ID,
        manual_tl::MessageCopy::CONSTRUCTOR_ID,
    ] {
        let mut m = Encrypted::build().finish(auth_key());
        let s = session(&m);
        let r = m.deserialize(&mut server_packet(s, fresh(0), &id.to_le_bytes(), None));
        assert!(matches!(
            r,
            Err(DeserializeError::UnexpectedConstructor { id: got }) if got == id
        ));
    }
}

#[test]
fn a_good_server_packet_is_processed_once() {
    let mut m = Encrypted::build().finish(auth_key());
    let s = session(&m);
    let n = m
        .deserialize(&mut server_packet(s, fresh(0), &pong(), None))
        .unwrap()
        .len();
    assert!(n > 0);
    // the same message again is dropped
    assert!(
        m.deserialize(&mut server_packet(s, fresh(0), &pong(), None))
            .unwrap()
            .is_empty()
    );
    assert!(
        m.deserialize(&mut server_packet(s, fresh(1), &pong(), None))
            .unwrap()
            .len()
            == n
    );
}

#[test]
fn another_session_is_an_error_not_a_panic() {
    let mut m = Encrypted::build().finish(auth_key());
    let s = session(&m);
    assert_eq!(
        m.deserialize(&mut server_packet(s + 1, fresh(0), &pong(), None))
            .err(),
        Some(DeserializeError::BadSessionId {
            got: s + 1,
            expected: s
        })
    );
}

#[test]
fn even_server_message_ids_are_refused() {
    let mut m = Encrypted::build().finish(auth_key());
    let s = session(&m);
    assert_eq!(
        m.deserialize(&mut server_packet(s, 100, &pong(), None))
            .err(),
        Some(DeserializeError::BadMessageId { got: 100 })
    );
}

#[test]
fn padding_must_be_12_to_1024_bytes() {
    let mut m = Encrypted::build().finish(auth_key());
    let s = session(&m);
    // 32 bytes of header + a 20 byte pong + 12 bytes the pong ignores: already a multiple of 16
    let mut body = pong();
    body.extend([0u8; 12]);
    for (pad, ok) in [(0, false), (16, true), (1024, true), (1040, false)] {
        let r = m.deserialize(&mut server_packet(s, fresh(pad as i64), &body, Some(pad)));
        assert_eq!(r.is_ok(), ok, "padding {pad}");
    }
}

#[test]
fn a_hostile_length_is_an_error_not_a_panic() {
    let mut m = Encrypted::build().finish(auth_key());
    let s = session(&m);
    let mut packet = server_packet(s, fresh(0), &pong(), None);
    // rewrite the length field (inside the encrypted part: rebuild with a lying length)
    packet.clear();
    let key = AuthKey::from_bytes(auth_key());
    let mut shifted = [0u8; 256];
    shifted[..248].copy_from_slice(&key.to_bytes()[8..]);
    let mut plain = 0i64.to_le_bytes().to_vec();
    plain.extend(s.to_le_bytes());
    plain.extend(fresh(0).to_le_bytes());
    plain.extend(1u32.to_le_bytes());
    plain.extend((-5i32).to_le_bytes());
    plain.extend([0u8; 12]);
    plain.extend(vec![0u8; (16 - plain.len() % 16) % 16]);
    let msg_key = encrypt_data_v2(&mut plain, &AuthKey::from_bytes(shifted));
    packet.extend(key.key_id());
    packet.extend(msg_key);
    packet.extend(plain);
    assert!(m.deserialize(&mut packet).is_err());
}

fn container_of(messages: &[manual_tl::Message]) -> Vec<u8> {
    use tl::Serializable;
    let mut out = MSG_CONTAINER_HEADER.to_vec();
    out.extend((messages.len() as i32).to_le_bytes());
    for m in messages {
        out.extend(m.to_bytes());
    }
    out
}

fn inner(msg_id: i64, body: Vec<u8>) -> manual_tl::Message {
    manual_tl::Message {
        msg_id,
        seq_no: 0,
        body,
    }
}

#[test]
fn a_container_inside_a_container_is_an_error() {
    let mut m = Encrypted::build().finish(auth_key());
    let s = session(&m);
    let nested = container_of(&[inner(fresh(2), pong())]);
    let outer = container_of(&[inner(fresh(4), nested)]);
    assert!(
        m.deserialize(&mut server_packet(s, fresh(0), &outer, None))
            .is_err()
    );
    assert_eq!(m.nesting, 0, "depth is restored after an error");
}

#[test]
fn a_flat_container_still_works_and_restores_depth() {
    let mut m = Encrypted::build().finish(auth_key());
    let s = session(&m);
    let c = container_of(&[inner(fresh(2), pong())]);
    assert!(
        m.deserialize(&mut server_packet(s, fresh(0), &c, None))
            .is_ok()
    );
    assert_eq!(m.nesting, 0);
}

#[test]
fn the_nesting_guard_refuses_a_deep_chain() {
    let mut m = Encrypted::build().finish(auth_key());
    m.nesting = MAX_NESTING;
    let c = container_of(&[]);
    let msg = inner(fresh(0), c);
    assert!(m.handle_container(msg).is_err());
}

#[test]
fn acks_are_capped_and_the_rest_stays_pending() {
    let mut m = Encrypted::build().finish(auth_key());
    m.pending_ack = (0..MAX_IDS_PER_ACK as i64 + 10).collect();
    let mut buf = DequeBuffer::with_capacity(0, 0);
    let _ = m.push(&mut buf, REQUEST);
    assert!(m.pending_ack.len() <= 10, "left {}", m.pending_ack.len());
}

#[test]
fn future_salts_for_someone_elses_request_do_not_replace_ours() {
    use tl::Serializable;
    let mut m = Encrypted::build().finish(auth_key());
    let before = m.salts.clone();
    let body = tl::enums::FutureSalts::Salts(tl::types::FutureSalts {
        req_msg_id: 12345,
        now: 0,
        salts: tl::RawVec(vec![]),
    })
    .to_bytes();
    m.handle_future_salts(inner(fresh(0), body)).unwrap();
    assert_eq!(m.salts, before);
    assert!(matches!(
        m.deserialization.as_slice(),
        [Deserialization::RpcResult(r)] if r.msg_id == MsgId(12345)
    ));
}

fn id(c: u32) -> Vec<u8> {
    c.to_le_bytes().to_vec()
}

fn le(mut v: Vec<u8>, parts: &[&[u8]]) -> Vec<u8> {
    for p in parts {
        v.extend(*p);
    }
    v
}

fn rpc_result(req: i64, result: Vec<u8>) -> Vec<u8> {
    le(
        id(manual_tl::RpcResult::CONSTRUCTOR_ID),
        &[&req.to_le_bytes(), &result],
    )
}

/// Feeds `body` as the n-th server message and returns what `deserialize` queued.
fn feed(
    m: &mut Encrypted,
    n: i64,
    body: Vec<u8>,
) -> Result<Vec<Deserialization>, DeserializeError> {
    m.process_message(inner(fresh(n), body))?;
    Ok(std::mem::take(&mut m.deserialization))
}

#[test]
fn service_messages_without_effects_are_accepted() {
    let mut m = Encrypted::build().finish(auth_key());
    let junk = [0u8; 16];
    for (n, c) in [
        tl::types::MsgsStateReq::CONSTRUCTOR_ID,
        tl::types::MsgsStateInfo::CONSTRUCTOR_ID,
        tl::types::MsgsAllInfo::CONSTRUCTOR_ID,
        tl::types::MsgResendReq::CONSTRUCTOR_ID,
        tl::types::DestroySessionOk::CONSTRUCTOR_ID,
        tl::types::HttpWait::CONSTRUCTOR_ID,
    ]
    .into_iter()
    .enumerate()
    {
        let out = feed(&mut m, n as i64 * 2 + 1, le(id(c), &[&junk])).unwrap();
        assert!(out.is_empty(), "{c:x}");
    }
    // anything else is an update for the upper layers
    let out = feed(&mut m, 99, le(id(0xdeadbeef), &[&junk])).unwrap();
    assert!(matches!(&out[..], [Deserialization::Update(_)]));
}

fn new_session(unique_id: i64, first: i64) -> Vec<u8> {
    le(
        id(tl::types::NewSessionCreated::CONSTRUCTOR_ID),
        &[
            &first.to_le_bytes(),
            &unique_id.to_le_bytes(),
            &5i64.to_le_bytes(),
        ],
    )
}

#[test]
fn a_new_session_is_reported_once_per_unique_id() {
    let mut m = Encrypted::build().finish(auth_key());
    let out = feed(&mut m, 1, new_session(100, 4000)).unwrap();
    assert!(
        matches!(&out[..], [Deserialization::NewSession { first_msg_id }] if *first_msg_id == MsgId(4000))
    );
    // the same session announced again (a resend): nothing new
    assert!(feed(&mut m, 2, new_session(100, 4000)).unwrap().is_empty());
    // another session
    assert_eq!(feed(&mut m, 3, new_session(101, 5000)).unwrap().len(), 1);
    // the memory is bounded: after SEEN_SESSIONS others, id 100 counts as new again
    for n in 0..SEEN_SESSIONS as i64 {
        feed(&mut m, 10 + n, new_session(200 + n, 1)).unwrap();
    }
    assert_eq!(feed(&mut m, 90, new_session(100, 4000)).unwrap().len(), 1);
}

#[test]
fn detailed_info_new_session_and_bad_salt() {
    let mut m = Encrypted::build().finish(auth_key());
    let info = le(
        id(tl::types::MsgDetailedInfo::CONSTRUCTOR_ID),
        &[
            &1i64.to_le_bytes(),
            &111i64.to_le_bytes(),
            &0i32.to_le_bytes(),
            &0i32.to_le_bytes(),
        ],
    );
    feed(&mut m, 1, info).unwrap();
    let new_info = le(
        id(tl::types::MsgNewDetailedInfo::CONSTRUCTOR_ID),
        &[
            &222i64.to_le_bytes(),
            &0i32.to_le_bytes(),
            &0i32.to_le_bytes(),
        ],
    );
    feed(&mut m, 2, new_info).unwrap();
    assert!(m.pending_ack.contains(&111) && m.pending_ack.contains(&222));

    let created = le(
        id(tl::types::NewSessionCreated::CONSTRUCTOR_ID),
        &[
            &0i64.to_le_bytes(),
            &0i64.to_le_bytes(),
            &77i64.to_le_bytes(),
        ],
    );
    feed(&mut m, 3, created).unwrap();
    assert_eq!(m.salts.len(), 1);
    assert_eq!(m.salts[0].salt, 77);

    let bad_salt = le(
        id(tl::types::BadServerSalt::CONSTRUCTOR_ID),
        &[
            &5i64.to_le_bytes(),
            &0i32.to_le_bytes(),
            &48i32.to_le_bytes(),
            &88i64.to_le_bytes(),
        ],
    );
    let out = feed(&mut m, 4, bad_salt).unwrap();
    assert!(matches!(&out[..], [Deserialization::BadMessage(b)] if b.code == 48));
    assert_eq!(m.salts[0].salt, 88);
}

#[test]
fn rpc_results_of_every_kind() {
    let mut m = Encrypted::build().finish(auth_key());
    let err = le(
        id(tl::types::RpcError::CONSTRUCTOR_ID),
        &[&420i32.to_le_bytes(), &[3, b'a', b'b', b'c']],
    );
    let out = feed(&mut m, 1, rpc_result(10, err)).unwrap();
    assert!(matches!(&out[..], [Deserialization::RpcError(e)] if e.error.error_code == 420));

    // a truncated rpc_error is a failure for that request, not for the connection
    let out = feed(
        &mut m,
        2,
        rpc_result(11, id(tl::types::RpcError::CONSTRUCTOR_ID)),
    )
    .unwrap();
    assert!(matches!(&out[..], [Deserialization::Failure(f)] if f.msg_id == MsgId(11)));

    // empty result: no constructor to peek
    let out = feed(&mut m, 3, rpc_result(12, vec![])).unwrap();
    assert!(matches!(&out[..], [Deserialization::Failure(_)]));

    // answers about dropped queries produce nothing
    for (n, c) in [
        tl::types::RpcAnswerUnknown::CONSTRUCTOR_ID,
        tl::types::RpcAnswerDroppedRunning::CONSTRUCTOR_ID,
        tl::types::RpcAnswerDropped::CONSTRUCTOR_ID,
    ]
    .into_iter()
    .enumerate()
    {
        let out = feed(&mut m, 10 + n as i64, rpc_result(13, id(c))).unwrap();
        assert!(out.is_empty());
    }

    // a plain result, and one that is an update too
    let out = feed(&mut m, 20, rpc_result(14, le(id(0x11223344), &[&[0; 4]]))).unwrap();
    assert!(matches!(&out[..], [Deserialization::RpcResult(r)] if r.msg_id == MsgId(14)));
    let upd = le(id(UPDATE_IDS[0]), &[&[0; 8]]);
    let out = feed(&mut m, 21, rpc_result(15, upd)).unwrap();
    assert!(matches!(
        &out[..],
        [
            Deserialization::OwnUpdate { .. },
            Deserialization::RpcResult(_)
        ]
    ));
}

#[test]
fn gzip_rpc_results_and_bad_gzip() {
    use std::io::Write;
    let mut m = Encrypted::build().finish(auth_key());
    let packed = |payload: &[u8]| {
        let mut z = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(payload).unwrap();
        let z = z.finish().unwrap();
        let mut v = id(manual_tl::GzipPacked::CONSTRUCTOR_ID);
        v.push(z.len() as u8); // TL string: short length prefix
        v.extend(&z);
        while !v.len().is_multiple_of(4) {
            v.push(0);
        }
        v
    };
    let payload = le(id(0x11223344), &[&[7; 4]]);
    let out = feed(&mut m, 1, rpc_result(1, packed(&payload))).unwrap();
    assert!(matches!(&out[..], [Deserialization::RpcResult(r)] if r.body == payload));

    // not gzip at all
    let mut bad = id(manual_tl::GzipPacked::CONSTRUCTOR_ID);
    bad.extend([4, 1, 2, 3, 4, 0, 0, 0]);
    let out = feed(&mut m, 2, rpc_result(2, bad)).unwrap();
    assert!(matches!(&out[..], [Deserialization::Failure(f)] if f.msg_id == MsgId(2)));

    // truncated gzip_packed header
    let out = feed(
        &mut m,
        3,
        rpc_result(3, id(manual_tl::GzipPacked::CONSTRUCTOR_ID)),
    )
    .unwrap();
    assert!(matches!(&out[..], [Deserialization::Failure(_)]));

    // a gzip_packed message (not an rpc_result) wrapping a service message
    let out = feed(&mut m, 4, packed(&le(id(0xdeadbeef), &[&[0; 4]]))).unwrap();
    assert!(matches!(&out[..], [Deserialization::Update(_)]));
}

fn bad_msg(code: i32, bad_msg_id: i64) -> Vec<u8> {
    use tl::Serializable;
    tl::enums::BadMsgNotification::Notification(tl::types::BadMsgNotification {
        bad_msg_id,
        bad_msg_seqno: 0,
        error_code: code,
    })
    .to_bytes()
}

#[test]
fn bad_msg_codes_19_32_33_64_start_a_new_session() {
    for code in [19, 32, 33, 64] {
        let mut m = Encrypted::build().finish(auth_key());
        m.sequence = 9;
        let old = m.session_id;
        let out = feed(&mut m, 1, bad_msg(code, 4)).unwrap();
        assert!(matches!(&out[..], [Deserialization::BadMessage(b)] if b.code == code));
        assert_ne!(m.session_id, old, "{code}");
        assert_eq!(m.previous_session_id, Some(old));
        assert_eq!(m.sequence, 0, "{code}");
    }
}

#[test]
fn other_bad_msg_codes_keep_the_session() {
    for code in [16, 17, 20, 34] {
        let mut m = Encrypted::build().finish(auth_key());
        let old = m.session_id;
        feed(&mut m, 1, bad_msg(code, 4)).unwrap();
        assert_eq!(m.session_id, old, "{code}");
    }
}

#[test]
fn answers_of_the_previous_session_are_still_accepted() {
    let mut m = Encrypted::build().finish(auth_key());
    let old = m.session_id;
    feed(&mut m, 1, bad_msg(32, 4)).unwrap();
    assert!(
        m.deserialize(&mut server_packet(old, fresh(2), &pong(), None))
            .is_ok()
    );
    let third = old ^ 1;
    assert!(matches!(
        m.deserialize(&mut server_packet(third, fresh(3), &pong(), None)),
        Err(DeserializeError::BadSessionId { .. })
    ));
}

#[test]
fn a_bad_server_salt_also_fixes_the_clock_and_the_next_message_id() {
    let mut m = Encrypted::build().finish(auth_key());
    m.time_offset = 1000;
    let bad_id = (i64::from(i32::MAX) << 32) | 4;
    let bad_salt = le(
        id(tl::types::BadServerSalt::CONSTRUCTOR_ID),
        &[
            &bad_id.to_le_bytes(),
            &0i32.to_le_bytes(),
            &48i32.to_le_bytes(),
            &88i64.to_le_bytes(),
        ],
    );
    m.process_message(inner(fresh(1), bad_salt)).unwrap();
    assert!(m.time_offset.abs() < 5, "{}", m.time_offset);
    assert_eq!(m.last_msg_id, bad_id);
}

fn detailed(answer: i64) -> Vec<u8> {
    le(
        id(tl::types::MsgNewDetailedInfo::CONSTRUCTOR_ID),
        &[
            &answer.to_le_bytes(),
            &0i32.to_le_bytes(),
            &0i32.to_le_bytes(),
        ],
    )
}

#[test]
fn a_detailed_info_asks_for_the_answer_once_a_minute() {
    let mut m = Encrypted::build().finish(auth_key());
    feed(&mut m, 1, detailed(222)).unwrap();
    assert_eq!(m.pending_resend, vec![222]);
    assert!(m.pending_ack.contains(&222));
    // asked again within a minute: not queued twice
    feed(&mut m, 2, detailed(222)).unwrap();
    assert_eq!(m.pending_resend, vec![222]);
    // after a minute it is asked again
    m.pending_resend.clear();
    m.resend_asked[0].1 -= std::time::Duration::from_secs(61);
    feed(&mut m, 3, detailed(222)).unwrap();
    assert_eq!(m.pending_resend, vec![222]);
}

#[test]
fn an_answer_we_already_have_is_not_asked_for() {
    let mut m = Encrypted::build().finish(auth_key());
    let have = fresh(7);
    feed(&mut m, 7, pong()).unwrap();
    feed(&mut m, 8, detailed(have)).unwrap();
    assert!(m.pending_resend.is_empty());
}

#[test]
fn the_resend_request_is_sent_with_the_next_push() {
    use tl::Serializable;
    let mut m = Encrypted::build().finish(auth_key());
    feed(&mut m, 1, detailed(222)).unwrap();
    let mut buffer = DequeBuffer::with_capacity(0, 0);
    // two messages: the ack and the resend request, then the request
    assert!(m.push(&mut buffer, REQUEST).is_some());
    let want =
        tl::enums::MsgResendReq::Req(tl::types::MsgResendReq { msg_ids: vec![222] }).to_bytes();
    assert!(buffer[..].windows(want.len()).any(|w| w == &want[..]));
    assert!(m.pending_resend.is_empty());
}

#[test]
fn a_full_container_keeps_the_resend_request_pending() {
    let mut m = Encrypted::build().finish(auth_key());
    feed(&mut m, 1, detailed(222)).unwrap();
    m.pending_ack.clear();
    m.msg_count = manual_tl::MessageContainer::MAXIMUM_LENGTH;
    let mut buffer = DequeBuffer::with_capacity(0, 0);
    assert!(m.push(&mut buffer, REQUEST).is_none());
    assert_eq!(m.pending_resend, vec![222]);
}
