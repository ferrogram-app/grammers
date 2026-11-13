// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::*;

impl<T: Transport, M: mtp::Mtp> Sender<T, M> {
    /// Process the result of deserializing an MTP buffer.
    pub(super) fn process_mtp_buffer(
        &mut self,
        results: Vec<mtp::Deserialization>,
        updates: &mut Vec<UpdatesLike>,
    ) {
        for result in results {
            match result {
                mtp::Deserialization::OwnUpdate { msg_id, update } => {
                    self.process_own_update(updates, msg_id, update)
                }
                mtp::Deserialization::Update(update) => self.process_update(updates, update),
                mtp::Deserialization::RpcResult(result) => self.process_result(result),
                mtp::Deserialization::RpcError(error) => self.process_error(error),
                mtp::Deserialization::BadMessage(bad_msg) => self.process_bad_message(bad_msg),
                mtp::Deserialization::NewSession { first_msg_id } => {
                    self.process_new_session(updates, first_msg_id)
                }
                mtp::Deserialization::Failure(failure) => self.process_deserialize_error(failure),
            }
        }
    }

    pub(super) fn process_own_update(
        &mut self,
        updates: &mut Vec<UpdatesLike>,
        msg_id: MsgId,
        update: Vec<u8>,
    ) {
        match (
            UpdatesLike::from_bytes(&update),
            self.peek_request(msg_id).and_then(|request| {
                tl::functions::messages::SendMessage::from_boxed_bytes(&request.body).ok()
            }),
        ) {
            (
                Ok(UpdatesLike::Updates(tl::enums::Updates::UpdateShortSentMessage(u))),
                Some(request),
            ) => {
                // As far as I know, UpdateShortSentMessage can only occur from SendMessage.
                // If that's not the case, new variants with additional requests should be added.
                updates.push(UpdatesLike::ShortSentMessage { request, update: u })
            }
            (Ok(UpdatesLike::AffectedMessages(affected)), _) => {
                // Check if the original request targeted a channel (e.g. channels.deleteMessages).
                // If so, the pts belongs to that channel, not the common/user pts sequence.
                let channel_id = self
                    .peek_request(msg_id)
                    .and_then(|request| {
                        tl::functions::channels::DeleteMessages::from_boxed_bytes(&request.body)
                            .ok()
                    })
                    .and_then(|request| match request.channel {
                        tl::enums::InputChannel::Channel(c) => Some((c.channel_id, request.id)),
                        _ => None,
                    });
                if let Some((channel_id, message_ids)) = channel_id {
                    updates.push(UpdatesLike::AffectedChannelMessages {
                        affected,
                        channel_id,
                        message_ids,
                    });
                } else {
                    updates.push(UpdatesLike::AffectedMessages(affected));
                }
            }
            (Ok(u), _) => {
                // In the future, we might want to flag "updates produced by the client" somehow.
                // This would be the starting place to do it.
                updates.push(u);
            }
            (Err(e), _) => {
                // This shouldn't happen. We just made the request, so they shouldn't be stale.
                // If the request failed with a failed-to-deserialize error, callers will handle it.
                warn!("telegram responded with updates that failed to be deserialized: {e}")
            }
        }
    }

    pub(super) fn process_update(&mut self, updates: &mut Vec<UpdatesLike>, update: Vec<u8>) {
        match UpdatesLike::from_bytes(&update) {
            Ok(u) => updates.push(u),
            Err(e) => {
                // These are to be treated as a gap.
                // > Manually obtaining updates through [get difference] is required in the following situations:
                // > […] Incorrect update: the client cannot deserialize the received data.
                warn!("telegram sent updates that failed to be deserialized: {e}");
                updates.push(UpdatesLike::MalformedUpdates);
            }
        }
    }

    pub(super) fn process_result(&mut self, result: mtp::RpcResult) {
        if let Some(req) = self.pop_request(result.msg_id) {
            let x = result.body;
            // The server controls this body: too short to hold a constructor id is an error
            // for the caller, not a panic.
            let Some(head) = x.first_chunk::<4>() else {
                drop(req.result.send(Err(InvocationError::Dropped(
                    "rpc result shorter than a constructor id",
                ))));
                return;
            };
            let res_id = u32::from_le_bytes(*head);
            debug!(
                res_id = format_args!("{:x}", res_id),
                res_name = tl::name_for_id(res_id),
                request = ?result.msg_id,
                "got result",
            );
            drop(req.result.send(Ok(x)));
        } else {
            info!(
                result = ?result.msg_id,
                "got rpc result but no such request is saved",
            );
        }
    }

    pub(super) fn process_error(&mut self, error: mtp::RpcResultError) {
        if let Some(req) = self.pop_request(error.msg_id) {
            debug!(error = ?error.error, "got rpc error");
            let x = req.body.as_slice();
            drop(
                req.result.send(Err(InvocationError::Rpc(
                    RpcError::from(error.error)
                        .with_caused_by(u32::from_le_bytes([x[0], x[1], x[2], x[3]])),
                ))),
            );
        } else {
            info!(
                error = ?error.msg_id,
                "got rpc error but no such request is saved",
            );
        }
    }

    /// The server opened a new session: it never saw requests older than `first_msg_id`, so
    /// they are sent again, and updates may have been lost, so the upper layer is told.
    pub(super) fn process_new_session(
        &mut self,
        updates: &mut Vec<UpdatesLike>,
        first_msg_id: MsgId,
    ) {
        for request in &mut self.requests {
            if matches!(&request.state, RequestState::Sent(pair) if pair.msg_id < first_msg_id) {
                info!("new session: re-sending a request the server has not seen");
                request.state = RequestState::NotSerialized;
            }
        }
        updates.push(UpdatesLike::ConnectionClosed);
    }

    pub(super) fn process_bad_message(&mut self, bad_msg: mtp::BadMessage) {
        for i in (0..self.requests.len()).rev() {
            match &self.requests[i].state {
                RequestState::Serialized(pair)
                    if pair.msg_id == bad_msg.msg_id || pair.container_msg_id == bad_msg.msg_id =>
                {
                    // The server cannot know ids we have not sent; ignore it instead of aborting.
                    warn!(
                        msg_id = ?bad_msg.msg_id,
                        "bad msg for unsent request: {}",
                        bad_msg.description()
                    );
                    return;
                }
                RequestState::Sent(pair)
                    if pair.msg_id == bad_msg.msg_id || pair.container_msg_id == bad_msg.msg_id =>
                {
                    // TODO add a test to make sure we resend the request
                    if bad_msg.retryable() {
                        info!(
                            request = ?pair.msg_id,
                            "{}; re-sending request",
                            bad_msg.description(),
                        );

                        // TODO check if actually retryable first!
                        self.requests[i].state = RequestState::NotSerialized;
                    } else {
                        if bad_msg.fatal() {
                            error!(
                                request = ?pair.msg_id,
                                "{}; cannot retry request",
                                bad_msg.description(),
                            );
                        } else {
                            warn!(
                                request = ?pair.msg_id,
                                "{}; cannot retry request",
                                bad_msg.description(),
                            );
                        }
                        let req = self.requests.swap_remove(i);
                        drop(req.result.send(Err(InvocationError::Dropped(
                            "response was non-retryable bad msg",
                        ))));
                    }
                }
                _ => {}
            }
        }
    }

    pub(super) fn process_deserialize_error(&mut self, failure: mtp::DeserializationFailure) {
        if let Some(req) = self.pop_request(failure.msg_id) {
            debug!(error = ?failure.error, "got deserialization failure");
            drop(req.result.send(Err(InvocationError::from(failure.error))));
        } else {
            info!(
                error = ?failure.error,
                "got deserialization failure but no such request is saved",
            );
        }
    }

    pub(super) fn peek_request(&mut self, msg_id: MsgId) -> Option<&Request> {
        self.requests.iter().find(|request| match request.state {
            RequestState::NotSerialized => false,
            RequestState::Serialized(MsgIdPair { msg_id: m, .. }) => m == msg_id,
            RequestState::Sent(MsgIdPair { msg_id: m, .. }) => m == msg_id,
        })
    }

    pub(super) fn pop_request(&mut self, msg_id: MsgId) -> Option<Request> {
        for i in 0..self.requests.len() {
            match &self.requests[i].state {
                RequestState::Serialized(pair) if pair.msg_id == msg_id => {
                    warn!(?msg_id, ?pair, "got response for unsent request; ignoring");
                    return None;
                }
                RequestState::Sent(pair) if pair.msg_id == msg_id => {
                    return Some(self.requests.swap_remove(i));
                }
                _ => {}
            }
        }

        None
    }
}
