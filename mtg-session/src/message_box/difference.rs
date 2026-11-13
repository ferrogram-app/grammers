// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Getting and applying the account and channel differences.

use mtg_tl_types as tl;
use tracing::{debug, trace};

use super::adaptor;
use super::defs::{
    Key, MessageBox, MessageBoxes, NO_DATE, NO_PTS, NO_SEQ, PtsInfo, State, UpdateAndPeers,
    UpdatesLike,
};

/// Getting and applying account difference.
impl MessageBoxes {
    /// Return the request that needs to be made to get the difference, if any.
    pub fn get_difference(&self) -> Option<tl::functions::updates::GetDifference> {
        for entry in [Key::Common, Key::Secondary] {
            if self.getting_diff_for.contains(&entry) {
                // A qts entry can exist without a pts one (a stored state with pts = 0, or qts
                // updates before the state was fetched): there is nothing to ask with then.
                let pts = self.entry(Key::Common).map(|entry| entry.pts)?;

                let gd = tl::functions::updates::GetDifference {
                    pts,
                    pts_limit: None,
                    pts_total_limit: None,
                    date: self.date.max(1), // non-zero or the request will fail
                    qts: self
                        .entry(Key::Secondary)
                        .map(|entry| entry.pts)
                        .unwrap_or(NO_PTS),
                    qts_limit: None,
                };
                trace!(?gd, "requesting");
                return Some(gd);
            }
        }
        None
    }

    /// Similar to [`MessageBoxes::process_updates`], but using the result from getting difference.
    pub fn apply_difference(
        &mut self,
        difference: tl::enums::updates::Difference,
    ) -> UpdateAndPeers {
        trace!(?difference, "applying account difference");
        debug_assert!(
            self.getting_diff_for.contains(&Key::Common)
                || self.getting_diff_for.contains(&Key::Secondary)
        );
        let finish: bool;
        let result = match difference {
            tl::enums::updates::Difference::Empty(diff) => {
                debug!(
                    "handling empty difference (date = {}, seq = {}); no longer getting diff",
                    diff.date, diff.seq
                );
                finish = true;
                self.date = diff.date;
                self.seq = diff.seq;
                (Vec::new(), Vec::new(), Vec::new())
            }
            tl::enums::updates::Difference::Difference(diff) => {
                debug!(
                    state = ?diff.state,
                    "handling full difference; no longer getting diff",
                );
                finish = true;
                self.apply_difference_type(diff)
            }
            tl::enums::updates::Difference::Slice(tl::types::updates::DifferenceSlice {
                new_messages,
                new_encrypted_messages,
                other_updates,
                chats,
                users,
                intermediate_state: state,
            }) => {
                debug!(?state, "handling partial difference");
                finish = false;
                self.apply_difference_type(tl::types::updates::Difference {
                    new_messages,
                    new_encrypted_messages,
                    other_updates,
                    chats,
                    users,
                    state,
                })
            }
            tl::enums::updates::Difference::TooLong(diff) => {
                debug!(
                    "handling too-long difference (pts = {}); no longer getting diff",
                    diff.pts
                );
                finish = true;
                // the deadline will be reset once the diff ends
                self.set_pts(Key::Common, diff.pts);
                (Vec::new(), Vec::new(), Vec::new())
            }
        };

        if finish {
            self.try_end_get_diff(Key::Common);
            self.try_end_get_diff(Key::Secondary);
        }

        result
    }

    fn apply_difference_type(
        &mut self,
        tl::types::updates::Difference {
            new_messages,
            new_encrypted_messages,
            other_updates: mut updates,
            chats,
            users,
            state: tl::enums::updates::State::State(state),
        }: tl::types::updates::Difference,
    ) -> UpdateAndPeers {
        self.date = state.date;
        self.seq = state.seq;
        self.set_pts(Key::Common, state.pts);
        self.set_pts(Key::Secondary, state.qts);
        let mk_state = |message_box| State {
            date: state.date,
            seq: state.seq,
            message_box: Some(message_box),
        };

        // other_updates can contain things like UpdateChannelTooLong and UpdateNewChannelMessage.
        // We need to process those as if they were socket updates to discard any we have already handled.
        // If the channel's difference is planned to be handled, skip its updates
        updates.retain(|update| {
            let Some(info) = PtsInfo::from_update(update) else {
                return true;
            };
            if let Key::Channel(_) = info.key {
                !self.getting_diff_for.contains(&info.key)
            } else {
                true
            }
        });
        let us = UpdatesLike::Updates(tl::enums::Updates::Updates(tl::types::Updates {
            updates,
            users,
            chats,
            date: NO_DATE,
            seq: NO_SEQ,
        }));

        // It is possible that the result from `GetDifference` includes users with `min = true`.
        // TODO in that case, we will have to resort to getUsers.
        let (mut result_updates, users, chats) = self
            .process_updates(us)
            .expect("gap is detected while applying difference");

        result_updates.extend(
            new_messages
                .into_iter()
                .map(|message| {
                    (
                        tl::types::UpdateNewMessage {
                            message,
                            pts: NO_PTS,
                            pts_count: 0,
                        }
                        .into(),
                        mk_state(MessageBox::Common { pts: state.pts }),
                    )
                })
                .chain(new_encrypted_messages.into_iter().map(|message| {
                    (
                        tl::types::UpdateNewEncryptedMessage {
                            message,
                            qts: NO_PTS,
                        }
                        .into(),
                        mk_state(MessageBox::Secondary { qts: state.qts }),
                    )
                })),
        );

        (result_updates, users, chats)
    }
}

/// Getting and applying channel difference.
impl MessageBoxes {
    /// The first channel currently getting its difference, as `(key, channel_id)`, if any.
    fn channel_in_diff(&self) -> Option<(Key, i64)> {
        self.getting_diff_for.iter().find_map(|&key| match key {
            Key::Channel(id) => Some((key, id)),
            _ => None,
        })
    }

    /// Return the request that needs to be made to get a channel's difference, if any.
    ///
    /// Note that this only returns the skeleton of a request.
    /// Both the channel hash and limit will be their default value.
    pub fn get_channel_difference(&self) -> Option<tl::functions::updates::GetChannelDifference> {
        let (key, channel_id) = self.channel_in_diff()?;

        if let Some(pts) = self.entry(key).map(|entry| entry.pts) {
            let gd = tl::functions::updates::GetChannelDifference {
                force: false,
                channel: tl::types::InputChannel {
                    channel_id,
                    access_hash: 0,
                }
                .into(),
                filter: tl::enums::ChannelMessagesFilter::Empty,
                pts,
                limit: 0,
            };
            trace!(?gd, "requesting");
            Some(gd)
        } else {
            panic!("Should not try to get difference for an entry {key:?} without known state");
        }
    }

    /// Similar to [`MessageBoxes::process_updates`], but using the result from getting difference.
    pub fn apply_channel_difference(
        &mut self,
        difference: tl::enums::updates::ChannelDifference,
    ) -> UpdateAndPeers {
        let (key, channel_id) = self
            .channel_in_diff()
            .expect("applying channel difference to have a channel in getting_diff_for");

        trace!(channel_id, ?difference, "applying channel difference");

        let Ok(tl::types::updates::ChannelDifference {
            r#final,
            pts,
            timeout,
            new_messages,
            other_updates: updates,
            chats,
            users,
        }) = adaptor::adapt_channel_difference(difference)
        else {
            // Malformed answer: behave as if the request had failed, keep the old state.
            self.end_channel_difference(PrematureEndReason::TemporaryServerIssues);
            return (Vec::new(), Vec::new(), Vec::new());
        };

        self.update_entry(key, |entry| entry.possible_gap = None);

        if r#final {
            debug!(
                "handling channel {} difference; no longer getting diff",
                channel_id
            );
            self.try_end_get_diff(key);
        } else {
            debug!("handling channel {} difference", channel_id);
        }

        self.set_pts(key, pts);
        let us = UpdatesLike::Updates(tl::enums::Updates::Updates(tl::types::Updates {
            updates,
            users,
            chats,
            date: NO_DATE,
            seq: NO_SEQ,
        }));
        let (mut result_updates, users, chats) = self
            .process_updates(us)
            .expect("gap is detected while applying channel difference");

        result_updates.extend(new_messages.into_iter().map(|message| {
            (
                tl::types::UpdateNewChannelMessage {
                    message,
                    pts: NO_PTS,
                    pts_count: 0,
                }
                .into(),
                State {
                    date: self.date,
                    seq: self.seq,
                    message_box: Some(MessageBox::Channel { channel_id, pts }),
                },
            )
        }));

        self.reset_timeout(key, timeout);

        (result_updates, users, chats)
    }

    pub fn end_channel_difference(&mut self, reason: PrematureEndReason) {
        let (key, channel_id) = self
            .channel_in_diff()
            .expect("ending channel difference to have a channel in getting_diff_for");

        trace!(channel_id, ?reason, "ending channel difference");
        match reason {
            PrematureEndReason::TemporaryServerIssues => {
                self.update_entry(key, |entry| entry.possible_gap = None);
                self.try_end_get_diff(key);
            }
            PrematureEndReason::Banned => {
                self.update_entry(key, |entry| entry.possible_gap = None);
                self.try_end_get_diff(key);
                self.pop_entry(key);
            }
        }
    }
}

/// Reason for calling [`MessageBoxes::end_channel_difference`].
#[derive(Debug)]
pub enum PrematureEndReason {
    /// The channel difference failed to be fetched for a temporary reasons.
    ///
    /// The channel state must be kept,
    /// and getting its difference retried in the future.
    TemporaryServerIssues,
    /// The logged-in account has been banned from the channel and won't
    /// be able to fetch the difference in the future.
    ///
    /// The channel state will be removed,
    /// and getting its difference should not be retried in the future.
    Banned,
}
