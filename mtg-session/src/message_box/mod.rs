// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module deals with correct handling of updates,
//! including gaps,
//! and knowing when the code should "get difference"
//! (the set of updates that the client should know by now
//! minus the set of updates that it actually knows).
//!
//! Each chat has its own [`LiveEntry`] in the [`MessageBoxes`]
//! (this `struct` is the "entry point").
//! At any given time,
//! the message box may be either getting difference for them
//! (entry is in [`MessageBoxes::getting_diff_for`])
//! or not.
//! If not getting difference,
//! a possible gap may be found for the updates
//! (entry is in [`MessageBoxes::possible_gaps`]).
//! Otherwise, the entry is on its happy path.
//!
//! Gaps are cleared when they are either
//! resolved on their own
//! (by waiting for a short time)
//! or because we got the difference for the corresponding entry.
//!
//! While there are entries for which their difference must be fetched,
//! [`MessageBoxes::check_deadlines`] will always return [`Instant::now`],
//! since "now" is the time to get the difference.

mod adaptor;
mod defs;
mod difference;
#[cfg(test)]
mod tests;

use std::cmp::Ordering;
use std::time::Duration;
#[cfg(not(test))]
use std::time::Instant;

use defs::Key;
pub use defs::{Gap, MessageBox, MessageBoxes, State, UpdateAndPeers, UpdatesLike};
use defs::{LiveEntry, NO_DATE, NO_PTS, NO_SEQ, POSSIBLE_GAP_TIMEOUT, PossibleGap, PtsInfo};
pub use difference::PrematureEndReason;
use mtg_tl_types as tl;
#[cfg(test)]
use tests::Instant;
use tracing::{debug, info, trace};

use crate::types::{ChannelState, UpdatesState};

fn next_updates_deadline() -> Instant {
    Instant::now() + defs::NO_UPDATES_TIMEOUT
}

fn update_sort_key(update: &tl::enums::Update) -> i32 {
    match PtsInfo::from_update(update) {
        Some(info) => info.pts - info.count,
        None => NO_PTS,
    }
}

impl MessageBox {
    pub fn pts(&self) -> i32 {
        match self {
            MessageBox::Common { pts } => *pts,
            MessageBox::Secondary { qts } => *qts,
            MessageBox::Channel { pts, .. } => *pts,
        }
    }
}

impl From<PtsInfo> for MessageBox {
    fn from(value: PtsInfo) -> Self {
        match value.key {
            Key::Common => Self::Common { pts: value.pts },
            Key::Secondary => Self::Secondary { qts: value.pts },
            Key::Channel(channel_id) => Self::Channel {
                channel_id,
                pts: value.pts,
            },
        }
    }
}

impl LiveEntry {
    fn effective_deadline(&self) -> Instant {
        match &self.possible_gap {
            Some(gap) => gap.deadline.min(self.deadline),
            None => self.deadline,
        }
    }
}

#[allow(clippy::new_without_default)]
/// Creation, querying, and setting base state.
impl MessageBoxes {
    /// Create a new, empty [`MessageBoxes`].
    pub fn new() -> Self {
        trace!("created new message box with no previous state");
        Self {
            entries: Vec::new(),
            date: NO_DATE,
            seq: NO_SEQ,
            getting_diff_for: Vec::new(),
            next_deadline: next_updates_deadline(),
        }
    }

    /// Create a [`MessageBoxes`] from a previously known update state.
    pub fn load(state: UpdatesState) -> Self {
        trace!(?state, "created new message box with state");
        let mut entries = Vec::with_capacity(2 + state.channels.len());
        let mut getting_diff_for = Vec::with_capacity(2 + state.channels.len());
        let deadline = next_updates_deadline();

        if state.pts != NO_PTS {
            entries.push(LiveEntry {
                key: Key::Common,
                pts: state.pts,
                deadline,
                possible_gap: None,
            });
        }
        if state.qts != NO_PTS {
            entries.push(LiveEntry {
                key: Key::Secondary,
                pts: state.qts,
                deadline,
                possible_gap: None,
            });
        }
        entries.extend(state.channels.iter().map(|c| LiveEntry {
            key: Key::Channel(c.id),
            pts: c.pts,
            deadline,
            possible_gap: None,
        }));
        entries.sort_by_key(|entry| entry.key);

        getting_diff_for.extend(entries.iter().map(|entry| entry.key));

        Self {
            entries,
            date: state.date,
            seq: state.seq,
            getting_diff_for,
            next_deadline: deadline,
        }
    }

    fn entry(&self, key: Key) -> Option<&LiveEntry> {
        self.entries
            .binary_search_by_key(&key, |entry| entry.key)
            .map(|i| &self.entries[i])
            .ok()
    }

    fn update_entry(&mut self, key: Key, updater: impl FnOnce(&mut LiveEntry)) -> bool {
        match self.entries.binary_search_by_key(&key, |entry| entry.key) {
            Ok(i) => {
                updater(&mut self.entries[i]);
                true
            }
            Err(_) => false,
        }
    }

    fn force_update_entry(&mut self, mut entry: LiveEntry, updater: impl FnOnce(&mut LiveEntry)) {
        match self
            .entries
            .binary_search_by_key(&entry.key, |entry| entry.key)
        {
            Ok(i) => updater(&mut self.entries[i]),
            Err(i) => {
                updater(&mut entry);
                self.entries.insert(i, entry);
            }
        }
    }

    fn set_entry(&mut self, entry: LiveEntry) {
        match self
            .entries
            .binary_search_by_key(&entry.key, |entry| entry.key)
        {
            Ok(i) => self.entries[i] = entry,
            Err(i) => self.entries.insert(i, entry),
        }
    }

    fn set_pts(&mut self, key: Key, pts: i32) {
        if !self.update_entry(key, |entry| entry.pts = pts) {
            self.set_entry(LiveEntry {
                key,
                pts,
                deadline: next_updates_deadline(),
                possible_gap: None,
            });
        }
    }

    fn pop_entry(&mut self, key: Key) -> Option<LiveEntry> {
        match self.entries.binary_search_by_key(&key, |entry| entry.key) {
            Ok(i) => Some(self.entries.remove(i)),
            Err(_) => None,
        }
    }

    /// Return the current state in a format that sessions understand.
    ///
    /// This should be used for persisting the state.
    pub fn session_state(&self) -> UpdatesState {
        UpdatesState {
            pts: self.entry(Key::Common).map(|s| s.pts).unwrap_or(NO_PTS),
            qts: self.entry(Key::Secondary).map(|s| s.pts).unwrap_or(NO_PTS),
            date: self.date,
            seq: self.seq,
            channels: self
                .entries
                .iter()
                .filter_map(|entry| match entry.key {
                    Key::Channel(id) => Some(ChannelState { id, pts: entry.pts }),
                    _ => None,
                })
                .collect(),
        }
    }

    /// Return true if the message box is empty and has no state yet.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return the next deadline when receiving updates should timeout.
    ///
    /// If a deadline expired, the corresponding entries will be marked as needing to get its difference.
    /// While there are entries pending of getting their difference, this method returns the current instant.
    pub fn check_deadlines(&mut self) -> Instant {
        let now = Instant::now();

        if !self.getting_diff_for.is_empty() {
            return self.next_deadline;
        }

        if now >= self.next_deadline {
            self.getting_diff_for
                .extend(self.entries.iter().filter_map(|entry| {
                    if now >= entry.effective_deadline() {
                        debug!(?entry, "deadline for forcibly fetching updates met");
                        Some(entry.key)
                    } else {
                        None
                    }
                }));

            // When extending `getting_diff_for`, it's important to have the moral equivalent of
            // `begin_get_diff` (that is, clear possible gaps if we're now getting difference).
            for i in 0..self.getting_diff_for.len() {
                self.update_entry(self.getting_diff_for[i], |entry| entry.possible_gap = None);
            }

            // To avoid hogging up all CPU by sleeping for no duration,
            // if the deadline was met but there's no state to fetch,
            // advance the deadline.
            if self.getting_diff_for.is_empty() {
                self.next_deadline = next_updates_deadline();
            }
        }

        self.next_deadline
    }

    /// Reset the deadline of an existing entry.
    /// Does nothing if the entry doesn't exist.
    ///
    /// If the updated deadline was the currently-next-deadline,
    /// the new closest deadline is calculated and stored as the next.
    fn reset_deadline(&mut self, key: Key, deadline: Instant) {
        let mut old_deadline = self.next_deadline;
        self.update_entry(key, |entry| {
            old_deadline = entry.deadline;
            entry.deadline = deadline;
        });
        if self.next_deadline == old_deadline {
            self.next_deadline = self
                .entries
                .iter()
                .fold(deadline, |d, entry| d.min(entry.effective_deadline()));
        }
    }

    fn reset_timeout(&mut self, key: Key, timeout: Option<i32>) {
        self.reset_deadline(
            key,
            timeout
                .map(|t| Instant::now() + Duration::from_secs(t as _))
                .unwrap_or_else(next_updates_deadline),
        );
    }

    /// Sets the update state.
    ///
    /// Should be called right after login if [`MessageBoxes::new`] was used, otherwise undesirable
    /// updates will be fetched.
    ///
    /// Should only be called while [`MessageBoxes::is_empty`].
    pub fn set_state(&mut self, state: tl::types::updates::State) {
        trace!(?state, "setting state");
        debug_assert!(self.is_empty());
        let deadline = next_updates_deadline();
        self.set_entry(LiveEntry {
            key: Key::Common,
            pts: state.pts,
            deadline,
            possible_gap: None,
        });
        self.set_entry(LiveEntry {
            key: Key::Secondary,
            pts: state.qts,
            deadline,
            possible_gap: None,
        });
        self.date = state.date;
        self.seq = state.seq;
        self.next_deadline = deadline;
    }

    /// Like [`MessageBoxes::set_state`], but for channels. Useful when getting dialogs.
    ///
    /// The update state will only be updated if no entry was known previously.
    pub fn try_set_channel_state(&mut self, id: i64, pts: i32) {
        trace!(channel_id = id, pts, "trying to set channel state");
        if self.entry(Key::Channel(id)).is_none() {
            self.set_entry(LiveEntry {
                key: Key::Channel(id),
                pts,
                deadline: next_updates_deadline(),
                possible_gap: None,
            });
        }
    }

    /// Try to begin getting difference for the given entry.
    /// Fails if the entry does not have a previously-known state that can be used to get its difference.
    ///
    /// Clears any previous gaps.
    fn try_begin_get_diff(&mut self, key: Key) {
        if !self.getting_diff_for.contains(&key) {
            if self.update_entry(key, |entry| entry.possible_gap = None) {
                self.getting_diff_for.push(key);
            } else {
                info!(
                    ?key,
                    "tried to begin getting difference but do not have entry for the key"
                );
            }
        }
    }

    /// Finish getting difference for the given entry, and resets its deadline.
    /// Does nothing if no difference was being fetched for the given key.
    fn try_end_get_diff(&mut self, key: Key) {
        let i = match self.getting_diff_for.iter().position(|&k| k == key) {
            Some(i) => i,
            None => return,
        };
        self.getting_diff_for.remove(i);
        self.reset_deadline(key, next_updates_deadline());

        debug_assert!(
            self.entry(key)
                .is_none_or(|entry| entry.possible_gap.is_none()),
            "gaps shouldn't be created while getting difference"
        );
    }
}

// "Normal" updates flow (processing and detection of gaps).
impl MessageBoxes {
    /// Process an update and return what should be done with it.
    ///
    /// Updates corresponding to entries for which their difference is currently being fetched
    /// will be ignored. While according to the [updates' documentation]:
    ///
    /// > Implementations \[have\] to postpone updates received via the socket while
    /// > filling gaps in the event and `Update` sequences, as well as avoid filling
    /// > gaps in the same sequence.
    ///
    /// In practice, these updates should have also been retrieved through getting difference.
    ///
    /// [updates' documentation]: https://core.telegram.org/api/updates
    pub fn process_updates(&mut self, updates: UpdatesLike) -> Result<UpdateAndPeers, Gap> {
        trace!(?updates, "processing updates");

        let deadline = next_updates_deadline();

        // Top level, when handling received `updates` and `updatesCombined`.
        // `updatesCombined` groups all the fields we care about, which is why we use it.
        //
        // This assumes all access hashes are already known to the client (socket updates are
        // expected to use `ensure_known_peer_hashes`, and the result from getting difference
        // has to deal with the peers in a different way).
        let tl::types::UpdatesCombined {
            date,
            seq_start,
            seq,
            mut updates,
            users,
            chats,
        } = match adaptor::adapt(updates) {
            Ok(combined) => combined,
            Err(Gap) => {
                self.try_begin_get_diff(Key::Common);
                return Err(Gap);
            }
        };

        let new_date = if date == NO_DATE { self.date } else { date };
        let new_seq = if seq == NO_SEQ { self.seq } else { seq };
        let mk_state = |message_box| State {
            date: new_date,
            seq: new_seq,
            message_box,
        };

        // > For all the other [not `updates` or `updatesCombined`] `Updates` type constructors
        // > there is no need to check `seq` or change a local state.
        if seq_start != NO_SEQ {
            match (self.seq + 1).cmp(&seq_start) {
                // Apply
                Ordering::Equal => {}
                // Ignore
                Ordering::Greater => {
                    debug!(
                        "skipping updates that were already handled at seq = {}",
                        self.seq
                    );
                    return Ok((Vec::new(), users, chats));
                }
                Ordering::Less => {
                    debug!(
                        "gap detected (local seq {}, remote seq {})",
                        self.seq, seq_start
                    );
                    self.try_begin_get_diff(Key::Common);
                    return Err(Gap);
                }
            }
        }

        // Telegram can send updates out of order (e.g. `ReadChannelInbox` first
        // and then `NewChannelMessage`, both with the same `pts`, but the `count`
        // is `0` and `1` respectively), so we sort them first.
        updates.sort_by_key(update_sort_key);

        let mut result = Vec::with_capacity(updates.len());
        let mut have_unresolved_gaps = false;

        // This loop does a lot at once to reduce the amount of times we need to iterate over
        // the updates as an optimization.
        //
        // It mutates the local pts state, remembers possible gaps, builds a set of entries for
        // which the deadlines should be reset, and determines whether any local pts was changed
        // so that the seq can be updated too (which could otherwise have been done earlier).
        for update in updates {
            if let tl::enums::Update::ChannelTooLong(u) = update {
                // Can skip this one early since no processing can be done for the entry.
                let key = Key::Channel(u.channel_id);
                if let Some(pts) = u.pts {
                    self.set_entry(LiveEntry {
                        key,
                        pts,
                        deadline,
                        possible_gap: None,
                    });
                }
                self.try_begin_get_diff(key);
                continue;
            }

            let info = match PtsInfo::from_update(&update) {
                Some(info) => info,
                None => {
                    // No pts means that the update can be applied in any order.
                    result.push((update, mk_state(None)));
                    continue;
                }
            };

            if self.getting_diff_for.contains(&info.key) {
                debug!(
                    key = ?info.key,
                    count = ?info.count,
                    remote = ?info.pts,
                    "forcing update to apply (getting difference)",
                );
                // Order does not need to be checked. These always must be applied.
                self.reset_deadline(info.key, next_updates_deadline());
                result.push((update, mk_state(Some(info.into()))));
                continue;
            }

            let mut gap_deadline = None;
            self.force_update_entry(
                LiveEntry {
                    key: info.key,
                    pts: info.pts - info.count,
                    deadline,
                    possible_gap: None,
                },
                |entry| {
                    match (entry.pts + info.count).cmp(&info.pts) {
                        // Apply
                        Ordering::Equal => {
                            entry.pts = info.pts;
                            entry.deadline = deadline;
                            result.push((update, mk_state(Some(info.into()))));
                        }
                        // Ignore
                        Ordering::Greater => {
                            debug!(
                                key = ?info.key,
                                local = ?entry.pts,
                                count = ?info.count,
                                remote = ?info.pts,
                                "skipping update",
                            );
                        }
                        Ordering::Less => {
                            // TODO store chats too?
                            info!(
                                key = ?info.key,
                                local = ?entry.pts,
                                count = ?info.count,
                                remote = ?info.pts,
                                "gap on update",
                            );

                            entry
                                .possible_gap
                                .get_or_insert_with(|| PossibleGap {
                                    deadline: Instant::now() + POSSIBLE_GAP_TIMEOUT,
                                    updates: Vec::new(),
                                })
                                .updates
                                .push(update.clone());
                        }
                    };

                    if let Some(mut gap) = entry.possible_gap.take() {
                        gap.updates.sort_by_key(|u| -update_sort_key(u));
                        while let Some(gap_update) = gap.updates.pop() {
                            let gap_info = PtsInfo::from_update(&gap_update)
                                .expect("only updates with pts info may be stored as gaps");

                            match (entry.pts + gap_info.count).cmp(&gap_info.pts) {
                                Ordering::Equal => {
                                    entry.pts = gap_info.pts;
                                    // possible gap can only be resolve if new update closed
                                    // the gap - this has already updated its deadline if so.
                                    result.push((gap_update, mk_state(Some(gap_info.into()))));
                                }
                                Ordering::Greater => {}
                                Ordering::Less => {
                                    gap.updates.push(gap_update);
                                    break;
                                }
                            };
                        }
                        if !gap.updates.is_empty() {
                            gap_deadline = Some(gap.deadline);
                            entry.possible_gap = Some(gap);
                            have_unresolved_gaps = true;
                        }
                    }
                },
            );

            self.next_deadline = self.next_deadline.min(gap_deadline.unwrap_or(deadline));
        }

        if !result.is_empty() && !have_unresolved_gaps {
            // > If the updates were applied, local *Updates* state must be updated
            // > with `seq` (unless it's 0) and `date` from the constructor.
            self.date = new_date;
            self.seq = new_seq;
        }

        Ok((result, users, chats))
    }
}
