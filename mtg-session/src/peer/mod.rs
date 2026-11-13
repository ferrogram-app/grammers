// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::ops::RangeInclusive;

mod convert;

/// A compact peer identifier.
/// ```
/// use std::mem::size_of;
/// assert_eq!(size_of::<mtg_session::types::PeerId>(), size_of::<i64>());
/// ```
/// The [`PeerInfo`] cached by the session for this `PeerId` may be retrieved via [`crate::Session::peer`].
///
/// The internal representation uses the Bot API Dialog ID format to
/// bit-pack both the peer's true identifier and type in a single integer.
///
/// Internally, arbitrary values outside the valid range of Bot API Dialog ID
/// may be used to represent special peer identifiers.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PeerId(i64);

/// Witness to the session's authority from Telegram to interact with a peer.
///
/// If Telegram deems the session to already have such authority, the session may
/// be allowed to present [`PeerAuth::default`] instead of this witness. This can
/// happen when the logged-in user is a bot account, or, for user accounts, when
/// the peer being interacted with is one of its contacts.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PeerAuth(i64);

/// Ocap-style reference to a peer object, a peer object capability, bundling the identity
/// of a peer (its [`PeerId`]) with authority over it (as [`PeerAuth`]), to allow fluent use.
///
/// This type implements conversion to [`tl::enums::InputPeer`] and derivatives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PeerRef {
    /// The peer identity.
    pub id: PeerId,
    /// The authority bound to both the sibling identity and the session of the logged-in user.
    pub auth: PeerAuth,
}

/// [`PeerId`]'s kind.
///
/// The `PeerId` bitpacks this information for size reasons.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PeerKind {
    /// The peer identity belongs to a [`tl::enums::User`] or the self-user without knowing its identifier.
    User,
    /// The peer identity belongs to a [`tl::types::Chat`] or one of its derivatives.
    Chat,
    /// The peer identity belongs to a [`tl::types::Channel`] or one of its derivatives.
    Channel,
}

/// An exploded peer reference along with any known useful information about the peer.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PeerInfo {
    User {
        /// Bare user identifier.
        ///
        /// Despite being `i64`, Telegram only uses strictly positive values.
        id: i64,
        /// Non-ambient authority bound to both the user itself and the session.
        auth: Option<PeerAuth>,
        /// Whether this user represents a bot or not.
        bot: Option<bool>,
        /// Whether this user represents the logged-in user authorized by this session or not.
        is_self: Option<bool>,
    },
    Chat {
        /// Bare chat identifier.
        ///
        /// Note that the HTTP Bot API negates this identifier to signal that it is a chat,
        /// but the true value used by Telegram's API is always strictly-positive.
        id: i64,
    },
    Channel {
        /// Bare channel identifier.
        ///
        /// Note that the HTTP Bot API prefixes this identifier with `-100` to signal that it is a channel,
        /// but the true value used by Telegram's API is always strictly-positive.
        id: i64,
        /// Non-ambient authority bound to both the user itself and the session.
        auth: Option<PeerAuth>,
        /// Channel kind, useful to determine what the possible permissions on it are.
        kind: Option<ChannelKind>,
    },
}

/// Additional information about a [`PeerInfo::Channel`].
///
/// A non-zero enum,
/// to make working with `Option<ChannelKind>`
/// and `Result<ChannelKind, ()>`
/// slightly more performant.
/// (See [`mod@core::option`]'s documentation about the "null pointer optimization".)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ChannelKind {
    /// Value used for a channel with its [`tl::types::Channel::broadcast`] flag set to `true`.
    Broadcast = 1,
    /// Value used for a channel with its [`tl::types::Channel::megagroup`] flag set to `true`.
    Megagroup,
    /// Value used for a channel with its [`tl::types::Channel::gigagroup`] flag set to `true`.
    Gigagroup,
    /// Value used for a channel of [`tl::types::Community`] or [`tl::types::CommunityForbidden`] type.
    Community,
}

/// Sentinel value used to represent the self-user
/// when its true `PeerId` is unknown.
///
/// Per <https://core.telegram.org/api/bots/ids>:
/// > a bot API dialog ID ranges from -4000000000000 to 1099511627775
///
/// This value is not intended to be visible or persisted,
/// so it can be changed as needed in the future.
const SELF_USER_ID: PeerId = PeerId(1 << 40);

/// Sentinel value used to represent empty chats.
///
/// Per <https://core.telegram.org/api/bots/ids>:
/// > \[…] transformed range for bot API chat dialog IDs is -999999999999 to -1 inclusively
/// >
/// > \[…] transformed range for bot API channel dialog IDs is -1997852516352 to -1000000000001 inclusively
///
/// `chat_id` parameters are in Telegram's API use the bare identifier,
/// so there's no empty constructor,
/// but it can be mimicked by picking the value in the correct range hole.
/// This value is closer to "channel with ID 0" than "chat with ID 0",
/// but there's no distinct `-0` integer,
/// and channels have a proper constructor for empty already.
const EMPTY_CHAT_ID: i64 = -1000000000000;

/// https://core.telegram.org/api/bots/ids#user-ids
const USER_ID_RANGE: RangeInclusive<i64> = 1..=0xffffffffff;
/// https://core.telegram.org/api/bots/ids#chat-ids
const CHAT_ID_RANGE: RangeInclusive<i64> = 1..=999999999999;
/// https://core.telegram.org/api/bots/ids#supergroup-channel-ids
const SUPERGROUP_AND_CHANNEL_ID_RANGE: RangeInclusive<i64> = 1..=997852516352;
/// https://core.telegram.org/api/bots/ids#monoforum-ids
const MONOFORUM_ID_RANGE: RangeInclusive<i64> = 1002147483649..=3000000000000;

impl PeerId {
    /// Creates a peer identity for the currently-logged-in user or bot account.
    ///
    /// Internally, this will use a special sentinel value outside of any valid Bot API Dialog ID range.
    pub fn self_user() -> Self {
        SELF_USER_ID
    }

    /// Creates a peer identity for a user or bot account.
    pub fn user(id: i64) -> Option<Self> {
        USER_ID_RANGE.contains(&id).then_some(Self(id))
    }

    /// Creates a peer identity for a small group chat.
    pub fn chat(id: i64) -> Option<Self> {
        CHAT_ID_RANGE.contains(&id).then_some(Self(-id))
    }

    /// Creates a peer identity for a broadcast channel, megagroup, gigagroup or monoforum.
    pub fn channel(id: i64) -> Option<Self> {
        (SUPERGROUP_AND_CHANNEL_ID_RANGE.contains(&id) || MONOFORUM_ID_RANGE.contains(&id))
            .then_some(Self(-(1000000000000 + id)))
    }

    /// Creates a peer identity from a [Bot API dialog ID](https://core.telegram.org/api/bots/ids).
    pub fn from_bot_api_dialog_id(id: i64) -> Option<Self> {
        if (1..=0xffffffffff).contains(&id)
            || (-999999999999..=-1).contains(&id)
            || (-1997852516352..=-1000000000001).contains(&id)
            || (-4000000000000..=-2002147483649).contains(&id)
        {
            Some(Self(id))
        } else {
            None
        }
    }

    /// Creates a peer identity for a user or bot account.
    /// Panics if the ID is out of the valid range.
    #[doc(hidden)]
    pub fn user_unchecked(id: i64) -> Self {
        debug_assert!(USER_ID_RANGE.contains(&id), "user ID out of range");
        Self(id)
    }

    /// Creates a peer identity for a small group chat.
    /// Panics if the ID is out of the valid range.
    #[doc(hidden)]
    pub fn chat_unchecked(id: i64) -> Self {
        debug_assert!(CHAT_ID_RANGE.contains(&id), "chat ID out of range");
        Self(-id)
    }

    /// Creates a peer identity for a broadcast channel, megagroup, gigagroup or monoforum.
    /// Panics if the ID is out of the valid range.
    #[doc(hidden)]
    pub fn channel_unchecked(id: i64) -> Self {
        debug_assert!(
            (SUPERGROUP_AND_CHANNEL_ID_RANGE.contains(&id) || MONOFORUM_ID_RANGE.contains(&id)),
            "channel ID out of range"
        );
        Self(-(1000000000000 + id))
    }

    /// Peer kind.
    pub fn kind(self) -> PeerKind {
        if 1 <= self.0 && self.0 <= 0xffffffffff || self.0 == SELF_USER_ID.0 {
            PeerKind::User
        } else if -999999999999 <= self.0 && self.0 <= -1 {
            PeerKind::Chat
        } else if -1997852516352 <= self.0 && self.0 <= -1000000000001
            || (-4000000000000 <= self.0 && self.0 <= -2002147483649)
        {
            PeerKind::Channel
        } else {
            unreachable!()
        }
    }

    /// Returns the identity using the [Bot API dialog ID](https://core.telegram.org/api/bots/ids)
    /// format, which has the [`PeerKind`] embedded.
    ///
    /// Returns `None` if the peer was constructed without providing an identifier.
    /// For now, this can only happen if `self` represents the [`Self::self_user`].
    pub fn bot_api_dialog_id(self) -> Option<i64> {
        (self.0 != SELF_USER_ID.0).then_some(self.0)
    }

    /// Returns the identity using the [Bot API dialog ID](https://core.telegram.org/api/bots/ids)
    /// format, which has the [`PeerKind`] embedded.
    #[doc(hidden)]
    pub fn bot_api_dialog_id_unchecked(self) -> i64 {
        debug_assert!(self.0 != SELF_USER_ID.0);
        self.0
    }

    /// Bare peer identifier without the [`PeerKind`] tag embedded, as used by Telegram's MTProto API.
    ///
    /// Returns `None` if the peer was constructed without providing an identifier.
    /// For now, this can only happen if `self` represents the [`Self::self_user`].
    pub fn bare_id(self) -> Option<i64> {
        if self.0 == SELF_USER_ID.0 {
            return None;
        }
        Some(match self.kind() {
            PeerKind::User => self.0,
            PeerKind::Chat => -self.0,
            PeerKind::Channel => -self.0 - 1000000000000,
        })
    }

    /// Bare peer identifier without the [`PeerKind`] tag embedded, as used by Telegram's MTProto API.
    #[doc(hidden)]
    pub fn bare_id_unchecked(self) -> i64 {
        debug_assert!(self.0 != SELF_USER_ID.0);
        match self.kind() {
            PeerKind::User => self.0,
            PeerKind::Chat => -self.0,
            PeerKind::Channel => -self.0 - 1000000000000,
        }
    }

    /// Returns the `PeerRef` for this identifier with ambient authority (i.e. [`PeerAuth::default`]).
    ///
    /// This is useful when [`crate::Session::peer_ref`] returns `None` due to not having any cached.
    ///
    /// # Examples
    ///
    /// ```
    /// # async fn f(session: &mtg_session::storages::ErasedSession, peer_id: mtg_session::types::PeerId) -> Result<(), Box<dyn std::error::Error>> {
    /// let peer_ref = session
    ///     .peer_ref(peer_id)
    ///     .await
    ///     .unwrap()
    ///     .unwrap_or(peer_id.to_ambient_ref());
    ///
    /// // Can try using the `peer_ref` to e.g. send messages now, even if no auth was found in cache,
    /// // if Telegram deems you have permission to do so (e.g. you're a bot or peer is your contact).
    /// # Ok(())
    /// # }
    /// ```
    pub fn to_ambient_ref(self) -> PeerRef {
        PeerRef {
            id: self,
            auth: PeerAuth::default(),
        }
    }
}

impl PeerAuth {
    /// Construct a new peer authentication using Telegram's `access_hash` value.
    pub fn from_hash(access_hash: i64) -> Self {
        PeerAuth(access_hash)
    }

    /// Grants access to the internal access hash.
    pub fn hash(self) -> i64 {
        self.0
    }
}

impl Default for PeerAuth {
    /// Returns the ambient authority to authorize peers only when Telegram considers it valid.
    ///
    /// The internal representation uses `0` to signal the ambient authority,
    /// although this might happen to be the actual witness used by some peers.
    fn default() -> Self {
        Self(0)
    }
}

impl PeerInfo {
    /// Returns the `PeerId` represented by this info.
    pub fn id(&self) -> PeerId {
        match self {
            PeerInfo::User { id, .. } => PeerId::user_unchecked(*id),
            PeerInfo::Chat { id } => PeerId::chat_unchecked(*id),
            PeerInfo::Channel { id, .. } => PeerId::channel_unchecked(*id),
        }
    }

    /// Returns the `PeerAuth` stored in this info.
    pub fn auth(&self) -> Option<PeerAuth> {
        match self {
            PeerInfo::User { auth, .. } => *auth,
            PeerInfo::Chat { .. } => Some(PeerAuth::default()),
            PeerInfo::Channel { auth, .. } => *auth,
        }
    }

    /// Updates self with any new information contained in the other info.
    ///
    /// This is equivalent to performing an "or-assign" operation on all the fields.
    ///
    /// Returns `true` if the other info matches in type and identifier.
    /// If they do not match, no fields will be updated, and `false` is returned instead.
    pub fn extend_info(&mut self, other: &PeerInfo) -> bool {
        match (self, &other) {
            (
                PeerInfo::User {
                    id,
                    auth,
                    bot,
                    is_self,
                },
                PeerInfo::User {
                    id: new_id,
                    auth: new_auth,
                    bot: new_bot,
                    is_self: new_self,
                },
            ) if id == new_id => {
                *auth = new_auth.or(*auth);
                *bot = new_bot.or(*bot);
                *is_self = new_self.or(*is_self);
                true
            }
            (PeerInfo::Chat { id }, PeerInfo::Chat { id: new_id }) if id == new_id => true,
            (
                PeerInfo::Channel { id, auth, kind },
                PeerInfo::Channel {
                    id: new_id,
                    auth: new_auth,
                    kind: new_kind,
                },
            ) if id == new_id => {
                *auth = new_auth.or(*auth);
                *kind = new_kind.or(*kind);
                true
            }
            _ => false,
        }
    }
}
