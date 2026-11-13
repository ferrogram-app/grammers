// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Conversions between the TL types and `PeerId`, `PeerRef` and `PeerInfo`.

use std::fmt;
use std::ops::Deref as _;

use mtg_tl_types as tl;

use super::*;

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.bot_api_dialog_id() {
            Some(id) => id.fmt(f),
            None => f.write_str("<self-user>"),
        }
    }
}

impl From<tl::enums::Peer> for PeerId {
    #[inline]
    fn from(peer: tl::enums::Peer) -> Self {
        <Self as From<&tl::enums::Peer>>::from(&peer)
    }
}
impl<'a> From<&'a tl::enums::Peer> for PeerId {
    fn from(peer: &'a tl::enums::Peer) -> Self {
        use tl::enums::Peer;
        match peer {
            Peer::User(user) => Self::from(user),
            Peer::Chat(chat) => Self::from(chat),
            Peer::Channel(channel) => Self::from(channel),
        }
    }
}

impl From<tl::types::PeerUser> for PeerId {
    #[inline]
    fn from(user: tl::types::PeerUser) -> Self {
        <Self as From<&tl::types::PeerUser>>::from(&user)
    }
}
impl<'a> From<&'a tl::types::PeerUser> for PeerId {
    fn from(user: &'a tl::types::PeerUser) -> Self {
        Self::user_unchecked(user.user_id)
    }
}

impl From<tl::types::PeerChat> for PeerId {
    #[inline]
    fn from(user: tl::types::PeerChat) -> Self {
        <Self as From<&tl::types::PeerChat>>::from(&user)
    }
}
impl<'a> From<&'a tl::types::PeerChat> for PeerId {
    fn from(chat: &'a tl::types::PeerChat) -> Self {
        Self::chat_unchecked(chat.chat_id)
    }
}

impl From<tl::types::PeerChannel> for PeerId {
    #[inline]
    fn from(channel: tl::types::PeerChannel) -> Self {
        <Self as From<&tl::types::PeerChannel>>::from(&channel)
    }
}
impl<'a> From<&'a tl::types::PeerChannel> for PeerId {
    fn from(channel: &'a tl::types::PeerChannel) -> Self {
        Self::channel_unchecked(channel.channel_id)
    }
}

impl From<tl::enums::InputPeer> for PeerRef {
    #[inline]
    fn from(peer: tl::enums::InputPeer) -> Self {
        <Self as From<&tl::enums::InputPeer>>::from(&peer)
    }
}
impl<'a> From<&'a tl::enums::InputPeer> for PeerRef {
    fn from(peer: &'a tl::enums::InputPeer) -> Self {
        use tl::{enums::InputPeer, types::InputPeerSelf};
        match peer {
            InputPeer::Empty => panic!("InputPeer::Empty cannot be converted to any Peer"),
            InputPeer::PeerSelf => <Self as From<&'a _>>::from(&InputPeerSelf {}),
            InputPeer::User(user) => <Self as From<&'a _>>::from(user),
            InputPeer::Chat(chat) => <Self as From<&'a _>>::from(chat),
            InputPeer::Channel(channel) => <Self as From<&'a _>>::from(channel),
            InputPeer::UserFromMessage(user) => <Self as From<&'a _>>::from(user.deref()),
            InputPeer::ChannelFromMessage(channel) => <Self as From<&'a _>>::from(channel.deref()),
        }
    }
}

impl From<tl::types::InputPeerSelf> for PeerRef {
    #[inline]
    fn from(self_user: tl::types::InputPeerSelf) -> Self {
        <Self as From<&tl::types::InputPeerSelf>>::from(&self_user)
    }
}
impl<'a> From<&'a tl::types::InputPeerSelf> for PeerRef {
    fn from(self_user: &'a tl::types::InputPeerSelf) -> Self {
        _ = self_user;
        Self {
            id: SELF_USER_ID,
            auth: PeerAuth::default(),
        }
    }
}

impl From<tl::types::InputPeerUser> for PeerRef {
    #[inline]
    fn from(user: tl::types::InputPeerUser) -> Self {
        <Self as From<&tl::types::InputPeerUser>>::from(&user)
    }
}
impl<'a> From<&'a tl::types::InputPeerUser> for PeerRef {
    fn from(user: &'a tl::types::InputPeerUser) -> Self {
        Self {
            id: PeerId::user_unchecked(user.user_id),
            auth: PeerAuth::from_hash(user.access_hash),
        }
    }
}

impl From<tl::types::InputPeerChat> for PeerRef {
    #[inline]
    fn from(chat: tl::types::InputPeerChat) -> Self {
        <Self as From<&tl::types::InputPeerChat>>::from(&chat)
    }
}
impl<'a> From<&'a tl::types::InputPeerChat> for PeerRef {
    fn from(chat: &'a tl::types::InputPeerChat) -> Self {
        Self {
            id: PeerId::chat_unchecked(chat.chat_id),
            auth: PeerAuth::default(),
        }
    }
}

impl From<tl::types::InputPeerChannel> for PeerRef {
    #[inline]
    fn from(channel: tl::types::InputPeerChannel) -> Self {
        <Self as From<&tl::types::InputPeerChannel>>::from(&channel)
    }
}
impl<'a> From<&'a tl::types::InputPeerChannel> for PeerRef {
    fn from(channel: &'a tl::types::InputPeerChannel) -> Self {
        Self {
            id: PeerId::channel_unchecked(channel.channel_id),
            auth: PeerAuth::from_hash(channel.access_hash),
        }
    }
}

impl From<tl::types::InputPeerUserFromMessage> for PeerRef {
    #[inline]
    fn from(user: tl::types::InputPeerUserFromMessage) -> Self {
        <Self as From<&tl::types::InputPeerUserFromMessage>>::from(&user)
    }
}
impl<'a> From<&'a tl::types::InputPeerUserFromMessage> for PeerRef {
    fn from(user: &'a tl::types::InputPeerUserFromMessage) -> Self {
        // Not currently willing to make PeerRef significantly larger to accomodate for this uncommon type.
        Self {
            id: PeerId::user_unchecked(user.user_id),
            auth: PeerAuth::default(),
        }
    }
}

impl From<tl::types::InputPeerChannelFromMessage> for PeerRef {
    #[inline]
    fn from(channel: tl::types::InputPeerChannelFromMessage) -> Self {
        <Self as From<&tl::types::InputPeerChannelFromMessage>>::from(&channel)
    }
}
impl<'a> From<&'a tl::types::InputPeerChannelFromMessage> for PeerRef {
    fn from(channel: &'a tl::types::InputPeerChannelFromMessage) -> Self {
        // Not currently willing to make PeerRef significantly larger to accomodate for this uncommon type.
        Self {
            id: PeerId::channel_unchecked(channel.channel_id),
            auth: PeerAuth::default(),
        }
    }
}

impl From<tl::enums::User> for PeerRef {
    #[inline]
    fn from(user: tl::enums::User) -> Self {
        <Self as From<&tl::enums::User>>::from(&user)
    }
}
impl<'a> From<&'a tl::enums::User> for PeerRef {
    fn from(user: &'a tl::enums::User) -> Self {
        use tl::enums::User;
        match user {
            User::Empty(user) => <Self as From<&_>>::from(user),
            User::User(user) => <Self as From<&_>>::from(user),
        }
    }
}

impl From<tl::types::UserEmpty> for PeerRef {
    #[inline]
    fn from(user: tl::types::UserEmpty) -> Self {
        <Self as From<&tl::types::UserEmpty>>::from(&user)
    }
}
impl<'a> From<&'a tl::types::UserEmpty> for PeerRef {
    fn from(user: &'a tl::types::UserEmpty) -> Self {
        Self {
            id: PeerId::user_unchecked(user.id),
            auth: PeerAuth::default(),
        }
    }
}

impl From<tl::types::User> for PeerRef {
    #[inline]
    fn from(user: tl::types::User) -> Self {
        <Self as From<&tl::types::User>>::from(&user)
    }
}
impl<'a> From<&'a tl::types::User> for PeerRef {
    fn from(user: &'a tl::types::User) -> Self {
        Self {
            id: PeerId::user_unchecked(user.id),
            auth: user
                .access_hash
                .map(PeerAuth::from_hash)
                .unwrap_or_default(),
        }
    }
}

impl From<tl::enums::Chat> for PeerRef {
    #[inline]
    fn from(chat: tl::enums::Chat) -> Self {
        <Self as From<&tl::enums::Chat>>::from(&chat)
    }
}
impl<'a> From<&'a tl::enums::Chat> for PeerRef {
    fn from(chat: &'a tl::enums::Chat) -> Self {
        use tl::enums::Chat;
        match chat {
            Chat::Empty(chat) => <Self as From<&_>>::from(chat),
            Chat::Chat(chat) => <Self as From<&_>>::from(chat),
            Chat::Forbidden(chat) => <Self as From<&_>>::from(chat),
            Chat::Channel(channel) => <Self as From<&_>>::from(channel),
            Chat::ChannelForbidden(channel) => <Self as From<&_>>::from(channel),
            Chat::CommunityForbidden(community) => <Self as From<&_>>::from(community),
            Chat::Community(community) => <Self as From<&_>>::from(community),
        }
    }
}

impl From<tl::types::ChatEmpty> for PeerRef {
    #[inline]
    fn from(chat: tl::types::ChatEmpty) -> Self {
        <Self as From<&tl::types::ChatEmpty>>::from(&chat)
    }
}
impl<'a> From<&'a tl::types::ChatEmpty> for PeerRef {
    fn from(chat: &'a tl::types::ChatEmpty) -> Self {
        Self {
            id: PeerId::chat_unchecked(chat.id),
            auth: PeerAuth::default(),
        }
    }
}

impl From<tl::types::Chat> for PeerRef {
    #[inline]
    fn from(chat: tl::types::Chat) -> Self {
        <Self as From<&tl::types::Chat>>::from(&chat)
    }
}
impl<'a> From<&'a tl::types::Chat> for PeerRef {
    fn from(chat: &'a tl::types::Chat) -> Self {
        Self {
            id: PeerId::chat_unchecked(chat.id),
            auth: PeerAuth::default(),
        }
    }
}

impl From<tl::types::ChatForbidden> for PeerRef {
    #[inline]
    fn from(chat: tl::types::ChatForbidden) -> Self {
        <Self as From<&tl::types::ChatForbidden>>::from(&chat)
    }
}
impl<'a> From<&'a tl::types::ChatForbidden> for PeerRef {
    fn from(chat: &'a tl::types::ChatForbidden) -> Self {
        Self {
            id: PeerId::chat_unchecked(chat.id),
            auth: PeerAuth::default(),
        }
    }
}

impl From<tl::types::Channel> for PeerRef {
    #[inline]
    fn from(channel: tl::types::Channel) -> Self {
        <Self as From<&tl::types::Channel>>::from(&channel)
    }
}
impl<'a> From<&'a tl::types::Channel> for PeerRef {
    fn from(channel: &'a tl::types::Channel) -> Self {
        Self {
            id: PeerId::channel_unchecked(channel.id),
            auth: channel
                .access_hash
                .map(PeerAuth::from_hash)
                .unwrap_or_default(),
        }
    }
}

impl From<tl::types::ChannelForbidden> for PeerRef {
    #[inline]
    fn from(channel: tl::types::ChannelForbidden) -> Self {
        <Self as From<&tl::types::ChannelForbidden>>::from(&channel)
    }
}
impl<'a> From<&'a tl::types::ChannelForbidden> for PeerRef {
    fn from(channel: &'a tl::types::ChannelForbidden) -> Self {
        Self {
            id: PeerId::channel_unchecked(channel.id),
            auth: PeerAuth::from_hash(channel.access_hash),
        }
    }
}

impl From<tl::types::CommunityForbidden> for PeerRef {
    #[inline]
    fn from(community: tl::types::CommunityForbidden) -> Self {
        <Self as From<&tl::types::CommunityForbidden>>::from(&community)
    }
}
impl<'a> From<&'a tl::types::CommunityForbidden> for PeerRef {
    fn from(community: &'a tl::types::CommunityForbidden) -> Self {
        Self {
            id: PeerId::channel_unchecked(community.id),
            auth: community
                .access_hash
                .map(PeerAuth::from_hash)
                .unwrap_or_default(),
        }
    }
}

impl From<tl::types::Community> for PeerRef {
    #[inline]
    fn from(community: tl::types::Community) -> Self {
        <Self as From<&tl::types::Community>>::from(&community)
    }
}
impl<'a> From<&'a tl::types::Community> for PeerRef {
    fn from(community: &'a tl::types::Community) -> Self {
        Self {
            id: PeerId::channel_unchecked(community.id),
            auth: community
                .access_hash
                .map(PeerAuth::from_hash)
                .unwrap_or_default(),
        }
    }
}

impl From<PeerId> for tl::enums::Peer {
    #[inline]
    fn from(peer: PeerId) -> Self {
        <Self as From<&PeerId>>::from(&peer)
    }
}
impl<'a> From<&'a PeerId> for tl::enums::Peer {
    fn from(peer: &'a PeerId) -> Self {
        match peer.kind() {
            PeerKind::User => Self::User(tl::types::PeerUser {
                user_id: peer.bare_id_unchecked(), // may have bogus data on release builds
            }),
            PeerKind::Chat => Self::Chat(tl::types::PeerChat {
                chat_id: peer.bare_id_unchecked(),
            }),
            PeerKind::Channel => Self::Channel(tl::types::PeerChannel {
                channel_id: peer.bare_id_unchecked(),
            }),
        }
    }
}

/// Generate owned `From<PeerRef>` impls that forward to the `From<&PeerRef>` impl.
macro_rules! forward_peer_ref_from {
    ($($ty:ty),+ $(,)?) => {$(
        impl From<PeerRef> for $ty {
            #[inline]
            fn from(peer: PeerRef) -> Self {
                <Self as From<&PeerRef>>::from(&peer)
            }
        }
    )+};
}

forward_peer_ref_from!(
    tl::enums::InputPeer,
    tl::enums::InputUser,
    i64,
    tl::enums::InputChannel,
);

impl<'a> From<&'a PeerRef> for tl::enums::InputPeer {
    fn from(peer: &'a PeerRef) -> Self {
        match peer.id.kind() {
            PeerKind::User => match peer.id.bare_id() {
                Some(user_id) => Self::User(tl::types::InputPeerUser {
                    user_id,
                    access_hash: peer.auth.hash(),
                }),
                None => Self::PeerSelf,
            },
            PeerKind::Chat => Self::Chat(tl::types::InputPeerChat {
                chat_id: peer.id.bare_id_unchecked(),
            }),
            PeerKind::Channel => Self::Channel(tl::types::InputPeerChannel {
                channel_id: peer.id.bare_id_unchecked(),
                access_hash: peer.auth.hash(),
            }),
        }
    }
}

impl<'a> From<&'a PeerRef> for tl::enums::InputUser {
    fn from(peer: &'a PeerRef) -> Self {
        match peer.id.kind() {
            PeerKind::User => match peer.id.bare_id() {
                Some(user_id) => Self::User(tl::types::InputUser {
                    user_id,
                    access_hash: peer.auth.hash(),
                }),
                None => Self::UserSelf,
            },
            PeerKind::Chat => Self::Empty,
            PeerKind::Channel => Self::Empty,
        }
    }
}

impl<'a> From<&'a PeerRef> for i64 {
    fn from(peer: &'a PeerRef) -> Self {
        match peer.id.kind() {
            PeerKind::User => EMPTY_CHAT_ID,
            PeerKind::Chat => peer.id.bare_id_unchecked(),
            PeerKind::Channel => EMPTY_CHAT_ID,
        }
    }
}

impl<'a> From<&'a PeerRef> for tl::enums::InputChannel {
    fn from(peer: &'a PeerRef) -> Self {
        match peer.id.kind() {
            PeerKind::User => Self::Empty,
            PeerKind::Chat => Self::Empty,
            PeerKind::Channel => Self::Channel(tl::types::InputChannel {
                channel_id: peer.id.bare_id_unchecked(),
                access_hash: peer.auth.hash(),
            }),
        }
    }
}

impl From<tl::enums::Chat> for PeerInfo {
    #[inline]
    fn from(chat: tl::enums::Chat) -> Self {
        <Self as From<&tl::enums::Chat>>::from(&chat)
    }
}
impl<'a> From<&'a tl::enums::Chat> for PeerInfo {
    fn from(chat: &'a tl::enums::Chat) -> Self {
        match chat {
            tl::enums::Chat::Chat(chat) => <Self as From<&tl::types::Chat>>::from(chat),
            tl::enums::Chat::Empty(chat) => <Self as From<&tl::types::ChatEmpty>>::from(chat),
            tl::enums::Chat::Forbidden(chat) => {
                <Self as From<&tl::types::ChatForbidden>>::from(chat)
            }
            tl::enums::Chat::Channel(channel) => <Self as From<&tl::types::Channel>>::from(channel),
            tl::enums::Chat::ChannelForbidden(channel) => {
                <Self as From<&tl::types::ChannelForbidden>>::from(channel)
            }
            tl::enums::Chat::CommunityForbidden(community) => {
                <Self as From<&tl::types::CommunityForbidden>>::from(community)
            }
            tl::enums::Chat::Community(community) => {
                <Self as From<&tl::types::Community>>::from(community)
            }
        }
    }
}

impl From<tl::enums::User> for PeerInfo {
    #[inline]
    fn from(user: tl::enums::User) -> Self {
        <Self as From<&tl::enums::User>>::from(&user)
    }
}
impl<'a> From<&'a tl::enums::User> for PeerInfo {
    fn from(user: &'a tl::enums::User) -> Self {
        match user {
            tl::enums::User::User(user) => <Self as From<&tl::types::User>>::from(user),
            tl::enums::User::Empty(user) => <Self as From<&tl::types::UserEmpty>>::from(user),
        }
    }
}

impl From<tl::types::User> for PeerInfo {
    #[inline]
    fn from(user: tl::types::User) -> Self {
        <Self as From<&tl::types::User>>::from(&user)
    }
}
impl<'a> From<&'a tl::types::User> for PeerInfo {
    fn from(user: &'a tl::types::User) -> Self {
        Self::User {
            id: user.id,
            auth: user.access_hash.map(PeerAuth).filter(|_| !user.min),
            bot: Some(user.bot),
            is_self: Some(user.is_self),
        }
    }
}

impl From<tl::types::UserEmpty> for PeerInfo {
    #[inline]
    fn from(user: tl::types::UserEmpty) -> Self {
        <Self as From<&tl::types::UserEmpty>>::from(&user)
    }
}
impl<'a> From<&'a tl::types::UserEmpty> for PeerInfo {
    fn from(user: &'a tl::types::UserEmpty) -> Self {
        Self::User {
            id: user.id,
            auth: None,
            bot: None,
            is_self: None,
        }
    }
}

impl From<tl::types::Chat> for PeerInfo {
    #[inline]
    fn from(chat: tl::types::Chat) -> Self {
        <Self as From<&tl::types::Chat>>::from(&chat)
    }
}
impl<'a> From<&'a tl::types::Chat> for PeerInfo {
    fn from(chat: &'a tl::types::Chat) -> Self {
        Self::Chat { id: chat.id }
    }
}

impl From<tl::types::ChatEmpty> for PeerInfo {
    #[inline]
    fn from(chat: tl::types::ChatEmpty) -> Self {
        <Self as From<&tl::types::ChatEmpty>>::from(&chat)
    }
}
impl<'a> From<&'a tl::types::ChatEmpty> for PeerInfo {
    fn from(chat: &'a tl::types::ChatEmpty) -> Self {
        Self::Chat { id: chat.id }
    }
}

impl From<tl::types::ChatForbidden> for PeerInfo {
    #[inline]
    fn from(chat: tl::types::ChatForbidden) -> Self {
        <Self as From<&tl::types::ChatForbidden>>::from(&chat)
    }
}
impl<'a> From<&'a tl::types::ChatForbidden> for PeerInfo {
    fn from(chat: &'a tl::types::ChatForbidden) -> Self {
        Self::Chat { id: chat.id }
    }
}

impl From<tl::types::Channel> for PeerInfo {
    #[inline]
    fn from(channel: tl::types::Channel) -> Self {
        <Self as From<&tl::types::Channel>>::from(&channel)
    }
}
impl<'a> From<&'a tl::types::Channel> for PeerInfo {
    fn from(channel: &'a tl::types::Channel) -> Self {
        Self::Channel {
            id: channel.id,
            auth: channel.access_hash.map(PeerAuth).filter(|_| !channel.min),
            kind: <ChannelKind as TryFrom<&'a tl::types::Channel>>::try_from(channel).ok(),
        }
    }
}

impl From<tl::types::ChannelForbidden> for PeerInfo {
    #[inline]
    fn from(channel: tl::types::ChannelForbidden) -> Self {
        <Self as From<&tl::types::ChannelForbidden>>::from(&channel)
    }
}
impl<'a> From<&'a tl::types::ChannelForbidden> for PeerInfo {
    fn from(channel: &'a tl::types::ChannelForbidden) -> Self {
        Self::Channel {
            id: channel.id,
            auth: Some(PeerAuth(channel.access_hash)),
            kind: <ChannelKind as TryFrom<&'a tl::types::ChannelForbidden>>::try_from(channel).ok(),
        }
    }
}

impl From<tl::types::CommunityForbidden> for PeerInfo {
    #[inline]
    fn from(community: tl::types::CommunityForbidden) -> Self {
        <Self as From<&tl::types::CommunityForbidden>>::from(&community)
    }
}
impl<'a> From<&'a tl::types::CommunityForbidden> for PeerInfo {
    fn from(community: &'a tl::types::CommunityForbidden) -> Self {
        Self::Channel {
            id: community.id,
            auth: community.access_hash.map(PeerAuth::from_hash),
            kind: Some(ChannelKind::Community),
        }
    }
}

impl From<tl::types::Community> for PeerInfo {
    #[inline]
    fn from(community: tl::types::Community) -> Self {
        <Self as From<&tl::types::Community>>::from(&community)
    }
}
impl<'a> From<&'a tl::types::Community> for PeerInfo {
    fn from(community: &'a tl::types::Community) -> Self {
        Self::Channel {
            id: community.id,
            auth: community
                .access_hash
                .map(PeerAuth)
                .filter(|_| !community.min),
            kind: Some(ChannelKind::Community),
        }
    }
}

impl TryFrom<tl::types::Channel> for ChannelKind {
    type Error = <ChannelKind as TryFrom<&'static tl::types::Channel>>::Error;

    #[inline]
    fn try_from(channel: tl::types::Channel) -> Result<Self, Self::Error> {
        <ChannelKind as TryFrom<&tl::types::Channel>>::try_from(&channel)
    }
}
impl<'a> TryFrom<&'a tl::types::Channel> for ChannelKind {
    type Error = ();

    fn try_from(channel: &'a tl::types::Channel) -> Result<Self, Self::Error> {
        match channel {
            channel if channel.gigagroup => Ok(Self::Gigagroup),
            channel if channel.broadcast => Ok(Self::Broadcast),
            channel if channel.megagroup => Ok(Self::Megagroup),
            _channel => Err(()),
        }
    }
}

impl TryFrom<tl::types::ChannelForbidden> for ChannelKind {
    type Error = <ChannelKind as TryFrom<&'static tl::types::ChannelForbidden>>::Error;

    #[inline]
    fn try_from(channel: tl::types::ChannelForbidden) -> Result<Self, Self::Error> {
        <ChannelKind as TryFrom<&tl::types::ChannelForbidden>>::try_from(&channel)
    }
}
impl<'a> TryFrom<&'a tl::types::ChannelForbidden> for ChannelKind {
    type Error = ();

    fn try_from(channel: &'a tl::types::ChannelForbidden) -> Result<Self, Self::Error> {
        match channel {
            // channel if channel.gigagroup => Ok(Self::Gigagroup),
            channel if channel.broadcast => Ok(Self::Broadcast),
            channel if channel.megagroup => Ok(Self::Megagroup),
            _channel => Err(()),
        }
    }
}
