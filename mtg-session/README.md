# mtg-session

The `Session` trait and its storages (memory, SQLite): the authorization key and datacenter
addresses, so that a new key and login are not needed on every start; known peers; and the
update state with the `message_box` logic (`pts`, `qts`, `seq`, `getDifference`).

Telegram documentation this crate implements:

- [Working with updates](https://core.telegram.org/api/updates): `pts`/`qts`/`seq`, gaps, `getDifference`, `getChannelDifference`
- [Datacenters](https://core.telegram.org/api/datacenter)
- [Peer ids](https://core.telegram.org/api/bots/ids) (Bot API scheme)
