# mtg-mtsender

Network side of MTProto: connects to Telegram, sends requests, receives responses and updates,
reconnects, and keeps a pool of connections to the datacenters.

Telegram documentation this crate implements:

- [MTProto transports](https://core.telegram.org/mtproto/mtproto-transports) over TCP (optionally through a SOCKS5 proxy)
- [Service messages](https://core.telegram.org/mtproto/service_messages) and
  [messages about messages](https://core.telegram.org/mtproto/service_messages_about_messages)
- [Datacenters](https://core.telegram.org/api/datacenter): `dcOption`, migration between DCs
- [Error handling](https://core.telegram.org/api/errors): RPC errors, flood waits

The protocol itself is in `mtg-mtproto`; this crate only moves its bytes over sockets.
